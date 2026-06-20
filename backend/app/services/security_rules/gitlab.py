"""GitLab configuration-risk security rules — M87B.

Every rule fires only on explicit, reliable normalized fields produced by the
GitLab connector (app/connectors/gitlab.py + gitlab_schema.py, M87A). Evidence
is metadata-only: booleans, counts, categories, opaque identifiers, and safe
record_type labels.

NEVER read, stored, or surfaced:
  GitLab access tokens, OAuth tokens, PRIVATE-TOKEN values, authorization
  headers, webhook secret tokens, webhook URLs, CI/CD variable names or values,
  deploy key material, SSH keys, deploy key fingerprints, runner tokens, runner
  IPs, runner descriptions, project names, group names, namespace paths, repo
  URLs, branch names, commit messages, merge request titles, issue titles,
  pipeline logs, job logs, artifacts, user emails, usernames, customer data,
  PII, or raw GitLab API payloads.

CLAIM DISCIPLINE
----------------
These are configuration posture findings that **may require review**. A finding
is evidence for review only. It never asserts that a credential was leaked, that
unauthorized access occurred, that source code was exposed, that any secret was
exposed, or that any data was exposed.

This does not confirm compromise, unauthorized access, source-code exposure,
secret exposure, token exposure, or data exposure.

Severity reflects review priority, not confirmed impact.

Record types evaluated (M87A)
------------------------------
  gitlab_project                      — project visibility, feature flags
  gitlab_group                        — group visibility posture
  gitlab_branch_protection            — branch protection rule posture
  gitlab_webhook                      — webhook security posture
  gitlab_ci_variable_summary          — CI variable count/protection posture
  gitlab_deploy_key_summary           — deploy key write-access posture
  gitlab_runner_summary               — runner tag/locking posture
  gitlab_merge_request_approval_summary — MR approval requirement posture
"""

from __future__ import annotations

from typing import Any

from app.connectors.gitlab_schema import (
    GITLAB_BRANCH_PROTECTION,
    GITLAB_CI_VARIABLE_SUMMARY,
    GITLAB_DEPLOY_KEY_SUMMARY,
    GITLAB_GROUP,
    GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY,
    GITLAB_PROJECT,
    GITLAB_RUNNER_SUMMARY,
    GITLAB_WEBHOOK,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Shared disclaimer ─────────────────────────────────────────────────────────

_DISCLAIMER = (
    "This does not confirm compromise, unauthorized access, source-code "
    "exposure, secret exposure, token exposure, or data exposure. "
    "GitLab configuration evidence may require review."
)

# ── Rule key constants ─────────────────────────────────────────────────────────

# Project rules (M87B)
RULE_PROJECT_PUBLIC_VISIBILITY = "gitlab_project_public_visibility"
RULE_PROJECT_SHARED_RUNNERS_ENABLED = "gitlab_project_shared_runners_enabled"
RULE_PROJECT_SNIPPETS_ENABLED_PUBLIC = "gitlab_project_snippets_enabled_public"

# Group rules (M87B)
RULE_GROUP_PUBLIC_VISIBILITY = "gitlab_group_public_visibility"

# Branch protection rules (M87B)
RULE_BRANCH_FORCE_PUSH_ENABLED = "gitlab_branch_force_push_enabled"
RULE_BRANCH_CODE_OWNER_APPROVAL_MISSING = "gitlab_branch_code_owner_approval_missing"

# Webhook rules (M87B)
RULE_WEBHOOK_SECRET_MISSING = "gitlab_webhook_secret_missing"
RULE_WEBHOOK_SSL_VERIFICATION_DISABLED = "gitlab_webhook_ssl_verification_disabled"

# CI variable rules (M87B)
RULE_CI_UNPROTECTED_UNMASKED_VARIABLES = "gitlab_ci_unprotected_unmasked_variables"

# Deploy key rules (M87B)
RULE_DEPLOY_KEY_WRITE_ENABLED = "gitlab_deploy_key_write_enabled"

# Runner rules (M87B)
RULE_RUNNER_UNTAGGED = "gitlab_runner_untagged"

# MR approval rules (M87B)
RULE_MR_APPROVAL_NOT_REQUIRED = "gitlab_merge_request_approval_not_required"


# Exported set of all rule keys in this module
GITLAB_RULE_KEYS: frozenset[str] = frozenset({
    RULE_PROJECT_PUBLIC_VISIBILITY,
    RULE_PROJECT_SHARED_RUNNERS_ENABLED,
    RULE_PROJECT_SNIPPETS_ENABLED_PUBLIC,
    RULE_GROUP_PUBLIC_VISIBILITY,
    RULE_BRANCH_FORCE_PUSH_ENABLED,
    RULE_BRANCH_CODE_OWNER_APPROVAL_MISSING,
    RULE_WEBHOOK_SECRET_MISSING,
    RULE_WEBHOOK_SSL_VERIFICATION_DISABLED,
    RULE_CI_UNPROTECTED_UNMASKED_VARIABLES,
    RULE_DEPLOY_KEY_WRITE_ENABLED,
    RULE_RUNNER_UNTAGGED,
    RULE_MR_APPROVAL_NOT_REQUIRED,
})


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

    Only includes fields whose values are booleans, ints, or short strings that
    do not look like secrets, tokens, URLs, or raw identifiers.
    """
    NEVER_INCLUDE = {
        "token", "secret", "private_token", "authorization",
        "webhook_url", "url", "ci_variable_name", "ci_variable_value",
        "deploy_key_material", "ssh_key", "runner_token",
        "user_email", "username", "project_name", "group_name",
        "branch_name", "raw", "payload", "request", "response",
        "password", "key_material", "fingerprint", "access_token",
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
            out[key] = val
    return out


# ── Project rules ─────────────────────────────────────────────────────────────

def _eval_project(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []

    visibility = get_str(record, "visibility_category")
    record_id = record.get("record_id")
    resource_id = get_str(record, "resource_id")

    # Rule 1: public project visibility
    if visibility == "public":
        candidates.append(
            FindingCandidate(
                provider="gitlab",
                rule_key=RULE_PROJECT_PUBLIC_VISIBILITY,
                finding_key=make_finding_key(RULE_PROJECT_PUBLIC_VISIBILITY, record_id),
                severity="high",
                title="GitLab project has public visibility",
                description=(
                    "A GitLab project is configured with public visibility. "
                    "Public projects are accessible to anyone on the internet. "
                    "Verify this is intentional. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "visibility_category", "archived",
                    "default_branch_present", "protected_branch_count",
                ),
                record_id=record_id,
            )
        )

    # Rule 2: shared runners enabled on non-public projects
    shared_runners = _get_bool(record, "shared_runners_enabled")
    if shared_runners is True and visibility not in ("public",):
        candidates.append(
            FindingCandidate(
                provider="gitlab",
                rule_key=RULE_PROJECT_SHARED_RUNNERS_ENABLED,
                finding_key=make_finding_key(RULE_PROJECT_SHARED_RUNNERS_ENABLED, record_id),
                severity="medium",
                title="GitLab project has shared runners enabled",
                description=(
                    "Shared runners are enabled on this GitLab project. "
                    "Shared runners execute CI/CD jobs on infrastructure shared with "
                    "other projects. Verify the runner configuration meets your "
                    "isolation requirements. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "visibility_category", "shared_runners_enabled",
                ),
                record_id=record_id,
            )
        )

    # Rule 3: snippets enabled on public project
    snippets = _get_bool(record, "snippets_enabled")
    if snippets is True and visibility == "public":
        candidates.append(
            FindingCandidate(
                provider="gitlab",
                rule_key=RULE_PROJECT_SNIPPETS_ENABLED_PUBLIC,
                finding_key=make_finding_key(RULE_PROJECT_SNIPPETS_ENABLED_PUBLIC, record_id),
                severity="low",
                title="GitLab public project has snippets enabled",
                description=(
                    "Snippets are enabled on a public GitLab project. "
                    "Any member can post code snippets that are publicly visible. "
                    "Review whether snippet sharing is appropriate for this project. "
                    + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "visibility_category", "snippets_enabled",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── Group rules ───────────────────────────────────────────────────────────────

def _eval_group(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []

    visibility = get_str(record, "visibility_category")
    record_id = record.get("record_id")

    # Rule 4: public group visibility
    if visibility == "public":
        candidates.append(
            FindingCandidate(
                provider="gitlab",
                rule_key=RULE_GROUP_PUBLIC_VISIBILITY,
                finding_key=make_finding_key(RULE_GROUP_PUBLIC_VISIBILITY, record_id),
                severity="high",
                title="GitLab group has public visibility",
                description=(
                    "A GitLab group is configured with public visibility. "
                    "Public groups expose their membership structure and contained "
                    "projects to anyone on the internet. "
                    "Verify this configuration is intentional. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "visibility_category",
                    "project_count", "subgroup_count", "member_count_category",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── Branch protection rules ───────────────────────────────────────────────────

def _eval_branch_protection(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []

    record_id = record.get("record_id")
    allow_force_push = _get_bool(record, "allow_force_push")
    code_owner_required = _get_bool(record, "code_owner_approval_required")
    pattern_category = get_str(record, "pattern_category")

    # Rule 5: force push enabled
    if allow_force_push is True:
        candidates.append(
            FindingCandidate(
                provider="gitlab",
                rule_key=RULE_BRANCH_FORCE_PUSH_ENABLED,
                finding_key=make_finding_key(RULE_BRANCH_FORCE_PUSH_ENABLED, record_id),
                severity="high",
                title="GitLab protected branch allows force push",
                description=(
                    "A GitLab branch protection rule has force push enabled. "
                    "Allowing force push on protected branches can overwrite or "
                    "remove commit history. Review whether force push is intentional "
                    "for this branch protection rule. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "project_resource_id", "pattern_category",
                    "allow_force_push", "push_access_level_category",
                    "merge_access_level_category",
                ),
                record_id=record_id,
            )
        )

    # Rule 6: code owner approval missing on protected/default/wildcard branches
    if (
        code_owner_required is False
        and pattern_category in ("protected", "default", "wildcard")
    ):
        candidates.append(
            FindingCandidate(
                provider="gitlab",
                rule_key=RULE_BRANCH_CODE_OWNER_APPROVAL_MISSING,
                finding_key=make_finding_key(RULE_BRANCH_CODE_OWNER_APPROVAL_MISSING, record_id),
                severity="medium",
                title="GitLab branch protection does not require code owner approval",
                description=(
                    "A GitLab protected branch rule does not require code owner "
                    "approval before merge. Code owner approval helps ensure that "
                    "changes to sensitive areas are reviewed by the designated owners. "
                    + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "project_resource_id", "pattern_category",
                    "code_owner_approval_required", "allowed_to_merge_count",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── Webhook rules ─────────────────────────────────────────────────────────────

def _eval_webhook(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []

    record_id = record.get("record_id")
    enabled = _get_bool(record, "enabled")
    if enabled is False:
        # Only evaluate active webhooks
        return candidates

    ssl_verification = _get_bool(record, "ssl_verification_enabled")
    secret_present = _get_bool(record, "secret_token_present")

    # Rule 7: no secret token on active webhook
    if secret_present is False:
        candidates.append(
            FindingCandidate(
                provider="gitlab",
                rule_key=RULE_WEBHOOK_SECRET_MISSING,
                finding_key=make_finding_key(RULE_WEBHOOK_SECRET_MISSING, record_id),
                severity="high",
                title="GitLab webhook has no secret token",
                description=(
                    "An active GitLab webhook does not have a secret token configured. "
                    "Without a secret token, the receiving endpoint cannot verify that "
                    "delivery requests originate from GitLab. "
                    + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "owner_type", "owner_resource_id",
                    "enabled", "secret_token_present", "event_count",
                    "ssl_verification_enabled",
                ),
                record_id=record_id,
            )
        )

    # Rule 8: SSL verification disabled on active webhook
    if ssl_verification is False:
        candidates.append(
            FindingCandidate(
                provider="gitlab",
                rule_key=RULE_WEBHOOK_SSL_VERIFICATION_DISABLED,
                finding_key=make_finding_key(RULE_WEBHOOK_SSL_VERIFICATION_DISABLED, record_id),
                severity="high",
                title="GitLab webhook has SSL verification disabled",
                description=(
                    "An active GitLab webhook has SSL certificate verification "
                    "disabled. Disabling SSL verification means the endpoint's "
                    "certificate is not validated, which may allow event delivery "
                    "to unverified endpoints. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "owner_type", "owner_resource_id",
                    "enabled", "ssl_verification_enabled", "secret_token_present",
                    "event_count",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── CI variable summary rules ─────────────────────────────────────────────────

def _eval_ci_variable_summary(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []

    record_id = record.get("record_id")
    unprotected_unmasked = _get_int(record, "unprotected_unmasked_count")

    # Rule 9: unprotected and unmasked CI variables present
    if unprotected_unmasked is not None and unprotected_unmasked > 0:
        candidates.append(
            FindingCandidate(
                provider="gitlab",
                rule_key=RULE_CI_UNPROTECTED_UNMASKED_VARIABLES,
                finding_key=make_finding_key(RULE_CI_UNPROTECTED_UNMASKED_VARIABLES, record_id),
                severity="high",
                title="GitLab CI/CD variables are unprotected and unmasked",
                description=(
                    f"{unprotected_unmasked} CI/CD variable(s) in this GitLab "
                    "project or group are neither protected nor masked. Unprotected "
                    "variables are available in all branches and forks; unmasked "
                    "variables may appear in job logs. CI/CD variable posture "
                    "evidence may require review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "owner_type", "owner_resource_id",
                    "variable_count", "unprotected_unmasked_count",
                    "protected_variable_count", "masked_variable_count",
                    "environment_scoped_count",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── Deploy key summary rules ──────────────────────────────────────────────────

def _eval_deploy_key_summary(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []

    record_id = record.get("record_id")
    write_count = _get_int(record, "write_enabled_count")

    # Rule 10: write-enabled deploy keys
    if write_count is not None and write_count > 0:
        candidates.append(
            FindingCandidate(
                provider="gitlab",
                rule_key=RULE_DEPLOY_KEY_WRITE_ENABLED,
                finding_key=make_finding_key(RULE_DEPLOY_KEY_WRITE_ENABLED, record_id),
                severity="high",
                title="GitLab project has write-enabled deploy keys",
                description=(
                    f"{write_count} deploy key(s) on this GitLab project have "
                    "write access enabled. Write-enabled deploy keys can push "
                    "commits to the repository. Deploy key posture evidence may "
                    "require review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "project_resource_id",
                    "deploy_key_count", "write_enabled_count", "read_only_count",
                    "enabled_count",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── Runner summary rules ──────────────────────────────────────────────────────

def _eval_runner_summary(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []

    record_id = record.get("record_id")
    untagged_count = _get_int(record, "untagged_runner_count")

    # Rule 11: untagged runners present
    # (untagged runners accept any job, not just tagged/specific jobs)
    if untagged_count is not None and untagged_count > 0:
        candidates.append(
            FindingCandidate(
                provider="gitlab",
                rule_key=RULE_RUNNER_UNTAGGED,
                finding_key=make_finding_key(RULE_RUNNER_UNTAGGED, record_id),
                severity="medium",
                title="GitLab runner accepts untagged jobs",
                description=(
                    f"{untagged_count} runner(s) in this GitLab project or group "
                    "are configured to accept untagged jobs. Runners that accept "
                    "untagged jobs will execute any pipeline job without tag "
                    "restrictions. Runner configuration evidence may require review. "
                    + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "owner_type", "owner_resource_id",
                    "runner_count", "untagged_runner_count", "tagged_runner_count",
                    "locked_runner_count", "paused_runner_count",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── MR approval summary rules ─────────────────────────────────────────────────

def _eval_mr_approval_summary(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []

    record_id = record.get("record_id")
    approvals_required = _get_int(record, "approvals_required")

    # Rule 12: no approvals required
    if approvals_required is not None and approvals_required == 0:
        candidates.append(
            FindingCandidate(
                provider="gitlab",
                rule_key=RULE_MR_APPROVAL_NOT_REQUIRED,
                finding_key=make_finding_key(RULE_MR_APPROVAL_NOT_REQUIRED, record_id),
                severity="medium",
                title="GitLab project does not require merge request approvals",
                description=(
                    "This GitLab project has no merge request approval requirement "
                    "(approvals_required is 0). Merge requests can be merged without "
                    "any peer review. Merge request approval configuration evidence "
                    "may require review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "project_resource_id",
                    "approval_rule_count", "approvals_required",
                    "code_owner_approval_required", "reset_approvals_on_push",
                    "disable_overriding_approvers_per_merge_request",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── Top-level dispatcher ──────────────────────────────────────────────────────

def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one normalized GitLab snapshot record for configuration risks.

    Dispatches to the appropriate per-surface evaluator based on record_type.
    Unknown record types return no findings (safe default).

    Args:
        record: A flat normalized dict from the GitLab connector.

    Returns:
        A list of FindingCandidate instances; may be empty.
    """
    if not isinstance(record, dict):
        return []

    rtype = get_str(record, "record_type")

    if rtype == GITLAB_PROJECT:
        return _eval_project(record)
    if rtype == GITLAB_GROUP:
        return _eval_group(record)
    if rtype == GITLAB_BRANCH_PROTECTION:
        return _eval_branch_protection(record)
    if rtype == GITLAB_WEBHOOK:
        return _eval_webhook(record)
    if rtype == GITLAB_CI_VARIABLE_SUMMARY:
        return _eval_ci_variable_summary(record)
    if rtype == GITLAB_DEPLOY_KEY_SUMMARY:
        return _eval_deploy_key_summary(record)
    if rtype == GITLAB_RUNNER_SUMMARY:
        return _eval_runner_summary(record)
    if rtype == GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY:
        return _eval_mr_approval_summary(record)

    # gitlab_instance: no security rules at M87B; covered in M87C
    return []
