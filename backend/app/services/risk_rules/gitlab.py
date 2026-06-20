"""GitLab drift risk classification rules (M87A).

Entry point: ``classify_gitlab_change(change)``

Classifies drift changes for GitLab configuration records.

Risk levels
-----------
high   — Project/group visibility changed to public; branch protection removed
         or force-push enabled; webhook secret removed; webhook SSL verification
         disabled; CI variable posture weakens materially; deploy key write
         count increases.

medium — Webhook event scope broadens; approval requirements reduced;
         code-owner approval disabled; runner protection weakens; CI variable
         count increases without protected/masked increase.

low    — Count-only changes with unclear impact; metadata-only drift; unknown
         optional fields; safe enablement with no exposure signal.

Claim discipline
----------------
All reason strings use safe review-framing:
  "GitLab configuration evidence may require review."
  "may require review"
  "does not confirm"
Forbidden phrases: breach, compromise, attacker, leaked, unauthorized access,
exfiltration, stolen, fraud, attack, repo exposed, secret exposed, token leaked.
"""

from __future__ import annotations

from app.models.change import Change


def _get(obj: object, field: str) -> object:
    """Safely retrieve a field from a Change object or dict."""
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


# ── gitlab_instance ───────────────────────────────────────────────────────────


def _classify_instance_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return (
            "low",
            "GitLab instance configuration record was added or removed during sync.",
        )

    if fp == "two_factor_requirement_enabled":
        if new_v is False or new_v == "false":
            return (
                "high",
                "GitLab instance two-factor authentication requirement was disabled. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab instance two-factor authentication requirement was enabled.",
        )

    if fp == "sign_up_enabled":
        if new_v is True or new_v == "true":
            return (
                "medium",
                "GitLab instance sign-up was enabled. "
                "This may allow new users to register — GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab instance sign-up was disabled.",
        )

    if fp == "visibility_restriction_category":
        if new_v in ("public", "unknown"):
            return (
                "medium",
                "GitLab instance default project visibility changed to a less restrictive category. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab instance default project visibility category changed.",
        )

    if fp == "shared_runners_enabled":
        if new_v is True or new_v == "true":
            return (
                "medium",
                "GitLab instance shared runners were enabled. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab instance shared runners setting changed.",
        )

    return (
        "low",
        f"GitLab instance configuration field '{fp}' changed.",
    )


# ── gitlab_project ────────────────────────────────────────────────────────────


def _classify_project_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct == "added":
        return (
            "low",
            "A new GitLab project configuration record was observed.",
        )
    if ct == "removed":
        return (
            "medium",
            "A GitLab project configuration record was removed. "
            "GitLab configuration evidence may require review.",
        )

    if fp == "visibility_category":
        if new_v == "public":
            return (
                "high",
                "GitLab project visibility changed to public. "
                "GitLab configuration evidence may require review.",
            )
        if new_v == "internal":
            return (
                "medium",
                "GitLab project visibility changed to internal. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab project visibility changed to a more restrictive setting.",
        )

    if fp == "archived":
        if new_v is False or new_v == "false":
            return (
                "low",
                "A GitLab project was unarchived — it is now active again.",
            )
        return (
            "low",
            "A GitLab project was archived.",
        )

    if fp == "protected_branch_count":
        try:
            old_n = int(prev_v or 0)
            new_n = int(new_v or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n < old_n:
            return (
                "high",
                f"GitLab project protected branch count decreased from {old_n} to {new_n}. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab project protected branch count changed from {old_n} to {new_n}.",
        )

    if fp == "deploy_key_count":
        try:
            old_n = int(prev_v or 0)
            new_n = int(new_v or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n > old_n:
            return (
                "medium",
                f"GitLab project deploy key count increased from {old_n} to {new_n}. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab project deploy key count changed from {old_n} to {new_n}.",
        )

    if fp == "webhook_count":
        try:
            old_n = int(prev_v or 0)
            new_n = int(new_v or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n > old_n:
            return (
                "medium",
                f"GitLab project webhook count increased from {old_n} to {new_n}. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab project webhook count changed from {old_n} to {new_n}.",
        )

    if fp in ("wiki_enabled", "snippets_enabled", "packages_enabled"):
        if new_v is True or new_v == "true":
            return (
                "low",
                f"GitLab project {fp.replace('_enabled', '')} feature was enabled.",
            )
        return (
            "low",
            f"GitLab project {fp.replace('_enabled', '')} feature was disabled.",
        )

    if fp == "shared_runners_enabled":
        if new_v is True or new_v == "true":
            return (
                "medium",
                "GitLab project shared runners were enabled. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab project shared runners were disabled.",
        )

    return (
        "low",
        f"GitLab project configuration field '{fp}' changed.",
    )


# ── gitlab_group ──────────────────────────────────────────────────────────────


def _classify_group_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return (
            "low",
            "GitLab group configuration record was added or removed during sync.",
        )

    if fp == "visibility_category":
        if new_v == "public":
            return (
                "high",
                "GitLab group visibility changed to public. "
                "GitLab configuration evidence may require review.",
            )
        if new_v == "internal":
            return (
                "medium",
                "GitLab group visibility changed to internal. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab group visibility changed to a more restrictive setting.",
        )

    if fp == "two_factor_requirement_enabled":
        if new_v is False or new_v == "false":
            return (
                "high",
                "GitLab group two-factor authentication requirement was disabled. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab group two-factor authentication requirement was enabled.",
        )

    if fp == "membership_lock":
        if new_v is False or new_v == "false":
            return (
                "medium",
                "GitLab group membership lock was disabled. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab group membership lock was enabled.",
        )

    return (
        "low",
        f"GitLab group configuration field '{fp}' changed.",
    )


# ── gitlab_branch_protection ─────────────────────────────────────────────────


def _classify_branch_protection_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "removed":
        return (
            "high",
            "A GitLab branch protection rule was removed. "
            "GitLab configuration evidence may require review.",
        )

    if ct == "added":
        return (
            "low",
            "A new GitLab branch protection rule was added.",
        )

    if fp == "allow_force_push":
        if new_v is True or new_v == "true":
            return (
                "high",
                "GitLab branch protection: force push was enabled. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab branch protection: force push was disabled (hardened).",
        )

    if fp == "code_owner_approval_required":
        if new_v is False or new_v == "false":
            return (
                "medium",
                "GitLab branch protection: code owner approval requirement was disabled. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab branch protection: code owner approval requirement was enabled.",
        )

    if fp == "push_access_level_category":
        if new_v in ("developer", "reporter", "guest", "no_access"):
            return (
                "medium",
                f"GitLab branch protection push access level changed to '{new_v}'. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab branch protection push access level changed to '{new_v}'.",
        )

    if fp == "merge_access_level_category":
        if new_v in ("developer", "reporter", "guest", "no_access"):
            return (
                "medium",
                f"GitLab branch protection merge access level changed to '{new_v}'. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab branch protection merge access level changed to '{new_v}'.",
        )

    if fp in ("allowed_to_push_count", "allowed_to_merge_count"):
        try:
            new_n = int(new_v or 0)
        except (ValueError, TypeError):
            new_n = 0
        if new_n == 0:
            return (
                "medium",
                f"GitLab branch protection {fp.replace('_', ' ')} dropped to zero. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab branch protection {fp.replace('_', ' ')} changed.",
        )

    return (
        "low",
        f"GitLab branch protection field '{fp}' changed.",
    )


# ── gitlab_webhook ────────────────────────────────────────────────────────────


def _classify_webhook_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "added":
        return (
            "medium",
            "A new GitLab webhook was added. "
            "GitLab configuration evidence may require review.",
        )

    if ct == "removed":
        return (
            "medium",
            "A GitLab webhook was removed. "
            "GitLab configuration evidence may require review.",
        )

    if fp == "ssl_verification_enabled":
        if new_v is False or new_v == "false":
            return (
                "high",
                "GitLab webhook SSL verification was disabled. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab webhook SSL verification was enabled.",
        )

    if fp == "secret_token_present":
        if new_v is False or new_v == "false":
            return (
                "high",
                "GitLab webhook secret token was removed. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab webhook secret token was added.",
        )

    if fp == "url_scheme":
        if new_v == "http":
            return (
                "high",
                "GitLab webhook URL scheme changed to HTTP (non-encrypted). "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab webhook URL scheme changed to HTTPS.",
        )

    if fp == "event_count":
        try:
            new_n = int(new_v or 0)
        except (ValueError, TypeError):
            new_n = 0
        if new_n > 5:
            return (
                "medium",
                f"GitLab webhook event scope broadened (now {new_n} events). "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab webhook event count changed to {new_n}.",
        )

    if fp in ("push_events", "merge_requests_events", "pipeline_events", "job_events"):
        if new_v is True or new_v == "true":
            return (
                "medium",
                f"GitLab webhook event scope expanded: {fp} enabled. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab webhook event scope: {fp} disabled.",
        )

    return (
        "low",
        f"GitLab webhook field '{fp}' changed.",
    )


# ── gitlab_ci_variable_summary ────────────────────────────────────────────────


def _classify_ci_variable_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return (
            "low",
            "GitLab CI variable summary record was added or removed during sync.",
        )

    if fp == "unprotected_unmasked_count":
        try:
            old_n = int(prev_v or 0)
            new_n = int(new_v or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n > old_n:
            return (
                "high",
                f"GitLab unprotected/unmasked CI variable count increased from {old_n} to {new_n}. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab unprotected/unmasked CI variable count changed to {new_n}.",
        )

    if fp == "variable_count":
        try:
            old_n = int(prev_v or 0)
            new_n = int(new_v or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n > old_n:
            return (
                "medium",
                f"GitLab CI variable count increased from {old_n} to {new_n}. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab CI variable count changed from {old_n} to {new_n}.",
        )

    if fp in ("protected_variable_count", "masked_variable_count"):
        try:
            old_n = int(prev_v or 0)
            new_n = int(new_v or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n < old_n:
            return (
                "medium",
                f"GitLab {fp.replace('_', ' ')} decreased from {old_n} to {new_n}. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab {fp.replace('_', ' ')} changed from {old_n} to {new_n}.",
        )

    return (
        "low",
        f"GitLab CI variable summary field '{fp}' changed.",
    )


# ── gitlab_deploy_key_summary ─────────────────────────────────────────────────


def _classify_deploy_key_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return (
            "low",
            "GitLab deploy key summary record was added or removed during sync.",
        )

    if fp == "write_enabled_count":
        try:
            old_n = int(prev_v or 0)
            new_n = int(new_v or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n > old_n:
            return (
                "high",
                f"GitLab deploy key write-enabled count increased from {old_n} to {new_n}. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab deploy key write-enabled count changed from {old_n} to {new_n}.",
        )

    if fp == "deploy_key_count":
        try:
            old_n = int(prev_v or 0)
            new_n = int(new_v or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n > old_n:
            return (
                "medium",
                f"GitLab deploy key count increased from {old_n} to {new_n}. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab deploy key count changed from {old_n} to {new_n}.",
        )

    return (
        "low",
        f"GitLab deploy key summary field '{fp}' changed.",
    )


# ── gitlab_runner_summary ─────────────────────────────────────────────────────


def _classify_runner_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return (
            "low",
            "GitLab runner summary record was added or removed during sync.",
        )

    if fp == "locked_runner_count":
        try:
            old_n = int(prev_v or 0)
            new_n = int(new_v or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n < old_n:
            return (
                "medium",
                f"GitLab locked runner count decreased from {old_n} to {new_n}. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab locked runner count changed from {old_n} to {new_n}.",
        )

    if fp == "paused_runner_count":
        try:
            old_n = int(prev_v or 0)
            new_n = int(new_v or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n > old_n:
            return (
                "low",
                f"GitLab paused runner count increased from {old_n} to {new_n}.",
            )
        return (
            "low",
            f"GitLab paused runner count changed from {old_n} to {new_n}.",
        )

    return (
        "low",
        f"GitLab runner summary field '{fp}' changed.",
    )


# ── gitlab_merge_request_approval_summary ─────────────────────────────────────


def _classify_mr_approval_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return (
            "low",
            "GitLab MR approval summary record was added or removed during sync.",
        )

    if fp == "approvals_required":
        try:
            old_n = int(prev_v or 0)
            new_n = int(new_v or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n < old_n:
            return (
                "medium",
                f"GitLab MR required approvals decreased from {old_n} to {new_n}. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            f"GitLab MR required approvals changed from {old_n} to {new_n}.",
        )

    if fp == "code_owner_approval_required":
        if new_v is False or new_v == "false":
            return (
                "medium",
                "GitLab MR code owner approval requirement was disabled. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab MR code owner approval requirement was enabled.",
        )

    if fp == "disable_overriding_approvers_per_merge_request":
        if new_v is False or new_v == "false":
            return (
                "medium",
                "GitLab MR approvers can now be overridden per merge request. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab MR approver override was disabled.",
        )

    if fp == "reset_approvals_on_push":
        if new_v is False or new_v == "false":
            return (
                "medium",
                "GitLab MR approval reset on push was disabled. "
                "GitLab configuration evidence may require review.",
            )
        return (
            "low",
            "GitLab MR approval reset on push was enabled.",
        )

    return (
        "low",
        f"GitLab MR approval summary field '{fp}' changed.",
    )


# ── Main dispatcher ───────────────────────────────────────────────────────────


def classify_gitlab_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for a GitLab configuration change.

    Dispatches on ``provider_metadata["record_type"]``:
      * ``gitlab_instance``                     → instance-level rules
      * ``gitlab_project``                      → project posture rules
      * ``gitlab_group``                        → group posture rules
      * ``gitlab_branch_protection``            → branch protection rules
      * ``gitlab_webhook``                      → webhook posture rules
      * ``gitlab_ci_variable_summary``          → CI variable count rules
      * ``gitlab_deploy_key_summary``           → deploy key count rules
      * ``gitlab_runner_summary``               → runner posture rules
      * ``gitlab_merge_request_approval_summary`` → MR approval rules

    Does not confirm breach, compromise, or unauthorized access.
    GitLab configuration evidence may require review.
    """
    pm = _get(change, "provider_metadata") or {}
    if isinstance(pm, dict):
        record_type = (pm.get("record_type") or "").lower()
    else:
        record_type = ""

    if record_type == "gitlab_instance":
        return _classify_instance_change(change)
    if record_type == "gitlab_project":
        return _classify_project_change(change)
    if record_type == "gitlab_group":
        return _classify_group_change(change)
    if record_type == "gitlab_branch_protection":
        return _classify_branch_protection_change(change)
    if record_type == "gitlab_webhook":
        return _classify_webhook_change(change)
    if record_type == "gitlab_ci_variable_summary":
        return _classify_ci_variable_change(change)
    if record_type == "gitlab_deploy_key_summary":
        return _classify_deploy_key_change(change)
    if record_type == "gitlab_runner_summary":
        return _classify_runner_change(change)
    if record_type == "gitlab_merge_request_approval_summary":
        return _classify_mr_approval_change(change)

    # Fallback for unknown gitlab_ subtypes
    return (
        "low",
        f"GitLab configuration changed (record type: {record_type or 'unknown'}). "
        "GitLab configuration evidence may require review.",
    )
