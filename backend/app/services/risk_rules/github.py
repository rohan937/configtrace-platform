"""GitHub repository configuration risk rules — Milestone 26.

Classifies a Change (ORM object or plain dict) that originated from a GitHub
integration into one of four risk levels:

    critical  — changes that remove gates preventing dangerous code or
                credentials from reaching production, or that expose the
                repository to the public internet
    high      — changes that weaken security posture, expose secrets, disrupt
                critical automation, or affect deployment access
    medium    — notable changes that alter behaviour but are generally
                reversible or have lower immediate impact
    low       — cosmetic, additive, or routine low-impact changes

Signal model
------------
Each rule weighs multiple signals simultaneously — no single signal is
sufficient on its own:

    1. Category (record_type)   — what kind of configuration changed
    2. Direction of change      — protection weakened vs. strengthened
    3. Security / production impact — does this affect deployment safety?
    4. Name sensitivity         — does a secret / variable name suggest a
                                  production credential?
    5. Change type              — added / removed / modified and the specific
                                  direction of that modification

Keyword matching is one input among these five, never the sole determinant.

Rule order
----------
Within each record-type block: most-severe → least-severe.  The first
matching rule short-circuits the rest.
"""

from __future__ import annotations

import re
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Attribute-access helper (supports both ORM objects and plain dicts)
# ─────────────────────────────────────────────────────────────────────────────

def _get(obj: Any, key: str) -> Any:
    """Return *obj[key]* for dicts, or ``getattr(obj, key, None)`` for objects."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


# ─────────────────────────────────────────────────────────────────────────────
# Sensitive name patterns
# ─────────────────────────────────────────────────────────────────────────────

#: Substrings that, found in a secret or variable name, indicate a
#: production credential.  Used to escalate secret additions from Low→Medium
#: and secret / variable changes to High.  Matched case-insensitively.
#:
#: Ordering note: longer patterns (e.g. ``API_KEY``) appear before shorter
#: subsets (``KEY``) for documentation clarity only — ``re.search`` finds
#: any substring match regardless of order.
_SENSITIVE_PATTERNS: tuple[str, ...] = (
    "PRODUCTION",
    "PROD",
    "DATABASE",
    "DB",
    "API_KEY",
    "PRIVATE_KEY",
    "TOKEN",
    "SECRET",
    "STRIPE",
    "CLOUDFLARE",
    "AWS",
    "VERCEL",
    "SUPABASE",
    "FIREBASE",
    "OPENAI",
    "CLERK",
    "RESEND",
    "WEBHOOK",
    "KEY",
)

# Pre-compile a single OR-pattern for efficient repeated matching.
_SENSITIVE_RE = re.compile(
    "|".join(re.escape(p) for p in _SENSITIVE_PATTERNS),
    re.IGNORECASE,
)


def _is_sensitive_secret(name: str) -> bool:
    """Return ``True`` if *name* contains any sensitive substring.

    Used for both secret and variable names — the sensitivity check is
    identical regardless of record type.
    """
    return bool(_SENSITIVE_RE.search(name or ""))


# ─────────────────────────────────────────────────────────────────────────────
# Main classifier
# ─────────────────────────────────────────────────────────────────────────────

def classify_github_change(change: Any) -> tuple[str, str]:
    """Classify a GitHub configuration change and return ``(risk_level, risk_reason)``.

    Accepts either a SQLAlchemy ``Change`` ORM object or a plain ``dict``
    (e.g. from unit tests).

    Dispatches on ``provider_metadata["record_type"]`` to the appropriate
    per-category rule set.

    Args:
        change: A ``Change`` ORM instance or a ``dict`` with the same field
                names (``change_type``, ``field_path``, ``prev_value``,
                ``new_value``, ``provider_metadata``).

    Returns:
        ``(risk_level, risk_reason)`` where *risk_level* is one of
        ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
    """
    change_type = (_get(change, "change_type") or "").lower()
    field_path = _get(change, "field_path") or ""
    prev_value = _get(change, "prev_value")
    new_value = _get(change, "new_value")
    pm: dict[str, Any] = _get(change, "provider_metadata") or {}
    record_type = (pm.get("record_type") or "").lower()
    record_name = pm.get("record_name") or ""

    if record_type == "github_repo_settings":
        return _classify_repo_settings(change_type, field_path, prev_value, new_value)

    if record_type == "github_branch_protection":
        return _classify_branch_protection(change_type, field_path, prev_value, new_value)

    if record_type == "github_actions_secret":
        return _classify_actions_secret(change_type, field_path, record_name)

    if record_type == "github_actions_variable":
        return _classify_actions_variable(change_type, record_name, new_value)

    if record_type == "github_webhook":
        return _classify_webhook(change_type, field_path, prev_value, new_value)

    if record_type == "github_actions_permissions":
        return _classify_actions_permissions(change_type, field_path, prev_value, new_value)

    if record_type == "github_deploy_key":
        return _classify_deploy_key(change_type, field_path, prev_value, new_value)

    if record_type == "github_environment_protection":
        return _classify_environment_protection(
            change_type, field_path, prev_value, new_value, record_name
        )

    # Unknown GitHub record type — safe low-severity fallback.
    return (
        "low",
        "An unrecognised GitHub configuration record changed. This may be a "
        "new record type introduced in a future update.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Per-category rule sets
# ─────────────────────────────────────────────────────────────────────────────


def _classify_repo_settings(
    change_type: str,
    field_path: str,
    prev_value: Any,
    new_value: Any,
) -> tuple[str, str]:
    """Rules for ``github_repo_settings`` records.

    Risk signals considered: visibility direction, archival, default branch,
    and merge-policy changes.
    """

    # ── CRITICAL ──────────────────────────────────────────────────────────────

    # Repository made public — exposes all code, issues, and history to the
    # public internet.  Reversing this requires another deliberate action.
    if (
        change_type == "modified"
        and field_path == "visibility"
        and str(new_value).lower() == "public"
    ):
        return (
            "critical",
            "Repository visibility changed to public. All code, commit history, "
            "issues, and configuration are now accessible to anyone on the internet. "
            "Review whether sensitive data or secrets may be exposed.",
        )

    # ── HIGH ──────────────────────────────────────────────────────────────────

    # Default branch changed — affects all CI/CD pipelines, branch policies,
    # integrations, and auto-deploy rules that reference the default branch.
    if change_type == "modified" and field_path == "default_branch":
        return (
            "high",
            f"Default branch changed from '{prev_value}' to '{new_value}'. "
            "CI/CD pipelines, branch protection rules, and integrations that "
            "target the default branch may now behave differently.",
        )

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    # Repository archived — becomes read-only; all write operations blocked.
    # Classified Medium because it is a deliberate, logged, reversible action.
    if change_type == "modified" and field_path == "archived" and new_value is True:
        return (
            "medium",
            "Repository was archived and is now read-only. All pushes, issue "
            "creation, and pull requests are blocked until the repository is "
            "unarchived.",
        )

    # Repository made private — visibility reduced (generally a safer change).
    if (
        change_type == "modified"
        and field_path == "visibility"
        and str(new_value).lower() in ("private", "internal")
    ):
        return (
            "medium",
            f"Repository visibility changed to '{new_value}'. Public access is "
            "removed. Verify that all required collaborators and integrations "
            "still have access.",
        )

    # Merge strategy changed — affects how pull requests are merged.
    if change_type == "modified" and field_path in (
        "allow_merge_commit",
        "allow_squash_merge",
        "allow_rebase_merge",
        "delete_branch_on_merge",
    ):
        return (
            "medium",
            f"Repository merge setting '{field_path}' changed to '{new_value}'. "
            "Pull request merge behaviour is affected for all contributors.",
        )

    # Other repository settings changes.
    if change_type == "modified":
        return (
            "medium",
            f"Repository setting '{field_path}' changed from '{prev_value}' "
            f"to '{new_value}'.",
        )

    # ── LOW ───────────────────────────────────────────────────────────────────
    return (
        "low",
        "A repository settings record was added or removed with no matched "
        "high-severity rule.",
    )


def _classify_branch_protection(
    change_type: str,
    field_path: str,
    prev_value: Any,
    new_value: Any,
) -> tuple[str, str]:
    """Rules for ``github_branch_protection`` records.

    Signal model: changes that remove or weaken gates on the protected branch
    are Critical or High; changes that add or strengthen gates are Low.

    Direction of change (weakening vs. strengthening) is the primary signal,
    with the specific setting determining the exact severity.
    """

    # ── CRITICAL (gates removed entirely) ────────────────────────────────────

    # Branch protection record deleted — branch is now completely unprotected.
    if change_type == "removed":
        return (
            "critical",
            "A branch protection rule was deleted. The branch is now fully "
            "unprotected — anyone with write access can force-push, delete it, "
            "or merge without review.",
        )

    # Protection flag disabled — equivalent to removing all protection.
    if (
        change_type == "modified"
        and field_path == "protection_enabled"
        and new_value is False
    ):
        return (
            "critical",
            "Branch protection has been disabled. The branch is now unprotected "
            "and can be force-pushed to or deleted by anyone with write access.",
        )

    # Force-pushes allowed — commit history can now be silently rewritten.
    if (
        change_type == "modified"
        and field_path == "allow_force_pushes"
        and new_value is True
    ):
        return (
            "critical",
            "Force-pushes are now allowed on this branch. Commit history can be "
            "rewritten without a trace, which may silently discard work or "
            "introduce unauthorised changes.",
        )

    # Branch deletion allowed — the protected branch can now be deleted.
    if (
        change_type == "modified"
        and field_path == "allow_deletions"
        and new_value is True
    ):
        return (
            "critical",
            "Branch deletion is now allowed. The protected branch can be "
            "permanently deleted by anyone with write access.",
        )

    # Required status checks disabled — pull requests can merge without CI.
    if (
        change_type == "modified"
        and field_path == "required_status_checks_enabled"
        and new_value is False
    ):
        return (
            "critical",
            "Required status checks have been disabled. Pull requests can now "
            "be merged without any automated validation (tests, linting, etc.).",
        )

    # Required PR reviews disabled — changes can merge without peer review.
    if (
        change_type == "modified"
        and field_path == "required_pull_request_reviews_enabled"
        and new_value is False
    ):
        return (
            "critical",
            "Required pull request reviews have been disabled. Changes can now "
            "be merged to this branch without any peer review.",
        )

    # ── HIGH (protection weakened but not removed entirely) ───────────────────

    # Admins exempted from protection — they can now bypass review and CI.
    if (
        change_type == "modified"
        and field_path == "enforce_admins"
        and new_value is False
    ):
        return (
            "high",
            "Branch protection rules are no longer enforced for administrators. "
            "Admins can now bypass review requirements and status checks on this branch.",
        )

    # Linear history no longer required — merge commits now allowed.
    if (
        change_type == "modified"
        and field_path == "required_linear_history"
        and new_value is False
    ):
        return (
            "high",
            "Required linear history has been disabled. Merge commits are now "
            "allowed, making it harder to audit individual changes.",
        )

    # Required review count decreased — fewer approvals needed before merge.
    if (
        change_type == "modified"
        and field_path == "required_approving_review_count"
        and isinstance(prev_value, (int, float))
        and isinstance(new_value, (int, float))
        and new_value < prev_value
    ):
        return (
            "high",
            f"Required approving review count reduced from {int(prev_value)} "
            f"to {int(new_value)}. Fewer reviewers are needed to approve "
            "a pull request before it can be merged.",
        )

    # ── MEDIUM (notable changes, mostly strengthening or count increases) ─────

    # Required review count increased — more approvals now required (safer).
    if (
        change_type == "modified"
        and field_path == "required_approving_review_count"
        and isinstance(prev_value, (int, float))
        and isinstance(new_value, (int, float))
        and new_value > prev_value
    ):
        return (
            "medium",
            f"Required approving review count increased from {int(prev_value)} "
            f"to {int(new_value)}. More reviewers are now needed before merging.",
        )

    # Stale review dismissal disabled — old approvals survive new commits.
    if (
        change_type == "modified"
        and field_path == "dismiss_stale_reviews"
        and new_value is False
    ):
        return (
            "medium",
            "Dismissal of stale reviews was disabled. Approvals granted before "
            "new commits are pushed will no longer be automatically revoked.",
        )

    # ── LOW (protection added or explicitly strengthened) ─────────────────────

    # New protection rule created.
    if change_type == "added":
        return (
            "low",
            "A branch protection rule was added. The branch is now protected.",
        )

    if change_type == "modified":
        # Explicit strengthening checks — these fields moving in the safe
        # direction are Low because they reduce risk rather than increasing it.
        if field_path == "protection_enabled" and new_value is True:
            return (
                "low",
                "Branch protection has been enabled on this branch.",
            )
        if field_path in (
            "required_status_checks_enabled",
            "required_pull_request_reviews_enabled",
            "enforce_admins",
            "required_linear_history",
        ) and new_value is True:
            return (
                "low",
                f"Branch protection was strengthened: '{field_path}' enabled.",
            )
        if field_path in ("allow_force_pushes", "allow_deletions") and new_value is False:
            return (
                "low",
                f"Branch protection was strengthened: '{field_path}' disallowed.",
            )

        # Any other explicitly tracked field modification.
        return (
            "medium",
            f"Branch protection setting '{field_path}' changed to '{new_value}'.",
        )

    return (
        "low",
        "No specific risk pattern matched for this branch protection change.",
    )


def _classify_actions_secret(
    change_type: str,
    field_path: str,
    record_name: str,
) -> tuple[str, str]:
    """Rules for ``github_actions_secret`` records.

    Secret *values* are never available — only the name and the rotation
    signal (``last_updated_at`` changed) can be classified.  Name sensitivity
    is the primary differentiating signal within each change_type.
    """
    is_sensitive = _is_sensitive_secret(record_name)

    # ── HIGH ──────────────────────────────────────────────────────────────────

    # Sensitive secret deleted — dependent workflows will break.
    if change_type == "removed" and is_sensitive:
        return (
            "high",
            f"Actions secret '{record_name}' was deleted. This secret has a "
            "production-sensitive name — any workflow that references it will "
            "now fail.",
        )

    # Sensitive secret rotated — the credential was changed.
    if change_type == "modified" and field_path == "last_updated_at" and is_sensitive:
        return (
            "high",
            f"Actions secret '{record_name}' was rotated. This secret has a "
            "production-sensitive name — verify the new value is correct and "
            "that all dependent workflows continue to function.",
        )

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    # Non-sensitive secret deleted — workflows will break, but lower credential risk.
    if change_type == "removed":
        return (
            "medium",
            f"Actions secret '{record_name}' was deleted. Workflows that "
            "reference this secret will fail.",
        )

    # Non-sensitive secret rotated.
    if change_type == "modified" and field_path == "last_updated_at":
        return (
            "medium",
            f"Actions secret '{record_name}' was rotated. Verify the new value "
            "is correct and that dependent workflows continue to function.",
        )

    # Sensitive secret added — a production credential is now stored here.
    if change_type == "added" and is_sensitive:
        return (
            "medium",
            f"A new Actions secret '{record_name}' with a production-sensitive "
            "name was added. Review that this credential belongs in this "
            "repository and is properly scoped.",
        )

    # ── LOW ───────────────────────────────────────────────────────────────────

    # Non-sensitive secret added.
    if change_type == "added":
        return (
            "low",
            f"A new Actions secret '{record_name}' was added.",
        )

    return (
        "low",
        "No specific risk pattern matched for this Actions secret change.",
    )


def _classify_actions_variable(
    change_type: str,
    record_name: str,
    new_value: Any,
) -> tuple[str, str]:
    """Rules for ``github_actions_variable`` records.

    Variable values are not secrets — they are stored and can be compared.
    Name sensitivity and the direction of change are the primary signals.
    For modified records, *new_value* is the new field value (a string);
    for added records it is the full record dict (not used for name checks).
    """
    is_sensitive = _is_sensitive_secret(record_name)

    # ── HIGH ──────────────────────────────────────────────────────────────────

    # Sensitive variable modified — a production-critical value changed.
    if change_type == "modified" and is_sensitive:
        return (
            "high",
            f"Actions variable '{record_name}' was modified. This variable has "
            "a production-sensitive name — verify the change was intentional "
            "and that dependent workflows use the new value correctly.",
        )

    # Non-sensitive variable modified but new value looks like a production URL.
    if (
        change_type == "modified"
        and isinstance(new_value, str)
        and new_value.startswith(("http://", "https://"))
    ):
        return (
            "high",
            f"Actions variable '{record_name}' was changed to an external URL. "
            "Verify the new endpoint is correct and intentional.",
        )

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    # Sensitive variable added.
    if change_type == "added" and is_sensitive:
        return (
            "medium",
            f"A new Actions variable '{record_name}' with a production-sensitive "
            "name was added. Verify that this value is correct for this "
            "repository's environment.",
        )

    # Sensitive variable removed — dependent workflows may break or silently
    # use an unset value.
    if change_type == "removed" and is_sensitive:
        return (
            "medium",
            f"Actions variable '{record_name}' was removed. This variable has "
            "a production-sensitive name — workflows that reference it may fail "
            "or fall back to an unset value.",
        )

    # ── LOW ───────────────────────────────────────────────────────────────────

    # Non-sensitive variable removed.
    if change_type == "removed":
        return (
            "low",
            f"Actions variable '{record_name}' was removed. Verify that no "
            "workflows reference it.",
        )

    # Non-sensitive variable modified.
    if change_type == "modified":
        return (
            "low",
            f"Actions variable '{record_name}' value was updated. Verify that "
            "dependent workflows use the new value correctly.",
        )

    # Non-sensitive variable added.
    if change_type == "added":
        return (
            "low",
            f"A new Actions variable '{record_name}' was added.",
        )

    return ("low", "No specific risk pattern matched for this Actions variable change.")


def _classify_webhook(
    change_type: str,
    field_path: str,
    prev_value: Any,
    new_value: Any,
) -> tuple[str, str]:
    """Rules for ``github_webhook`` records.

    Delivery URL changes and webhook removal/disablement are High because they
    affect what system receives repository events.  Additions are Medium
    because they expand the event delivery surface.
    """

    # ── HIGH ──────────────────────────────────────────────────────────────────

    # Webhook deleted — receiving system stops getting events.
    if change_type == "removed":
        return (
            "high",
            "A repository webhook was deleted. Any system that relied on this "
            "webhook will stop receiving GitHub events immediately.",
        )

    # Delivery URL changed — per policy: any URL change is High.
    if change_type == "modified" and field_path == "url":
        return (
            "high",
            "The webhook delivery URL changed. GitHub events will now be sent "
            "to a different endpoint. Verify the new URL is legitimate and "
            "under your control.",
        )

    # Webhook disabled (active → False) — events stop being delivered.
    if change_type == "modified" and field_path == "active" and new_value is False:
        return (
            "high",
            "A repository webhook was disabled. Events will no longer be "
            "delivered to the configured URL until the webhook is re-enabled.",
        )

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    # Webhook added — a new delivery endpoint has been connected.
    if change_type == "added":
        return (
            "medium",
            "A new repository webhook was added. Verify that the delivery URL "
            "is expected and under your control.",
        )

    # Webhook re-enabled (active → True).
    if change_type == "modified" and field_path == "active" and new_value is True:
        return (
            "medium",
            "A repository webhook was re-enabled. Event delivery to the "
            "configured URL will resume.",
        )

    # Subscribed events changed — webhook now receives a different event set.
    if change_type == "modified" and field_path == "events":
        return (
            "medium",
            "Webhook event subscriptions changed. The webhook will now receive "
            "a different set of repository events.",
        )

    # ── LOW ───────────────────────────────────────────────────────────────────

    # Other webhook configuration changes (e.g. content_type).
    if change_type == "modified":
        return (
            "low",
            f"Webhook configuration field '{field_path}' changed.",
        )

    return ("low", "No specific risk pattern matched for this webhook change.")


def _classify_actions_permissions(
    change_type: str,
    field_path: str,
    prev_value: Any,
    new_value: Any,
) -> tuple[str, str]:
    """Rules for ``github_actions_permissions`` records."""

    # ── HIGH ──────────────────────────────────────────────────────────────────

    # Actions disabled — all workflow runs stop immediately.
    if change_type == "modified" and field_path == "enabled" and new_value is False:
        return (
            "high",
            "GitHub Actions has been disabled for this repository. All workflow "
            "runs will stop immediately until Actions is re-enabled.",
        )

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    # Actions re-enabled.
    if change_type == "modified" and field_path == "enabled" and new_value is True:
        return (
            "medium",
            "GitHub Actions has been re-enabled for this repository.",
        )

    # Allowed actions broadened to allow any action from any repository.
    if change_type == "modified" and field_path == "allowed_actions":
        if str(new_value).lower() == "all":
            return (
                "medium",
                "Actions permissions changed to 'all'. Any action from any "
                "repository or publisher can now run in workflows.",
            )
        return (
            "medium",
            f"Actions permission 'allowed_actions' changed from '{prev_value}' "
            f"to '{new_value}'.",
        )

    # ── LOW ───────────────────────────────────────────────────────────────────
    return ("low", "No specific risk pattern matched for this Actions permissions change.")


def _classify_deploy_key(
    change_type: str,
    field_path: str,
    prev_value: Any,
    new_value: Any,
) -> tuple[str, str]:
    """Rules for ``github_deploy_key`` records.

    For added keys the *new_value* full record dict is inspected to determine
    whether the key grants write access (``read_only=False``).
    """

    # ── CRITICAL ──────────────────────────────────────────────────────────────

    # Write-enabled deploy key added — key can push code.
    if change_type == "added":
        new_record = new_value if isinstance(new_value, dict) else {}
        read_only = new_record.get("read_only", True)  # default to read-only
        if read_only is False:
            return (
                "critical",
                "A write-enabled deploy key was added. This key can push code "
                "to the repository — verify it belongs to an authorised system "
                "and is properly managed.",
            )
        # Read-only key added — lower risk.
        return (
            "medium",
            "A new read-only deploy key was added. Verify that it belongs to "
            "an authorised system and will only be used for read access.",
        )

    # ── HIGH ──────────────────────────────────────────────────────────────────

    # Deploy key removed — automated systems using it lose access.
    if change_type == "removed":
        return (
            "high",
            "A deploy key was removed. Any automated system using this key for "
            "repository access will lose access immediately.",
        )

    # Key upgraded from read-only to read-write — gains push access.
    if (
        change_type == "modified"
        and field_path == "read_only"
        and new_value is False
    ):
        return (
            "high",
            "A deploy key changed from read-only to read-write. The key now "
            "has push access to the repository.",
        )

    # ── LOW ───────────────────────────────────────────────────────────────────

    # Other deploy key field changes (title, verified, etc.).
    if change_type == "modified":
        return (
            "low",
            f"Deploy key field '{field_path}' changed.",
        )

    return ("low", "No specific risk pattern matched for this deploy key change.")


def _classify_environment_protection(
    change_type: str,
    field_path: str,
    prev_value: Any,
    new_value: Any,
    record_name: str,
) -> tuple[str, str]:
    """Rules for ``github_environment_protection`` records — M57.9.

    Priority chain (first match wins):
    1. removed → high
    2. added   → low (new environment = new deployment target)
    3. reviewers_count decreased → high
    4. prevent_self_review disabled → medium
    5. reviewers_count increased → low
    6. wait_timer decreased/removed → medium
    7. wait_timer increased → low
    8. protected_branches → False / custom_branch_policies added → high
    9. other branch policy changes → medium
    10. other field changes → low
    """
    env_label = f"Environment '{record_name}'" if record_name else "A deployment environment"

    if change_type == "removed":
        return (
            "high",
            f"{env_label} was removed. Deployment protection rules for this "
            "environment no longer apply.",
        )

    if change_type == "added":
        return (
            "low",
            f"{env_label} was added as a new deployment environment. "
            "Review its protection rules.",
        )

    # reviewers_count decreased
    if field_path == "reviewers_count":
        try:
            old_count = int(prev_value or 0)
            new_count = int(new_value or 0)
        except (ValueError, TypeError):
            old_count, new_count = 0, 0
        if new_count < old_count:
            return (
                "high",
                f"{env_label} required reviewers decreased from {old_count} "
                f"to {new_count}. Production deployment approval may now require "
                "fewer reviewers.",
            )
        if new_count > old_count:
            return (
                "low",
                f"{env_label} required reviewers increased from {old_count} "
                f"to {new_count}.",
            )

    # prevent_self_review disabled
    if field_path == "prevent_self_review" and new_value is False and prev_value is True:
        return (
            "medium",
            f"{env_label} no longer prevents self-review. The actor who triggers "
            "a deployment could now approve it.",
        )

    # prevent_self_review enabled
    if field_path == "prevent_self_review" and new_value is True:
        return (
            "low",
            f"{env_label} now requires that a different person approves deployments.",
        )

    # wait_timer changed
    if field_path == "wait_timer":
        try:
            old_t = int(prev_value or 0)
            new_t = int(new_value or 0)
        except (ValueError, TypeError):
            old_t, new_t = 0, 0
        if new_t < old_t:
            return (
                "medium",
                f"{env_label} wait timer decreased from {old_t} to {new_t} minutes. "
                "Deployments may proceed sooner than before.",
            )
        return (
            "low",
            f"{env_label} wait timer changed from {old_t} to {new_t} minutes.",
        )

    # Branch policy weakened
    if field_path == "protected_branches" and new_value is False and prev_value is True:
        return (
            "high",
            f"{env_label} no longer restricts deployments to protected branches. "
            "Unprotected branches may now trigger deployments.",
        )

    if field_path in ("protected_branches", "custom_branch_policies"):
        return (
            "medium",
            f"{env_label} deployment branch policy changed (field: {field_path}).",
        )

    return (
        "low",
        f"{env_label} protection setting '{field_path}' changed.",
    )
