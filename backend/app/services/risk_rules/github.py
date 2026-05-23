"""GitHub repository configuration risk rules — Milestone 26.

Classifies a Change (ORM object or plain dict) that originated from a GitHub
integration into one of four risk levels:
    critical  — changes that can expose data or destroy irreplaceable history
    high      — changes likely to disrupt workflows or introduce security risk
    medium    — changes that alter behaviour but are generally reversible
    low       — cosmetic or low-impact changes

Design decisions
----------------
* ``classify_github_change`` accepts both ORM ``Change`` objects and plain
  dicts — the same ``_get`` helper used in the Cloudflare rule set.
* All seven GitHub record types are handled with explicit rule tables.
* Secret-rotation sensitivity is determined by a case-insensitive substring
  check against a curated list of sensitive name patterns.
* Rule order within each block is most-severe → least-severe (first match
  short-circuits the remaining checks).
* The final ``return ("low", "…")`` is the universal catch-all.
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
# Sensitive secret name patterns
# ─────────────────────────────────────────────────────────────────────────────

#: Substrings that, when found in a secret name, escalate the rotation risk
#: from Medium to High.  Matched case-insensitively.
_SENSITIVE_PATTERNS: tuple[str, ...] = (
    "PROD",
    "DATABASE",
    "TOKEN",
    "SECRET",
    "STRIPE",
    "CLOUDFLARE",
    "AWS",
    "VERCEL",
    "API_KEY",
    "PRIVATE_KEY",
    "KEY",
)

# Pre-compile a single OR-pattern for O(1) matching per check.
_SENSITIVE_RE = re.compile(
    "|".join(re.escape(p) for p in _SENSITIVE_PATTERNS),
    re.IGNORECASE,
)


def _is_sensitive_secret(name: str) -> bool:
    """Return ``True`` if *name* contains any sensitive substring."""
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

    # ── Dispatch by record type ───────────────────────────────────────────────
    if record_type == "github_repo_settings":
        return _classify_repo_settings(change_type, field_path, prev_value, new_value)

    if record_type == "github_branch_protection":
        return _classify_branch_protection(change_type, field_path, prev_value, new_value)

    if record_type == "github_actions_secret":
        return _classify_actions_secret(change_type, field_path, record_name)

    if record_type == "github_actions_variable":
        return _classify_actions_variable(change_type)

    if record_type == "github_webhook":
        return _classify_webhook(change_type, field_path)

    if record_type == "github_actions_permissions":
        return _classify_actions_permissions(change_type, field_path, prev_value, new_value)

    if record_type == "github_deploy_key":
        return _classify_deploy_key(change_type, field_path, prev_value, new_value)

    # Unknown GitHub record type — safe fallback.
    return (
        "low",
        "No specific GitHub risk pattern matched. This change may be routine "
        "configuration maintenance.",
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
    """Rules for ``github_repo_settings`` records."""

    # ── CRITICAL ──────────────────────────────────────────────────────────────

    # Repository made public — exposes all code, issues, and history.
    if (
        change_type == "modified"
        and field_path == "visibility"
        and str(new_value).lower() == "public"
    ):
        return (
            "critical",
            "Repository visibility changed to public. All code, issues, and "
            "history are now accessible to anyone on the internet.",
        )

    # ── HIGH ──────────────────────────────────────────────────────────────────

    # Repository archived — becomes read-only; all write operations blocked.
    if change_type == "modified" and field_path == "archived" and new_value is True:
        return (
            "high",
            "Repository archived. All write operations (pushes, issue creation, "
            "pull requests) are now blocked.",
        )

    # Default branch changed — affects where all CI/CD pipelines and integrations point.
    if change_type == "modified" and field_path == "default_branch":
        return (
            "high",
            f"Default branch changed from '{prev_value}' to '{new_value}'. "
            "CI/CD pipelines, integrations, and branch policies that reference "
            "the default branch may be affected.",
        )

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    # Repository made private — visibility reduced (generally safer, but notable).
    if (
        change_type == "modified"
        and field_path == "visibility"
        and str(new_value).lower() == "private"
    ):
        return (
            "medium",
            "Repository visibility changed to private. Public access is removed; "
            "verify that all collaborators still have the required access.",
        )

    # Merge strategy changed.
    if change_type == "modified" and field_path in (
        "allow_merge_commit",
        "allow_squash_merge",
        "allow_rebase_merge",
        "delete_branch_on_merge",
    ):
        return (
            "medium",
            f"Repository merge setting '{field_path}' changed to '{new_value}'. "
            "Pull request merge behaviour is affected.",
        )

    # Other settings changes.
    if change_type == "modified":
        return (
            "medium",
            f"Repository setting '{field_path}' changed from '{prev_value}' "
            f"to '{new_value}'.",
        )

    # ── LOW ───────────────────────────────────────────────────────────────────
    return (
        "low",
        "No specific risk pattern matched for this repository settings change.",
    )


def _classify_branch_protection(
    change_type: str,
    field_path: str,
    prev_value: Any,
    new_value: Any,
) -> tuple[str, str]:
    """Rules for ``github_branch_protection`` records."""

    # ── CRITICAL ──────────────────────────────────────────────────────────────

    # Branch protection removed entirely.
    if change_type == "modified" and field_path == "protection_enabled" and new_value is False:
        return (
            "critical",
            "Branch protection has been removed. The branch is now unprotected — "
            "anyone with write access can force-push or delete it.",
        )

    # Branch protection added/removed as a whole record.
    if change_type == "removed":
        return (
            "critical",
            "Branch protection rule deleted. The branch is now unprotected.",
        )

    # ── HIGH ──────────────────────────────────────────────────────────────────

    # Force-pushes now allowed — can rewrite history.
    if (
        change_type == "modified"
        and field_path == "allow_force_pushes"
        and new_value is True
    ):
        return (
            "high",
            "Force-pushes are now allowed on this branch. History can be "
            "rewritten, which may silently discard commits.",
        )

    # Branch deletion now allowed.
    if (
        change_type == "modified"
        and field_path == "allow_deletions"
        and new_value is True
    ):
        return (
            "high",
            "Branch deletion is now allowed. The protected branch can be deleted "
            "by anyone with write access.",
        )

    # PR review requirement removed.
    if (
        change_type == "modified"
        and field_path == "required_pull_request_reviews_enabled"
        and new_value is False
    ):
        return (
            "high",
            "Required pull request reviews have been disabled. Changes can now "
            "be merged without peer review.",
        )

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    # Admin enforcement removed — admins can now bypass protection rules.
    if (
        change_type == "modified"
        and field_path == "enforce_admins"
        and new_value is False
    ):
        return (
            "medium",
            "Branch protection rules are no longer enforced for administrators. "
            "Admins can now bypass review and status-check requirements.",
        )

    # Required approvals count reduced.
    if change_type == "modified" and field_path == "required_approving_review_count":
        if (
            isinstance(prev_value, (int, float))
            and isinstance(new_value, (int, float))
            and new_value < prev_value
        ):
            return (
                "medium",
                f"Required approving review count reduced from {prev_value} "
                f"to {new_value}. Fewer reviewers are needed before merging.",
            )

    # Protection just added.
    if change_type == "added":
        return (
            "low",
            "Branch protection rule added. The branch is now protected.",
        )

    # Protection enabled.
    if (
        change_type == "modified"
        and field_path == "protection_enabled"
        and new_value is True
    ):
        return (
            "low",
            "Branch protection has been enabled on this branch.",
        )

    # Other protection changes.
    if change_type == "modified":
        return (
            "medium",
            f"Branch protection setting '{field_path}' changed to '{new_value}'.",
        )

    # ── LOW ───────────────────────────────────────────────────────────────────
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

    Secret values are never available — only the name and the rotation signal
    (``last_updated_at`` changed) can be classified.
    """

    # ── HIGH ──────────────────────────────────────────────────────────────────

    # Secret deleted — workflows that depend on it will fail.
    if change_type == "removed":
        if _is_sensitive_secret(record_name):
            return (
                "high",
                f"Sensitive Actions secret '{record_name}' was deleted. "
                "Workflows that reference this secret will fail.",
            )
        return (
            "high",
            f"Actions secret '{record_name}' was deleted. "
            "Workflows that reference this secret will fail.",
        )

    # Secret rotated — elevated risk when the name matches a sensitive pattern.
    if change_type == "modified" and field_path == "last_updated_at":
        if _is_sensitive_secret(record_name):
            return (
                "high",
                f"Sensitive secret '{record_name}' was rotated (updated_at changed). "
                "Verify the new value is correct and that dependent workflows "
                "continue to function.",
            )
        return (
            "medium",
            f"Actions secret '{record_name}' was rotated (updated_at changed). "
            "Verify the new value is correct and that dependent workflows "
            "continue to function.",
        )

    # ── LOW ───────────────────────────────────────────────────────────────────

    # Secret added.
    if change_type == "added":
        return (
            "low",
            f"New Actions secret '{record_name}' was added.",
        )

    return (
        "low",
        "No specific risk pattern matched for this Actions secret change.",
    )


def _classify_actions_variable(change_type: str) -> tuple[str, str]:
    """Rules for ``github_actions_variable`` records.

    Variables are not secrets; their values are stored and can be compared.
    """
    if change_type == "removed":
        return (
            "medium",
            "An Actions variable was removed. Workflows referencing it may fail "
            "or silently use an unset value.",
        )
    if change_type == "modified":
        return (
            "low",
            "An Actions variable value was changed. Verify that dependent "
            "workflows use the new value correctly.",
        )
    if change_type == "added":
        return (
            "low",
            "A new Actions variable was added.",
        )
    return ("low", "No specific risk pattern matched for this Actions variable change.")


def _classify_webhook(change_type: str, field_path: str) -> tuple[str, str]:
    """Rules for ``github_webhook`` records."""

    # ── HIGH ──────────────────────────────────────────────────────────────────

    # Webhook deleted.
    if change_type == "removed":
        return (
            "high",
            "A repository webhook was deleted. Any systems or services that "
            "relied on this webhook will stop receiving events.",
        )

    # Webhook URL changed — per policy: any URL change = High risk.
    if change_type == "modified" and field_path == "url":
        return (
            "high",
            "Webhook delivery URL changed. Events will now be sent to the new "
            "URL. Verify the endpoint is legitimate and under your control.",
        )

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    # Webhook added.
    if change_type == "added":
        return (
            "medium",
            "A new repository webhook was added. Verify that the delivery URL "
            "is expected and under your control.",
        )

    # Webhook deactivated.
    if change_type == "modified" and field_path == "active":
        return (
            "medium",
            "Webhook active status changed. Review whether the change was "
            "intentional.",
        )

    # Subscribed events changed.
    if change_type == "modified" and field_path == "events":
        return (
            "medium",
            "Webhook event subscriptions changed. The webhook will now receive "
            "a different set of events.",
        )

    # ── LOW ───────────────────────────────────────────────────────────────────
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

    # Actions disabled entirely.
    if change_type == "modified" and field_path == "enabled" and new_value is False:
        return (
            "high",
            "GitHub Actions has been disabled for this repository. All workflow "
            "runs will stop immediately.",
        )

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    # Actions re-enabled.
    if change_type == "modified" and field_path == "enabled" and new_value is True:
        return (
            "medium",
            "GitHub Actions has been re-enabled for this repository.",
        )

    # Allowed actions broadened (e.g. from 'selected' to 'all').
    if change_type == "modified" and field_path == "allowed_actions":
        if str(new_value).lower() == "all":
            return (
                "medium",
                "Actions permissions changed to 'all' — any action from any "
                "repository can now run in workflows.",
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
    """Rules for ``github_deploy_key`` records."""

    # ── HIGH ──────────────────────────────────────────────────────────────────

    # Read-only changed to False — key now has write access.
    if (
        change_type == "modified"
        and field_path == "read_only"
        and new_value is False
    ):
        return (
            "high",
            "Deploy key changed from read-only to read-write. The key now has "
            "push access to the repository.",
        )

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    # Key removed.
    if change_type == "removed":
        return (
            "medium",
            "A deploy key was removed. Any system using this key for automated "
            "access will lose access immediately.",
        )

    # Key added.
    if change_type == "added":
        return (
            "low",
            "A new deploy key was added. Verify that it belongs to an authorised "
            "system and is scoped appropriately.",
        )

    # Other changes.
    if change_type == "modified":
        return (
            "low",
            f"Deploy key field '{field_path}' changed.",
        )

    return ("low", "No specific risk pattern matched for this deploy key change.")
