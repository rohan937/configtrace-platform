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
    raw_pm = _get(change, "provider_metadata")
    pm: dict[str, Any] = raw_pm if isinstance(raw_pm, dict) else {}
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

    # ── M59.6 — Additional GitHub surfaces ────────────────────────────────────
    if record_type == "github_ruleset":
        return _classify_ruleset(pm, change_type, field_path, prev_value, new_value)
    if record_type == "github_codeowners":
        return _classify_codeowners(pm, change_type, field_path, prev_value, new_value)
    if record_type == "github_workflow_file":
        return _classify_workflow_file(pm, change_type, field_path, prev_value, new_value)
    if record_type == "github_oidc_trust":
        return _classify_oidc_trust(pm, change_type, field_path, prev_value, new_value)
    if record_type == "github_collaborator":
        return _classify_collaborator(pm, change_type, field_path, prev_value, new_value)
    if record_type == "github_app_installation":
        return _classify_app_installation(pm, change_type, field_path, prev_value, new_value)
    if record_type == "github_security_features":
        return _classify_security_features(pm, change_type, field_path, prev_value, new_value)

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

    # Stale review dismissal disabled — old approvals survive new commits,
    # which lets a previously-approved PR be amended with new code that no
    # reviewer has seen and merged on the strength of the stale approval.
    if (
        change_type == "modified"
        and field_path == "dismiss_stale_reviews"
        and new_value is False
    ):
        return (
            "high",
            "Dismissal of stale reviews was disabled. Approvals granted before "
            "new commits are pushed will no longer be automatically revoked, "
            "which may allow unreviewed code to be merged under a prior approval.",
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

    # NOTE: dismiss_stale_reviews disabled handled in HIGH section above.

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

    # Delivery URL changed — escalate to Critical if the new scheme is plain
    # HTTP (events including payloads and HMAC headers would traverse the
    # network in cleartext); otherwise High.
    if change_type == "modified" and field_path == "url":
        new_url_lower = str(new_value or "").lower()
        if new_url_lower.startswith("http://"):
            return (
                "critical",
                "The webhook delivery URL changed to a plain http:// endpoint. "
                "GitHub event payloads and signature headers would be sent in "
                "cleartext, which may allow interception or tampering. Use "
                "https:// and verify the destination is under your control.",
            )
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

    # SSL verification disabled for webhook deliveries — this weakens
    # transport verification for events sent to the endpoint.
    if change_type == "modified" and field_path == "insecure_ssl_enabled" and new_value is True:
        return (
            "high",
            "Webhook SSL verification is disabled. This weakens delivery "
            "transport verification and may require review. Configuration "
            "evidence does not confirm compromise, unauthorized access, or "
            "data exposure.",
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

    # SSL verification restored (insecure_ssl_enabled True → False).
    if change_type == "modified" and field_path == "insecure_ssl_enabled" and new_value is False:
        return (
            "medium",
            "Webhook SSL verification was re-enabled. Delivery transport "
            "verification is restored for this webhook.",
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


# ═════════════════════════════════════════════════════════════════════════════
# M59.6 — Sub-classifiers for new GitHub surfaces
# ═════════════════════════════════════════════════════════════════════════════


def _str(v: Any) -> str:
    return str(v) if v is not None else ""


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    s = _str(v).strip().lower()
    return s in ("true", "1", "on", "yes")


# ─────────────────────────────────────────────────────────────────────────────
# A. github_ruleset
# ─────────────────────────────────────────────────────────────────────────────


def _classify_ruleset(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    name = _str(pm.get("name") or pm.get("record_id"))
    targets_prot = bool(pm.get("targets_protected_branch", False))

    # Removed / added.
    if change_type == "removed":
        sev = "critical" if targets_prot else "high"
        return (
            sev,
            f"Ruleset '{name}' was removed.  Branches/tags that were covered "
            "by this ruleset are no longer enforced — this may weaken "
            "production release gates and code-review controls.",
        )

    if change_type == "added":
        return (
            "low",
            f"A new ruleset '{name}' was added.  Verify the branch/tag "
            "patterns and bypass actors match your team's policy.",
        )

    # Enforcement toggled.
    if change_type == "modified" and field_path == "enforcement":
        prev_s = _str(prev_value).lower()
        new_s = _str(new_value).lower()
        if prev_s == "active" and new_s == "disabled":
            sev = "critical" if targets_prot else "high"
            return (
                sev,
                f"Ruleset '{name}' was disabled.  Branch/tag protections that "
                "were previously enforced no longer apply.",
            )
        if prev_s == "active" and new_s == "evaluate":
            return (
                "high",
                f"Ruleset '{name}' was moved to 'evaluate' mode — violations "
                "are logged but no longer block merges/pushes.",
            )
        if new_s == "active":
            return (
                "low",
                f"Ruleset '{name}' enforcement was enabled.",
            )

    # Bypass actors.
    if change_type == "modified" and field_path == "bypass_actor_count":
        prev_n = _to_int(prev_value)
        new_n = _to_int(new_value)
        if new_n > prev_n:
            sev = "critical" if targets_prot else "high"
            return (
                sev,
                f"Ruleset '{name}' bypass-actor count increased from {prev_n} "
                f"to {new_n}.  More actors can now bypass branch/tag "
                "protections — verify each bypass actor is intentional.",
            )
        if new_n < prev_n:
            return (
                "low",
                f"Ruleset '{name}' bypass-actor count decreased from {prev_n} "
                f"to {new_n}.",
            )

    # Required status checks.
    if change_type == "modified" and field_path == "required_status_checks_count":
        prev_n = _to_int(prev_value)
        new_n = _to_int(new_value)
        if new_n < prev_n:
            return (
                "high",
                f"Ruleset '{name}' required-status-check count was lowered "
                f"from {prev_n} to {new_n}.  Fewer CI checks must pass before "
                "merge, which may weaken release gates.",
            )
        return (
            "low",
            f"Ruleset '{name}' required-status-check count increased from "
            f"{prev_n} to {new_n}.",
        )

    # Required PR reviews toggled.
    if change_type == "modified" and field_path == "required_pr_reviews_required":
        if _to_bool(new_value) is False:
            return (
                "high",
                f"Ruleset '{name}' no longer requires pull request reviews. "
                "Changes can be merged without peer approval.",
            )
        return (
            "low",
            f"Ruleset '{name}' now requires pull request reviews.",
        )

    # Force pushes / deletions allowed.
    if change_type == "modified" and field_path == "restrict_force_pushes":
        if _to_bool(new_value) is False:
            sev = "critical" if targets_prot else "high"
            return (
                sev,
                f"Ruleset '{name}' no longer restricts force-pushes.  History "
                "rewrites are now permitted on covered branches.",
            )
        return (
            "low",
            f"Ruleset '{name}' now restricts force-pushes.",
        )

    if change_type == "modified" and field_path == "restrict_deletions":
        if _to_bool(new_value) is False:
            sev = "critical" if targets_prot else "high"
            return (
                sev,
                f"Ruleset '{name}' no longer restricts deletions.  Covered "
                "branches/tags can now be deleted.",
            )
        return (
            "low",
            f"Ruleset '{name}' now restricts deletions.",
        )

    # Branch patterns broadened.
    if change_type == "modified" and field_path == "branch_patterns_count":
        prev_n = _to_int(prev_value)
        new_n = _to_int(new_value)
        if new_n > prev_n:
            return (
                "medium",
                f"Ruleset '{name}' branch-pattern count increased from "
                f"{prev_n} to {new_n}.  Verify the new patterns are intentional.",
            )

    # Signed commits.
    if change_type == "modified" and field_path == "require_signed_commits":
        if _to_bool(new_value) is False:
            return (
                "high",
                f"Ruleset '{name}' no longer requires signed commits.",
            )
        return ("low", f"Ruleset '{name}' now requires signed commits.")

    return (
        "low",
        f"Ruleset '{name}' configuration changed; no specific risk pattern "
        "matched.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# B. github_codeowners
# ─────────────────────────────────────────────────────────────────────────────


# Critical-path labels we expect to see covered by CODEOWNERS rules.
_CRITICAL_CODEOWNER_PATHS: tuple[str, ...] = (
    "workflows", "infra", "terraform", "auth", "billing", "security", "config",
)


def _classify_codeowners(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    if change_type == "removed":
        return (
            "high",
            "The CODEOWNERS file was removed.  Pull requests that touched "
            "sensitive paths no longer require designated reviewers — this "
            "may weaken security and production review gates.",
        )

    if change_type == "added":
        return (
            "low",
            "A CODEOWNERS file was added.  Designated reviewers now apply to "
            "matching paths.",
        )

    # exists toggled.
    if change_type == "modified" and field_path == "exists":
        if _to_bool(new_value) is False:
            return (
                "high",
                "CODEOWNERS was effectively removed (exists=False).  Critical "
                "paths may no longer have designated reviewers.",
            )
        return (
            "low",
            "CODEOWNERS is now present.  Designated reviewers apply.",
        )

    # critical_paths_with_owners — most security-relevant signal.
    if change_type == "modified" and field_path == "critical_paths_with_owners":
        prev_d = prev_value if isinstance(prev_value, dict) else {}
        new_d = new_value if isinstance(new_value, dict) else {}
        lost: list[str] = []
        for path in _CRITICAL_CODEOWNER_PATHS:
            if bool(prev_d.get(path, False)) and not bool(new_d.get(path, False)):
                lost.append(path)
        if lost:
            return (
                "high",
                "CODEOWNERS lost coverage for critical paths "
                f"({', '.join(sorted(lost))}).  Changes to those paths may "
                "merge without the previously-designated reviewers.",
            )
        # Coverage added?
        gained: list[str] = []
        for path in _CRITICAL_CODEOWNER_PATHS:
            if not bool(prev_d.get(path, False)) and bool(new_d.get(path, False)):
                gained.append(path)
        if gained:
            return (
                "low",
                "CODEOWNERS now covers additional critical paths "
                f"({', '.join(sorted(gained))}).",
            )
        return ("medium", "CODEOWNERS critical-path coverage map was modified.")

    if change_type == "modified" and field_path == "wildcard_owner_present":
        if _to_bool(new_value) is False:
            return (
                "medium",
                "CODEOWNERS no longer has a wildcard owner.  PRs that don't "
                "match any specific rule will fall through to the default "
                "review process.",
            )
        return (
            "low",
            "CODEOWNERS now has a wildcard owner.",
        )

    if change_type == "modified" and field_path == "content_hash":
        return (
            "medium",
            "CODEOWNERS content changed.  Review the diff to confirm "
            "designated reviewers for sensitive paths are still correct.",
        )

    if change_type == "modified" and field_path == "rule_count":
        prev_n = _to_int(prev_value)
        new_n = _to_int(new_value)
        if new_n < prev_n:
            return (
                "medium",
                f"CODEOWNERS rule count decreased from {prev_n} to {new_n} — "
                "some path patterns may no longer have designated reviewers.",
            )
        return (
            "low",
            f"CODEOWNERS rule count increased from {prev_n} to {new_n}.",
        )

    return ("low", "CODEOWNERS metadata changed; no specific risk pattern matched.")


# ─────────────────────────────────────────────────────────────────────────────
# C. github_workflow_file
# ─────────────────────────────────────────────────────────────────────────────


def _classify_workflow_file(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    path = _str(pm.get("path") or pm.get("record_id"))
    is_deploy = bool(pm.get("is_deploy_workflow", False))

    if change_type == "added":
        # New workflow — review pull_request_target / permissions.
        if bool(pm.get("has_pull_request_target")):
            return (
                "high",
                f"A new workflow '{path}' was added that uses "
                "'pull_request_target'.  This trigger runs with secrets in "
                "the context of the base repository — verify it does not "
                "check out untrusted code from forks.",
            )
        return (
            "medium",
            f"A new workflow '{path}' was added.  Review its permissions "
            "and triggers.",
        )

    if change_type == "removed":
        sev = "high" if is_deploy else "medium"
        return (
            sev,
            f"Workflow '{path}' was removed.  Any automation it provided "
            "(including deploy or required-check jobs) no longer runs.",
        )

    if change_type == "modified" and field_path == "permissions_summary":
        new_s = _str(new_value).lower()
        prev_s = _str(prev_value).lower()
        if "write-all" in new_s and "write-all" not in prev_s:
            sev = "critical" if is_deploy else "high"
            return (
                sev,
                f"Workflow '{path}' permissions were broadened to 'write-all'. "
                "Jobs in this workflow can now modify any repository resource — "
                "this may allow privilege escalation.",
            )
        # contents/write or actions/write newly added.
        if ("contents:write" in new_s and "contents:write" not in prev_s) or \
           ("actions:write" in new_s and "actions:write" not in prev_s):
            sev = "critical" if is_deploy else "high"
            return (
                sev,
                f"Workflow '{path}' gained write access "
                "(contents:write or actions:write).  Verify the new permission "
                "is required and not exposed to untrusted triggers.",
            )
        # Tightened.
        if "write-all" in prev_s and "write-all" not in new_s:
            return (
                "low",
                f"Workflow '{path}' permissions tightened away from 'write-all'.",
            )
        return (
            "medium",
            f"Workflow '{path}' permissions changed.  Review the new scope.",
        )

    if change_type == "modified" and field_path == "has_pull_request_target":
        if _to_bool(new_value) and not _to_bool(prev_value):
            return (
                "high",
                f"Workflow '{path}' now uses 'pull_request_target'.  This "
                "trigger runs with secrets in the context of the base "
                "repository — verify it does not check out untrusted code.",
            )
        return (
            "low",
            f"Workflow '{path}' no longer uses 'pull_request_target'.",
        )

    if change_type == "modified" and field_path == "enabled":
        if _to_bool(new_value) is False:
            sev = "high" if is_deploy else "medium"
            return (
                sev,
                f"Workflow '{path}' was disabled.  The jobs it defines no "
                "longer run.",
            )
        return (
            "low",
            f"Workflow '{path}' was re-enabled.",
        )

    if change_type == "modified" and field_path == "content_hash":
        sev = "high" if is_deploy else "medium"
        return (
            sev,
            f"Workflow '{path}' content changed.  Review the diff to verify "
            "no risky steps (write permissions, untrusted checkout, broadened "
            "triggers) were introduced.",
        )

    if change_type == "modified" and field_path == "triggers_summary":
        new_s = _str(new_value).lower()
        if "pull_request_target" in new_s:
            return (
                "high",
                f"Workflow '{path}' triggers now include 'pull_request_target'. "
                "Verify the workflow does not check out untrusted code.",
            )
        if "schedule" in new_s and "schedule" not in _str(prev_value).lower():
            return (
                "medium",
                f"Workflow '{path}' now runs on a schedule.  Verify the cron "
                "expression and permission scope.",
            )
        return (
            "medium",
            f"Workflow '{path}' trigger summary changed.",
        )

    if change_type == "modified" and field_path == "secret_reference_count":
        prev_n = _to_int(prev_value)
        new_n = _to_int(new_value)
        if new_n > prev_n:
            return (
                "medium",
                f"Workflow '{path}' references {new_n} secrets (was {prev_n}). "
                "Verify each new secret reference is restricted to trusted "
                "branches/environments.",
            )

    return (
        "low",
        f"Workflow '{path}' metadata changed; no specific risk pattern matched.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# D. github_oidc_trust
# ─────────────────────────────────────────────────────────────────────────────


def _classify_oidc_trust(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    cloud = _str(pm.get("cloud_provider", "cloud")).lower() or "cloud"
    aud = _str(pm.get("audience"))

    if change_type == "removed":
        return (
            "medium",
            f"An OIDC trust binding for {cloud} was removed.  Workflows that "
            "relied on it will no longer be able to assume the bound role.",
        )

    if change_type == "added":
        return (
            "medium",
            f"A new OIDC trust binding for {cloud} was added (audience "
            f"'{aud or 'unknown'}').  Verify the subject pattern restricts "
            "to the exact repo/branch/environment.",
        )

    # Wildcards broaden trust.
    if change_type == "modified" and field_path == "repo_wildcard":
        if _to_bool(new_value):
            return (
                "critical",
                f"OIDC trust for {cloud} was broadened to a repository "
                "wildcard.  Any workflow run in matching repos can now "
                "assume the bound role — restrict the sub claim to an "
                "exact repository.",
            )
        return (
            "low",
            f"OIDC trust for {cloud} repository pattern was narrowed.",
        )

    if change_type == "modified" and field_path == "branch_wildcard":
        if _to_bool(new_value):
            return (
                "high",
                f"OIDC trust for {cloud} was broadened to a branch wildcard. "
                "Workflows on any branch can now assume the role — restrict "
                "the sub claim to specific branches or environments.",
            )
        return ("low", f"OIDC trust for {cloud} branch pattern was narrowed.")

    if change_type == "modified" and field_path == "org_wildcard":
        if _to_bool(new_value):
            return (
                "critical",
                f"OIDC trust for {cloud} was broadened to an organisation "
                "wildcard.  Any repo in the org can now assume the role.",
            )

    if change_type == "modified" and field_path == "environment_restricted":
        if _to_bool(new_value) is False:
            return (
                "high",
                f"OIDC trust for {cloud} no longer restricts to a deploy "
                "environment.  Workflows outside protected environments "
                "may now assume the role.",
            )
        return (
            "low",
            f"OIDC trust for {cloud} is now restricted to an environment.",
        )

    if change_type == "modified" and field_path == "audience":
        return (
            "medium",
            f"OIDC audience for {cloud} changed.  Verify the new audience "
            "matches the cloud-side configuration.",
        )

    if change_type == "modified" and field_path == "repo_pattern":
        return (
            "medium",
            f"OIDC subject pattern for {cloud} changed.  Verify the new "
            "pattern still pins to the intended repo/branch/environment.",
        )

    return (
        "low",
        f"OIDC trust binding for {cloud} changed; no specific risk pattern "
        "matched.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# E. github_collaborator
# ─────────────────────────────────────────────────────────────────────────────


_PERMISSION_RANK: dict[str, int] = {
    "read": 1, "triage": 2, "write": 3, "maintain": 4, "admin": 5,
}


def _classify_collaborator(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    actor = _str(pm.get("actor_login") or pm.get("record_id"))
    actor_type = _str(pm.get("actor_type", "user"))
    outside = bool(pm.get("is_outside_collaborator", False))
    actor_label = f"{actor_type} '{actor}'"

    if change_type == "added":
        perm = _str(pm.get("permission") or new_value).lower()
        if perm == "admin":
            sev = "critical" if outside else "high"
            return (
                sev,
                f"Outside-collaborator {actor_label} was added with 'admin' "
                "permission." if outside else
                f"{actor_label} was added with 'admin' permission.  Verify "
                "the grant was approved and remove if unnecessary.",
            )
        if perm in ("write", "maintain"):
            sev = "high" if outside else "medium"
            return (
                sev,
                f"{actor_label} was added with '{perm}' permission"
                f"{' (outside collaborator)' if outside else ''}. "
                "Verify the grant was approved.",
            )
        return (
            "low",
            f"{actor_label} was added with '{perm}' permission.",
        )

    if change_type == "removed":
        return (
            "medium",
            f"{actor_label} was removed.  Verify the change was intentional — "
            "removing a code-owning team can affect availability and review.",
        )

    if change_type == "modified" and field_path == "permission":
        prev_s = _str(prev_value).lower()
        new_s = _str(new_value).lower()
        prev_r = _PERMISSION_RANK.get(prev_s, 0)
        new_r = _PERMISSION_RANK.get(new_s, 0)
        if new_r > prev_r and new_s == "admin":
            sev = "critical" if outside else "high"
            return (
                sev,
                f"{actor_label} permission was raised from '{prev_s}' to "
                f"'admin'{' (outside collaborator)' if outside else ''}. "
                "This grants full repository control — verify the grant "
                "was approved.",
            )
        if new_r > prev_r and new_s in ("write", "maintain"):
            sev = "high" if outside else "medium"
            return (
                sev,
                f"{actor_label} permission was raised from '{prev_s}' to "
                f"'{new_s}'.  Verify the grant was approved.",
            )
        if new_r < prev_r:
            return (
                "low",
                f"{actor_label} permission was lowered from '{prev_s}' to "
                f"'{new_s}'.",
            )

    if change_type == "modified" and field_path == "is_outside_collaborator":
        if _to_bool(new_value):
            return (
                "high",
                f"{actor_label} was reclassified as an outside collaborator.  "
                "Review whether their current permission level is still "
                "appropriate.",
            )

    return (
        "low",
        f"{actor_label} metadata changed; no specific risk pattern matched.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# F. github_app_installation
# ─────────────────────────────────────────────────────────────────────────────


def _classify_app_installation(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    slug = _str(pm.get("app_slug") or pm.get("record_id"))

    if change_type == "added":
        # Installation just landed — review permissions.
        if bool(pm.get("has_admin_access")):
            return (
                "critical",
                f"GitHub App '{slug}' was installed with administration "
                "access.  Verify the app is trusted and reduce to least "
                "privilege if appropriate.",
            )
        if bool(pm.get("has_secrets_access")) or bool(pm.get("has_contents_write")):
            return (
                "high",
                f"GitHub App '{slug}' was installed with elevated permissions "
                "(secrets / contents:write).  Verify the app is trusted.",
            )
        return (
            "medium",
            f"GitHub App '{slug}' was installed.  Review its permissions and "
            "repository selection.",
        )

    if change_type == "removed":
        return (
            "medium",
            f"GitHub App '{slug}' was removed.  Any automation it provided "
            "no longer runs.",
        )

    if change_type == "modified" and field_path == "has_admin_access":
        if _to_bool(new_value) and not _to_bool(prev_value):
            return (
                "critical",
                f"GitHub App '{slug}' was granted administration access. "
                "Verify the grant was approved and reduce permissions if "
                "unnecessary.",
            )
        return (
            "low",
            f"GitHub App '{slug}' administration access was removed.",
        )

    if change_type == "modified" and field_path == "has_secrets_access":
        if _to_bool(new_value) and not _to_bool(prev_value):
            return (
                "high",
                f"GitHub App '{slug}' was granted access to repository secrets. "
                "Verify the grant was approved.",
            )
        return (
            "low",
            f"GitHub App '{slug}' lost access to repository secrets.",
        )

    if change_type == "modified" and field_path == "has_contents_write":
        if _to_bool(new_value) and not _to_bool(prev_value):
            return (
                "high",
                f"GitHub App '{slug}' was granted contents:write.  The app "
                "can now modify repository code.",
            )

    if change_type == "modified" and field_path == "has_workflows_write":
        if _to_bool(new_value) and not _to_bool(prev_value):
            return (
                "high",
                f"GitHub App '{slug}' was granted workflows:write.  The app "
                "can now modify workflow files.",
            )

    if change_type == "modified" and field_path == "repository_selection":
        prev_s = _str(prev_value).lower()
        new_s = _str(new_value).lower()
        if prev_s == "selected" and new_s == "all":
            return (
                "high",
                f"GitHub App '{slug}' repository selection was broadened from "
                "'selected' to 'all'.  The app now has access to every "
                "repository in the account.",
            )
        if prev_s == "all" and new_s == "selected":
            return (
                "low",
                f"GitHub App '{slug}' repository selection was narrowed to "
                "'selected'.",
            )

    if change_type == "modified" and field_path == "repositories_count":
        prev_n = _to_int(prev_value)
        new_n = _to_int(new_value)
        if new_n > prev_n:
            return (
                "medium",
                f"GitHub App '{slug}' repository count increased from "
                f"{prev_n} to {new_n}.  Verify the new repositories were "
                "added intentionally.",
            )

    return (
        "low",
        f"GitHub App '{slug}' metadata changed; no specific risk pattern "
        "matched.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# G. github_security_features
# ─────────────────────────────────────────────────────────────────────────────


def _classify_security_features(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    if change_type != "modified":
        return (
            "low",
            "Security-features record changed; no specific risk pattern matched.",
        )

    new_b = _to_bool(new_value)
    private = bool(pm.get("private_repo", True))

    # High-severity disablements.
    if field_path == "secret_scanning_enabled" and not new_b:
        return (
            "high",
            "Secret scanning was disabled.  Newly-leaked secrets in commits "
            "will no longer be surfaced automatically.",
        )
    if field_path == "secret_scanning_push_protection" and not new_b:
        return (
            "high",
            "Secret-scanning push protection was disabled.  Commits "
            "containing secrets can now be pushed without being blocked.",
        )
    if field_path == "code_scanning_enabled" and not new_b:
        return (
            "high",
            "Code scanning was disabled.  Static-analysis alerts on new code "
            "will no longer be produced.",
        )

    # Medium-severity disablements.
    if field_path == "dependabot_alerts_enabled" and not new_b:
        return (
            "medium",
            "Dependabot alerts were disabled.  Known-vulnerable dependencies "
            "will no longer be surfaced.",
        )
    if field_path == "dependabot_security_updates_enabled" and not new_b:
        return (
            "medium",
            "Dependabot security updates were disabled.  Vulnerable "
            "dependencies will no longer be auto-updated.",
        )
    if field_path == "vulnerability_alerts_enabled" and not new_b:
        return (
            "medium",
            "Vulnerability alerts were disabled.  Repository-level vulnerability "
            "notifications will no longer be delivered.",
        )

    # Enablements → low (positive change).
    if new_b and field_path in (
        "secret_scanning_enabled",
        "secret_scanning_push_protection",
        "code_scanning_enabled",
        "dependabot_alerts_enabled",
        "dependabot_security_updates_enabled",
        "vulnerability_alerts_enabled",
    ):
        return (
            "low",
            f"Security feature '{field_path}' was enabled — posture improved.",
        )

    return (
        "low",
        f"Security feature '{field_path}' changed; no specific risk pattern "
        "matched.",
    )
