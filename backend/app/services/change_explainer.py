"""Change explanation helper — Milestone 28.

Produces human-readable explanations for Change rows used in:
  - Email alert bodies (alert_service._compose_digest)
  - Change detail page summaries and suggested checks (frontend)

Pure functions — no database access.  Accepts both ORM objects and plain
dicts (so unit tests need no database).

Provider dispatch
-----------------
``provider_metadata["record_type"]`` prefixed with ``"github_"`` → GitHub rules.
Everything else → Cloudflare DNS rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Attribute-access helper (supports ORM objects and plain dicts)
# ─────────────────────────────────────────────────────────────────────────────

def _get(obj: Any, key: str) -> Any:
    """Return *obj[key]* for dicts, or ``getattr(obj, key, None)`` for objects."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


# ─────────────────────────────────────────────────────────────────────────────
# Output type
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ChangeExplanation:
    """Human-readable context for a single Change row.

    All fields are plain strings/lists — safe to embed directly in email
    bodies or frontend props without further encoding.
    """

    #: "Cloudflare DNS" | "GitHub repo configuration"
    provider_label: str

    #: Short human label for the record/item, e.g. "CNAME exx.configtrace.org"
    record_label: str

    #: Fragment used in single-change email subjects, e.g. "CNAME exx.configtrace.org target changed"
    subject_fragment: str

    #: One-sentence description of what happened.
    summary: str

    #: Plain-English specific change description (prev → new values).
    what_changed: str

    #: Human explanation of impact — typically the ``risk_reason`` string
    #: produced by the risk classifier.
    why_it_matters: str

    #: Suggested next steps for high/critical changes.  Empty list for
    #: low/medium changes (caller is responsible for deciding whether to show).
    suggested_checks: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Suggested check lists
# ─────────────────────────────────────────────────────────────────────────────

_DNS_CHECKS: list[str] = [
    "Confirm this change was intentional.",
    "Test the affected hostname (dig, nslookup, or browser).",
    "Verify the new target or IP address is correct.",
    "Check Cloudflare audit logs for who made the change.",
    "Roll back the DNS record if this was accidental.",
]

_DNS_EMAIL_AUTH_CHECKS: list[str] = [
    "Confirm this change was intentional.",
    "Test email delivery to verify SPF, DKIM, and DMARC are still valid.",
    "Verify your email provider's DNS configuration is intact.",
    "Check Cloudflare audit logs for who made the change.",
    "Restore the record if this was accidental.",
]

_GITHUB_CHECKS: list[str] = [
    "Confirm the change was intentional.",
    "Review GitHub repository settings.",
    "Check GitHub audit logs for who made the change.",
    "Verify workflows and deployments still pass.",
    "Restore the previous setting if this was accidental.",
]

_GITHUB_SECRET_CHECKS: list[str] = [
    "Confirm the rotation was intentional.",
    "Verify workflows or deployments using this secret still pass.",
    "Check GitHub audit logs for who made the change.",
    "Roll back or update dependent services if needed.",
]

_GITHUB_WEBHOOK_CHECKS: list[str] = [
    "Confirm the change was intentional.",
    "Verify the webhook endpoint is under your control.",
    "Check GitHub audit logs for who made the change.",
    "Test that events are being received by the correct endpoint.",
    "Restore the previous URL if this was accidental.",
]

_GITHUB_BRANCH_PROTECTION_CHECKS: list[str] = [
    "Confirm the change was intentional.",
    "Review branch protection rules in GitHub repository settings.",
    "Check GitHub audit logs for who made the change.",
    "Verify that CI/CD gates and merge requirements are still in place.",
    "Re-enable protection if this was accidental.",
]

_GITHUB_VISIBILITY_CHECKS: list[str] = [
    "Confirm this change was intentional.",
    "Review whether sensitive data, secrets, or proprietary code may be exposed.",
    "Check GitHub audit logs for who made the change.",
    "Change visibility back to private if this was accidental.",
]


def _dns_checks_for(rt: str, record_name: str) -> list[str]:
    """Return DNS-specific suggested checks, specialised for email-auth records."""
    name_lower = record_name.lower()
    is_email_auth = (
        rt in ("MX", "TXT")
        and any(kw in name_lower for kw in ("_dmarc", "_domainkey", "spf"))
    ) or rt == "MX"
    return _DNS_EMAIL_AUTH_CHECKS if is_email_auth else _DNS_CHECKS


def _github_checks_for(record_type: str) -> list[str]:
    """Return GitHub-specific suggested checks for the given ``record_type``."""
    if record_type == "github_actions_secret":
        return _GITHUB_SECRET_CHECKS
    if record_type == "github_webhook":
        return _GITHUB_WEBHOOK_CHECKS
    if record_type == "github_branch_protection":
        return _GITHUB_BRANCH_PROTECTION_CHECKS
    if record_type == "github_repo_settings":
        return _GITHUB_VISIBILITY_CHECKS
    return _GITHUB_CHECKS


# ─────────────────────────────────────────────────────────────────────────────
# Cloudflare DNS explanation
# ─────────────────────────────────────────────────────────────────────────────

def _explain_dns_change(change: Any, pm: dict) -> ChangeExplanation:
    record_type = pm.get("record_type") or ""
    record_name = pm.get("record_name") or _get(change, "record_identifier") or ""
    change_type = (_get(change, "change_type") or "").lower()
    field_path  = _get(change, "field_path") or ""
    prev_value  = _get(change, "prev_value")
    new_value   = _get(change, "new_value")
    risk_reason = _get(change, "risk_reason") or "This change may affect production traffic."
    risk_level  = (_get(change, "risk_level") or "").lower()

    rt = record_type.upper()
    record_label = f"{rt} {record_name}".strip() if rt else record_name

    # ── Summary and subject_fragment ──────────────────────────────────────
    if change_type == "removed":
        subject_fragment = f"{record_label} removed"
        summary = f"{record_label} was removed from Cloudflare DNS."

    elif change_type == "added":
        subject_fragment = f"{record_label} added"
        summary = f"{record_label} was added to Cloudflare DNS."

    else:  # modified
        if field_path == "content" and rt == "CNAME":
            subject_fragment = f"CNAME {record_name} target changed"
            summary = f"The CNAME target for {record_name} changed."
        elif field_path == "content" and rt in ("A", "AAAA"):
            subject_fragment = f"{rt} {record_name} address changed"
            summary = f"The IP address for {record_name} changed."
        elif field_path == "proxied":
            state = "enabled" if new_value else "disabled"
            subject_fragment = f"Cloudflare proxy {state} for {record_name}"
            summary = f"Cloudflare proxying was {state} for {record_name}."
        elif field_path == "ttl":
            subject_fragment = f"{record_label} TTL changed"
            summary = f"The TTL for {record_name} changed."
        else:
            subject_fragment = f"{record_label} modified"
            summary = f"{record_label} was modified in Cloudflare DNS."

    # ── What changed ──────────────────────────────────────────────────────
    what_changed = _dns_what_changed(
        change_type, field_path, rt, record_name, prev_value, new_value, pm
    )

    # ── Suggested checks (high/critical only) ─────────────────────────────
    checks = _dns_checks_for(rt, record_name) if risk_level in ("high", "critical") else []

    return ChangeExplanation(
        provider_label="Cloudflare DNS",
        record_label=record_label,
        subject_fragment=subject_fragment,
        summary=summary,
        what_changed=what_changed,
        why_it_matters=risk_reason,
        suggested_checks=checks,
    )


def _dns_what_changed(
    change_type: str,
    field_path: str,
    rt: str,
    record_name: str,
    prev_value: Any,
    new_value: Any,
    pm: dict,
) -> str:
    if change_type == "removed":
        old_content = pm.get("record_content")
        if old_content is None and isinstance(prev_value, dict):
            old_content = prev_value.get("content")
        if old_content:
            if rt == "CNAME":
                return f"{record_name} no longer points to {old_content}."
            if rt in ("A", "AAAA"):
                return f"{record_name} no longer resolves to {old_content}."
            if rt == "MX":
                return f"The MX record pointing to {old_content} was removed."
            return f"{record_name} ({rt} record with value {old_content}) was removed."
        return f"{record_name} ({rt} record) was removed."

    if change_type == "added":
        new_content: Any = None
        if isinstance(new_value, dict):
            new_content = new_value.get("content")
        if new_content:
            if rt == "CNAME":
                return f"{record_name} now points to {new_content}."
            if rt in ("A", "AAAA"):
                return f"{record_name} now resolves to {new_content}."
            if rt == "MX":
                return f"A new MX record pointing to {new_content} was added."
            return f"{record_name} ({rt} record with value {new_content}) was added."
        return f"{record_name} ({rt} record) was added."

    # modified
    if field_path == "content":
        if rt == "CNAME":
            return f"{record_name} now points to {new_value} instead of {prev_value}."
        if rt in ("A", "AAAA"):
            return f"{record_name} now resolves to {new_value} instead of {prev_value}."
        if rt == "MX":
            return f"The MX record now delivers to {new_value} (was {prev_value})."
        return f"The content of {record_name} changed from {prev_value!r} to {new_value!r}."

    if field_path == "ttl":
        return f"The TTL for {record_name} changed from {prev_value}s to {new_value}s."

    if field_path == "proxied":
        state = "enabled" if new_value else "disabled"
        return f"Cloudflare proxying was {state} for {record_name}."

    if field_path == "priority":
        return f"The MX priority for {record_name} changed from {prev_value} to {new_value}."

    if field_path == "comment":
        return f"The DNS comment for {record_name} was updated."

    return f"The '{field_path}' field for {record_name} changed from {prev_value!r} to {new_value!r}."


# ─────────────────────────────────────────────────────────────────────────────
# GitHub explanation
# ─────────────────────────────────────────────────────────────────────────────

def _explain_github_change(change: Any, pm: dict, record_type: str) -> ChangeExplanation:
    record_name = pm.get("record_name") or ""
    change_type = (_get(change, "change_type") or "").lower()
    field_path  = _get(change, "field_path") or ""
    prev_value  = _get(change, "prev_value")
    new_value   = _get(change, "new_value")
    risk_reason = (
        _get(change, "risk_reason")
        or "This change may affect your repository configuration."
    )
    risk_level = (_get(change, "risk_level") or "").lower()

    if record_type == "github_actions_secret":
        record_label, subject_fragment, summary, what_changed = \
            _github_secret(change_type, field_path, record_name)

    elif record_type == "github_actions_variable":
        record_label, subject_fragment, summary, what_changed = \
            _github_variable(change_type, field_path, record_name, prev_value, new_value)

    elif record_type == "github_branch_protection":
        record_label, subject_fragment, summary, what_changed = \
            _github_branch_protection(change_type, field_path, prev_value, new_value)

    elif record_type == "github_repo_settings":
        record_label, subject_fragment, summary, what_changed = \
            _github_repo_settings(change_type, field_path, prev_value, new_value)

    elif record_type == "github_webhook":
        record_label, subject_fragment, summary, what_changed = \
            _github_webhook(change_type, field_path, prev_value, new_value)

    elif record_type == "github_deploy_key":
        record_label, subject_fragment, summary, what_changed = \
            _github_deploy_key(change_type, field_path, prev_value, new_value)

    elif record_type == "github_actions_permissions":
        record_label = "Actions permissions"
        subject_fragment = (
            f"Actions permissions {field_path} changed"
            if field_path else "Actions permissions changed"
        )
        summary = "GitHub Actions permissions changed."
        what_changed = (
            f"Actions permission '{field_path}' changed from {prev_value!r} to {new_value!r}."
            if field_path else "GitHub Actions permissions changed."
        )

    else:
        friendly = record_type.replace("github_", "").replace("_", " ").title()
        record_label     = friendly
        subject_fragment = f"{friendly} changed"
        summary          = f"A GitHub configuration record changed ({record_type})."
        what_changed     = "An unrecognised GitHub configuration record type changed."

    checks = _github_checks_for(record_type) if risk_level in ("high", "critical") else []

    return ChangeExplanation(
        provider_label="GitHub repo configuration",
        record_label=record_label,
        subject_fragment=subject_fragment,
        summary=summary,
        what_changed=what_changed,
        why_it_matters=risk_reason,
        suggested_checks=checks,
    )


# GitHub per-record-type helpers
# Each returns (record_label, subject_fragment, summary, what_changed).

_SECRET_PRIVACY = (
    "Secret values are never exposed by GitHub or stored by ConfigTrace."
)


def _github_secret(
    change_type: str,
    field_path: str,
    record_name: str,
) -> tuple[str, str, str, str]:
    label = f"Actions secret {record_name}" if record_name else "Actions secret"
    if change_type == "removed":
        frag    = f"Actions secret {record_name} deleted" if record_name else "Actions secret deleted"
        summary = f"The Actions secret {record_name} was deleted." if record_name else "An Actions secret was deleted."
        what    = (
            f"The secret {record_name} was deleted from this repository. {_SECRET_PRIVACY}"
            if record_name else f"An Actions secret was deleted. {_SECRET_PRIVACY}"
        )
    elif change_type == "added":
        frag    = f"Actions secret {record_name} added" if record_name else "Actions secret added"
        summary = f"A new Actions secret {record_name} was added." if record_name else "A new Actions secret was added."
        what    = (
            f"A new secret {record_name} was added. {_SECRET_PRIVACY}"
            if record_name else f"A new Actions secret was added. {_SECRET_PRIVACY}"
        )
    else:
        # Rotation (modified → last_updated_at changed)
        frag    = f"Actions secret {record_name} updated" if record_name else "Actions secret updated"
        summary = f"The Actions secret {record_name} was rotated." if record_name else "An Actions secret was rotated."
        what    = (
            f"The secret metadata for {record_name} changed. {_SECRET_PRIVACY}"
            if record_name else f"The secret metadata changed. {_SECRET_PRIVACY}"
        )
    return label, frag, summary, what


def _github_variable(
    change_type: str,
    field_path: str,
    record_name: str,
    prev_value: Any,
    new_value: Any,
) -> tuple[str, str, str, str]:
    label = f"Actions variable {record_name}" if record_name else "Actions variable"
    if change_type == "removed":
        frag    = f"Actions variable {record_name} removed" if record_name else "Actions variable removed"
        summary = f"The Actions variable {record_name} was removed." if record_name else "An Actions variable was removed."
        what    = f"The variable {record_name} was removed." if record_name else "An Actions variable was removed."
    elif change_type == "added":
        frag    = f"Actions variable {record_name} added" if record_name else "Actions variable added"
        summary = f"A new Actions variable {record_name} was added." if record_name else "A new Actions variable was added."
        what    = f"A new variable {record_name} was added." if record_name else "A new Actions variable was added."
    else:
        frag    = f"Actions variable {record_name} changed" if record_name else "Actions variable changed"
        summary = f"The Actions variable {record_name} was updated." if record_name else "An Actions variable was updated."
        if isinstance(new_value, str):
            what = (
                f"The variable {record_name} changed from {prev_value!r} to {new_value!r}."
                if record_name else f"An Actions variable changed from {prev_value!r} to {new_value!r}."
            )
        else:
            what = f"The variable {record_name} was updated." if record_name else "An Actions variable was updated."
    return label, frag, summary, what


def _github_branch_protection(
    change_type: str,
    field_path: str,
    prev_value: Any,
    new_value: Any,
) -> tuple[str, str, str, str]:
    label = "Branch protection"
    if change_type == "removed":
        frag    = "branch protection rule deleted"
        summary = "A branch protection rule was deleted."
        what    = "The branch protection rule was deleted. The branch is now unprotected."
    elif change_type == "added":
        frag    = "branch protection rule added"
        summary = "A branch protection rule was added."
        what    = "A new branch protection rule was created."
    else:
        frag    = f"branch protection {field_path} changed" if field_path else "branch protection changed"
        summary = (
            f"A branch protection setting changed ({field_path})."
            if field_path else "A branch protection setting changed."
        )
        what    = (
            f"Branch protection setting '{field_path}' changed from {prev_value!r} to {new_value!r}."
            if field_path else "A branch protection setting was modified."
        )
    return label, frag, summary, what


def _github_repo_settings(
    change_type: str,
    field_path: str,
    prev_value: Any,
    new_value: Any,
) -> tuple[str, str, str, str]:
    label = "Repository settings"
    if field_path == "visibility":
        frag    = "repository visibility changed"
        summary = f"Repository visibility changed to {new_value}."
        what    = f"Repository visibility changed from {prev_value!r} to {new_value!r}."
    elif field_path == "default_branch":
        frag    = "default branch changed"
        summary = f"The default branch changed from {prev_value} to {new_value}."
        what    = f"Default branch changed from {prev_value!r} to {new_value!r}."
    elif field_path == "archived":
        frag    = "repository archived"
        summary = "The repository was archived."
        what    = "The repository was archived and is now read-only."
    else:
        frag    = f"repository setting {field_path} changed" if field_path else "repository settings changed"
        summary = (
            f"Repository setting {field_path} was updated."
            if field_path else "A repository setting was updated."
        )
        what    = (
            f"Repository setting '{field_path}' changed from {prev_value!r} to {new_value!r}."
            if field_path else "A repository setting was modified."
        )
    return label, frag, summary, what


def _github_webhook(
    change_type: str,
    field_path: str,
    prev_value: Any,
    new_value: Any,
) -> tuple[str, str, str, str]:
    label = "Webhook"
    if change_type == "removed":
        frag    = "webhook deleted"
        summary = "A repository webhook was deleted."
        what    = "The webhook was deleted. The receiving system will stop getting GitHub events."
    elif change_type == "added":
        frag    = "webhook added"
        summary = "A new repository webhook was added."
        what    = "A new webhook was added. GitHub events will now be delivered to the configured endpoint."
    elif field_path == "url":
        frag    = "webhook URL changed"
        summary = "The webhook delivery URL changed."
        what    = f"The webhook delivery URL changed from {prev_value!r} to {new_value!r}."
    elif field_path == "active":
        action  = "re-enabled" if new_value else "disabled"
        frag    = f"webhook {action}"
        summary = f"A repository webhook was {action}."
        what    = f"The webhook was {action}."
    else:
        frag    = f"webhook {field_path} changed" if field_path else "webhook changed"
        summary = "Webhook configuration changed."
        what    = (
            f"Webhook field '{field_path}' changed from {prev_value!r} to {new_value!r}."
            if field_path else "A webhook setting was modified."
        )
    return label, frag, summary, what


def _github_deploy_key(
    change_type: str,
    field_path: str,
    prev_value: Any,
    new_value: Any,
) -> tuple[str, str, str, str]:
    label = "Deploy key"
    if change_type == "removed":
        frag    = "deploy key removed"
        summary = "A deploy key was removed."
        what    = "A deploy key was removed. Automated systems using it will lose repository access."
    elif change_type == "added":
        new_record  = new_value if isinstance(new_value, dict) else {}
        read_only   = new_record.get("read_only", True)
        access_type = "read-only" if read_only else "write-enabled"
        frag    = f"{access_type} deploy key added"
        summary = f"A {access_type} deploy key was added."
        what    = f"A new {access_type} deploy key was added to this repository."
    elif field_path == "read_only":
        new_access = "read-only" if new_value else "read-write"
        old_access = "read-write" if new_value else "read-only"
        frag    = f"deploy key changed to {new_access}"
        summary = "A deploy key's access level changed."
        what    = f"The deploy key changed from {old_access} to {new_access}."
    else:
        frag    = f"deploy key {field_path} changed" if field_path else "deploy key changed"
        summary = "A deploy key was modified."
        what    = (
            f"Deploy key field '{field_path}' changed from {prev_value!r} to {new_value!r}."
            if field_path else "A deploy key was modified."
        )
    return label, frag, summary, what


# ─────────────────────────────────────────────────────────────────────────────
# Public interface
# ─────────────────────────────────────────────────────────────────────────────

def explain_change(change: Any) -> ChangeExplanation:
    """Return a :class:`ChangeExplanation` for *change* (ORM object or dict).

    Pure — no database access.

    Dispatch logic:
    - ``provider_metadata["record_type"]`` prefixed with ``"github_"``
      → GitHub explanation.
    - Everything else (including missing metadata) → Cloudflare DNS explanation.

    Args:
        change: A ``Change`` ORM instance or a plain ``dict`` with the same
                field names.  The following keys are used:
                ``change_type``, ``field_path``, ``prev_value``, ``new_value``,
                ``risk_level``, ``risk_reason``, ``provider_metadata``,
                ``record_identifier``.

    Returns:
        :class:`ChangeExplanation` with all fields populated.
    """
    pm: dict = _get(change, "provider_metadata") or {}
    record_type = (pm.get("record_type") or "").lower()

    if record_type.startswith("github_"):
        return _explain_github_change(change, pm, record_type)

    return _explain_dns_change(change, pm)
