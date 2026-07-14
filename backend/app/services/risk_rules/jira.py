"""Jira drift risk classification rules.

Entry point: ``classify_jira_change(change)``

Classifies drift changes for Jira Cloud configuration records. Built during
the Jira detection QA pass — this module previously did not exist, so every
Jira change silently fell through to the Cloudflare DNS classifier fallback
in ``risk_service.py``.

Risk levels
-----------
high   — permission scheme grants a public/high-privilege permission
         (anonymous, anyone, administer-projects, manage-sprints,
         create-issues, transition-issues); webhook secret indicator
         removed; webhook URL scheme changed to HTTP; automation rule gains
         a web-request or external (Slack/Teams) action.

medium — permission scheme grants logged-in users a permission or its
         unknown/high-privilege/public grant counts increase; workflow or
         workflow-scheme structural posture weakens (no statuses/
         transitions, no default workflow, unmapped issue types); webhook
         disabled, has no events, or gains broad/comment/attachment event
         scope; automation rule disabled, scoped globally/multi-project, or
         gains an email action; board JQL filter becomes broad.

low    — count-only changes with unclear impact; metadata-only drift;
         unknown/missing category fields; safe restoration/improvement
         transitions (e.g. a permission grant removed, SSL/HTTPS restored,
         a webhook secret added).

Claim discipline
----------------
All reason strings use safe review-framing:
  "Jira configuration evidence may require review."
  "may require review"
  "does not confirm"
Forbidden phrases: breach, compromise, attacker, leaked, unauthorized access,
exfiltration, stolen, fraud, attack, issue exposed, ticket exposed, secret
exposed, data exposed.
"""

from __future__ import annotations

from app.models.change import Change


def _get(obj: object, field: str) -> object:
    """Safely retrieve a field from a Change object or dict."""
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _is_truthy(val: object) -> bool:
    if val is True or val == "true" or val == 1:
        return True
    return False


def _is_falsy_explicit(val: object) -> bool:
    if val is False or val == "false" or val == 0:
        return True
    return False


def _int_pair(prev_v: object, new_v: object) -> tuple[int, int]:
    try:
        return int(prev_v or 0), int(new_v or 0)
    except (TypeError, ValueError):
        return 0, 0


# ── jira_site ──────────────────────────────────────────────────────────────────


def _classify_site_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()

    if ct in ("added", "removed"):
        return ("low", "Jira site configuration record was added or removed during sync.")

    return ("low", f"Jira site configuration field '{fp}' changed.")


# ── jira_project ───────────────────────────────────────────────────────────────


def _classify_project_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Jira project configuration record was added or removed during sync.")

    if fp == "project_private":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Jira project private flag was removed. "
                "Jira configuration evidence may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Jira project private flag was set (restricted).")
        return ("low", "Jira project private flag is now unknown or missing.")

    if fp == "project_deleted":
        if _is_truthy(new_v):
            return (
                "medium",
                "Jira project was marked deleted. "
                "Jira configuration evidence may require review.",
            )
        return ("low", "Jira project deleted flag changed.")

    if fp == "project_archived":
        return ("low", "Jira project archived flag changed.")

    return ("low", f"Jira project configuration field '{fp}' changed.")


# ── jira_board ─────────────────────────────────────────────────────────────────


def _classify_board_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Jira board configuration record was added or removed during sync.")

    if fp == "board_jql_filter_broad":
        if _is_truthy(new_v):
            return (
                "medium",
                "Jira board JQL filter scope became broad. "
                "Jira configuration evidence may require review.",
            )
        return ("low", "Jira board JQL filter scope narrowed.")

    if fp == "project_id":
        return (
            "medium",
            "Jira board project linkage changed. "
            "Jira configuration evidence may require review.",
        )

    return ("low", f"Jira board configuration field '{fp}' changed.")


# ── jira_workflow ──────────────────────────────────────────────────────────────


def _classify_workflow_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Jira workflow configuration record was added or removed during sync.")

    if fp == "workflow_active":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Jira workflow became inactive. "
                "Jira configuration evidence may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Jira workflow became active.")
        return ("low", "Jira workflow active state is now unknown or missing.")

    if fp == "workflow_status_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return (
                "medium",
                "Jira workflow status count dropped to zero. "
                "Jira configuration evidence may require review.",
            )
        return ("low", f"Jira workflow status count changed from {n_old} to {n_new}.")

    if fp == "workflow_transition_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return (
                "medium",
                "Jira workflow transition count dropped to zero. "
                "Jira configuration evidence may require review.",
            )
        return ("low", f"Jira workflow transition count changed from {n_old} to {n_new}.")

    if fp == "workflow_global_transition_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new > n_old:
            return (
                "medium",
                f"Jira workflow global transition count increased from {n_old} to {n_new}. "
                "Jira configuration evidence may require review.",
            )
        return ("low", "Jira workflow global transition count decreased.")

    if fp == "workflow_orphan_status_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new > n_old:
            return (
                "medium",
                f"Jira workflow orphan status count increased from {n_old} to {n_new}. "
                "Jira configuration evidence may require review.",
            )
        return ("low", "Jira workflow orphan status count decreased.")

    if fp in (
        "workflow_transition_rule_count",
        "workflow_validator_count",
        "workflow_condition_count",
    ):
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new > n_old:
            return (
                "medium",
                f"Jira workflow {fp.replace('workflow_', '').replace('_', ' ')} increased "
                f"from {n_old} to {n_new}. Jira configuration evidence may require review.",
            )
        return ("low", f"Jira workflow {fp} changed from {n_old} to {n_new}.")

    if fp == "workflow_draft":
        return ("low", "Jira workflow draft state changed.")

    return ("low", f"Jira workflow configuration field '{fp}' changed.")


# ── jira_workflow_scheme ───────────────────────────────────────────────────────


def _classify_workflow_scheme_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Jira workflow scheme record was added or removed during sync.")

    if fp == "workflow_scheme_default_present":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Jira workflow scheme no longer has a default workflow indicator. "
                "Jira configuration evidence may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Jira workflow scheme default workflow indicator was set.")
        return ("low", "Jira workflow scheme default workflow presence is now unknown or missing.")

    if fp == "workflow_scheme_unmapped_issue_type_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new > n_old:
            return (
                "medium",
                f"Jira workflow scheme unmapped issue type count increased from {n_old} to {n_new}. "
                "Jira configuration evidence may require review.",
            )
        return ("low", "Jira workflow scheme unmapped issue type count decreased.")

    if fp == "workflow_scheme_project_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new < n_old:
            return ("low", f"Jira workflow scheme project count decreased from {n_old} to {n_new}.")
        return ("low", f"Jira workflow scheme project count changed from {n_old} to {n_new}.")

    return ("low", f"Jira workflow scheme field '{fp}' changed.")


# ── jira_permission_scheme ─────────────────────────────────────────────────────


def _classify_permission_scheme_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Jira permission scheme record was added or removed during sync.")

    if fp == "permission_anonymous_grant_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new > n_old:
            return (
                "high",
                f"Jira permission scheme anonymous grant count increased from {n_old} to {n_new} — "
                "Jira anonymous access may now be enabled for one or more permissions. "
                "Jira configuration evidence may require review.",
            )
        return ("low", "Jira permission scheme anonymous grant count decreased.")

    if fp == "permission_anyone_grant_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new > n_old:
            return (
                "high",
                f"Jira permission scheme 'anyone' grant count increased from {n_old} to {n_new} — "
                "Jira public access may now be enabled for one or more permissions. "
                "Jira configuration evidence may require review.",
            )
        return ("low", "Jira permission scheme 'anyone' grant count decreased.")

    if fp == "permission_logged_in_grant_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new > n_old:
            return (
                "medium",
                f"Jira permission scheme logged-in grant count increased from {n_old} to {n_new}. "
                "Jira configuration evidence may require review.",
            )
        return ("low", "Jira permission scheme logged-in grant count decreased.")

    if fp in (
        "permission_public_administer_projects",
        "permission_public_manage_sprints",
        "permission_public_create_issues",
        "permission_public_transition_issues",
    ):
        label = fp.replace("permission_public_", "").replace("_", "-")
        if _is_truthy(new_v):
            return (
                "high",
                f"Jira permission scheme grants public {label} access. "
                "Jira project access was broadened — Jira configuration evidence may require review.",
            )
        return ("low", f"Jira permission scheme public {label} access was removed.")

    if fp == "permission_public_browse_projects":
        if _is_truthy(new_v):
            return (
                "medium",
                "Jira permission scheme grants public browse-projects access. "
                "Jira project access was broadened — Jira configuration evidence may require review.",
            )
        return ("low", "Jira permission scheme public browse-projects access was removed.")

    if fp in ("permission_unknown_holder_count", "permission_public_grant_count"):
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new > n_old:
            return (
                "medium",
                f"Jira permission scheme {fp.replace('permission_', '').replace('_', ' ')} "
                f"increased from {n_old} to {n_new}. Jira configuration evidence may require review.",
            )
        return ("low", f"Jira permission scheme {fp} changed from {n_old} to {n_new}.")

    if fp == "permission_high_privilege_grant_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new > n_old:
            return (
                "medium",
                f"Jira permission scheme high-privilege grant count increased from {n_old} to {n_new}. "
                "Jira configuration evidence may require review.",
            )
        return ("low", "Jira permission scheme high-privilege grant count decreased.")

    if fp == "permission_grant_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new > n_old:
            return (
                "medium",
                f"Jira permission scheme total grant count increased from {n_old} to {n_new}. "
                "Jira configuration evidence may require review.",
            )
        return ("low", "Jira permission scheme total grant count decreased.")

    return ("low", f"Jira permission scheme field '{fp}' changed.")


# ── jira_notification_scheme ───────────────────────────────────────────────────


def _classify_notification_scheme_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Jira notification scheme record was added or removed during sync.")

    if fp == "notification_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return (
                "medium",
                "Jira notification scheme notification count dropped to zero. "
                "Jira configuration evidence may require review.",
            )
        return ("low", f"Jira notification scheme notification count changed from {n_old} to {n_new}.")

    if fp in ("notification_email_recipient_count", "notification_unknown_recipient_count"):
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new > n_old:
            return (
                "medium",
                f"Jira notification scheme {fp.replace('notification_', '').replace('_', ' ')} "
                f"increased from {n_old} to {n_new}. Jira configuration evidence may require review.",
            )
        return ("low", f"Jira notification scheme {fp} changed from {n_old} to {n_new}.")

    return ("low", f"Jira notification scheme field '{fp}' changed.")


# ── jira_issue_type_scheme ─────────────────────────────────────────────────────


def _classify_issue_type_scheme_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Jira issue type scheme record was added or removed during sync.")

    if fp == "default_issue_type_present":
        if _is_falsy_explicit(new_v):
            return ("low", "Jira issue type scheme default issue type indicator was removed.")
        return ("low", "Jira issue type scheme default issue type indicator changed.")

    return ("low", f"Jira issue type scheme field '{fp}' changed.")


# ── jira_field_configuration_scheme ────────────────────────────────────────────


def _classify_field_configuration_scheme_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()

    if ct in ("added", "removed"):
        return ("low", "Jira field configuration scheme record was added or removed during sync.")

    return ("low", f"Jira field configuration scheme field '{fp}' changed.")


# ── jira_screen_scheme ─────────────────────────────────────────────────────────


def _classify_screen_scheme_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Jira screen scheme record was added or removed during sync.")

    if fp == "screen_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return ("low", "Jira screen scheme screen count dropped to zero.")
        return ("low", f"Jira screen scheme screen count changed from {n_old} to {n_new}.")

    return ("low", f"Jira screen scheme field '{fp}' changed.")


# ── jira_webhook ────────────────────────────────────────────────────────────────


def _classify_webhook_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("medium", "A new Jira webhook was added. Jira configuration evidence may require review.")
    if ct == "removed":
        return ("low", "A Jira webhook was removed.")

    if fp == "webhook_enabled":
        if _is_falsy_explicit(new_v):
            return ("medium", "Jira webhook was disabled. Jira configuration evidence may require review.")
        if _is_truthy(new_v):
            return ("low", "Jira webhook was enabled.")
        return ("low", "Jira webhook enabled state is now unknown or missing.")

    if fp == "webhook_secret_present":
        if _is_falsy_explicit(new_v):
            return (
                "high",
                "Jira webhook secret indicator was removed. "
                "Jira configuration evidence may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Jira webhook secret indicator was added.")
        return ("low", "Jira webhook secret presence is now unknown or missing.")

    if fp == "webhook_url_scheme_category":
        if new_v == "http":
            return (
                "high",
                "Jira webhook URL scheme changed to HTTP (non-encrypted). "
                "Jira configuration evidence may require review.",
            )
        if new_v == "https":
            return ("low", "Jira webhook URL scheme changed to HTTPS.")
        return ("low", "Jira webhook URL scheme is now unknown or missing.")

    if fp == "webhook_jql_filter_present":
        if _is_falsy_explicit(new_v):
            return (
                "low",
                "Jira webhook JQL scope filter indicator was removed.",
            )
        return ("low", "Jira webhook JQL scope filter indicator changed.")

    if fp == "webhook_event_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0:
            return (
                "medium",
                "Jira webhook event count dropped to zero. "
                "Jira configuration evidence may require review.",
            )
        if n_new > n_old:
            return (
                "medium",
                f"Jira webhook event count increased from {n_old} to {n_new}. "
                "Jira configuration evidence may require review.",
            )
        return ("low", f"Jira webhook event count changed from {n_old} to {n_new}.")

    if fp in ("webhook_has_comment_events", "webhook_has_attachment_events", "webhook_all_issue_events"):
        if _is_truthy(new_v):
            return (
                "medium",
                f"Jira webhook event scope expanded: {fp.replace('webhook_', '')} is now true. "
                "Jira configuration evidence may require review.",
            )
        return ("low", f"Jira webhook event scope: {fp} changed.")

    if fp in ("webhook_has_sprint_events", "webhook_has_worklog_events"):
        return ("low", f"Jira webhook event scope: {fp} changed.")

    return ("low", f"Jira webhook field '{fp}' changed.")


# ── jira_automation_rule ───────────────────────────────────────────────────────


def _classify_automation_rule_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Jira automation rule record was added or removed during sync.")

    if fp == "automation_enabled":
        if _is_falsy_explicit(new_v):
            return ("medium", "Jira automation rule was disabled. Jira configuration evidence may require review.")
        if _is_truthy(new_v):
            return ("low", "Jira automation rule was enabled.")
        return ("low", "Jira automation rule enabled state is now unknown or missing.")

    if fp == "automation_scope_category":
        if new_v in ("global", "multi-project"):
            return (
                "medium",
                f"Jira automation rule scope changed to {new_v}. "
                "Jira configuration evidence may require review.",
            )
        return ("low", f"Jira automation rule scope changed to {new_v}.")

    if fp in ("automation_has_web_request_action", "automation_has_external_action"):
        if _is_truthy(new_v):
            return (
                "high",
                f"Jira automation rule gained a {fp.replace('automation_has_', '').replace('_', ' ')}. "
                "Jira configuration evidence may require review.",
            )
        return ("low", f"Jira automation rule {fp} changed.")

    if fp == "automation_has_email_action":
        if _is_truthy(new_v):
            return (
                "medium",
                "Jira automation rule gained an email action. "
                "Jira configuration evidence may require review.",
            )
        return ("low", "Jira automation rule email action changed.")

    if fp in ("automation_action_count", "automation_branch_count"):
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new > n_old:
            return (
                "medium",
                f"Jira automation rule {fp.replace('automation_', '').replace('_', ' ')} increased "
                f"from {n_old} to {n_new}. Jira configuration evidence may require review.",
            )
        return ("low", f"Jira automation rule {fp} changed from {n_old} to {n_new}.")

    if fp == "automation_component_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new > n_old:
            return (
                "low",
                f"Jira automation rule component count increased from {n_old} to {n_new}.",
            )
        return ("low", f"Jira automation rule component count changed from {n_old} to {n_new}.")

    return ("low", f"Jira automation rule field '{fp}' changed.")


# ── Main dispatcher ───────────────────────────────────────────────────────────


def classify_jira_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for a Jira configuration change.

    Dispatches on ``provider_metadata["record_type"]``:
      * ``jira_site``                       → site metadata rules
      * ``jira_project``                    → project posture rules
      * ``jira_board``                      → board scope rules
      * ``jira_workflow``                   → workflow structure rules
      * ``jira_workflow_scheme``            → workflow scheme adoption rules
      * ``jira_permission_scheme``          → permission grant posture rules
      * ``jira_notification_scheme``        → notification recipient rules
      * ``jira_issue_type_scheme``          → issue type taxonomy rules
      * ``jira_field_configuration_scheme`` → field configuration rules
      * ``jira_screen_scheme``              → screen scheme rules
      * ``jira_webhook``                    → webhook transport/scope rules
      * ``jira_automation_rule``            → automation rule posture rules

    Does not confirm breach, compromise, or unauthorized access.
    Jira configuration evidence may require review.
    """
    pm = _get(change, "provider_metadata") or {}
    if isinstance(pm, dict):
        record_type = (pm.get("record_type") or "").lower()
    else:
        record_type = ""

    if record_type == "jira_site":
        return _classify_site_change(change)
    if record_type == "jira_project":
        return _classify_project_change(change)
    if record_type == "jira_board":
        return _classify_board_change(change)
    if record_type == "jira_workflow":
        return _classify_workflow_change(change)
    if record_type == "jira_workflow_scheme":
        return _classify_workflow_scheme_change(change)
    if record_type == "jira_permission_scheme":
        return _classify_permission_scheme_change(change)
    if record_type == "jira_notification_scheme":
        return _classify_notification_scheme_change(change)
    if record_type == "jira_issue_type_scheme":
        return _classify_issue_type_scheme_change(change)
    if record_type == "jira_field_configuration_scheme":
        return _classify_field_configuration_scheme_change(change)
    if record_type == "jira_screen_scheme":
        return _classify_screen_scheme_change(change)
    if record_type == "jira_webhook":
        return _classify_webhook_change(change)
    if record_type == "jira_automation_rule":
        return _classify_automation_rule_change(change)

    # Fallback for unknown jira_ subtypes
    return (
        "low",
        f"Jira configuration changed (record type: {record_type or 'unknown'}). "
        "Jira configuration evidence may require review.",
    )
