"""Sentry risk classification rules (Sentry messages 1-3 of 8).

This module exists to give every ``sentry_*`` record type a dedicated,
correct classifier so that ``risk_service.classify_change()`` never falls
through to an unrelated provider's default classifier.

This is intentionally NOT a Security Finding taxonomy — that is message 6.
Classification here is deliberately structural, not incident-level:

- An organization identity metadata change (slug, name, status) is Low —
  these are informational identity fields, not security posture by
  themselves.
- A capability probe losing access is a Medium diagnostic signal, never a
  "security incident" — permission changes are common and expected (e.g.
  the monitoring token's scopes being intentionally re-scoped), not proof
  of compromise. Regaining access is Low.
- Project/team creation, rename, or platform/status change (message 2) is
  Low/Medium informational noise, never overclassified as a security
  event on its own — final privilege-aware severity belongs to message 5.
- An organization-role escalation to owner/manager/admin (a new privileged
  member, or an existing member promoted into one of those roles) is HIGH
  — this is the clearest privilege-escalation signal message 2 can
  observe. The reverse (demotion away from a privileged role, or an
  active member being disabled/removed) is Low — reducing access is not a
  security incident.
- Team membership and project-team assignment edges default to Low: they
  describe routing/organizational structure, not privileged organization-
  wide access — message 5 owns effective-access analysis.
- Alert rules (message 3): a rule being disabled, removed, or losing its
  last notification action (action_count > 0 -> 0 while still enabled) is
  the clearest "monitoring coverage silently disappeared" signal this
  message can observe — these are Medium/High. Routine rule/trigger/
  action creation, rename, or a resolve-threshold tweak is Low. Threshold
  weakening (a higher above-threshold or lower below-threshold, or a
  longer time window) is Medium only when the comparison direction is
  deterministically known; an unknown direction is Low/diagnostic rather
  than guessed.

Future messages (4-7) will add classifiers for integrations, webhooks,
repositories, releases, and privileged-access posture as those record
types are introduced — this module's dispatcher already fails safely
into a generic low-severity message for any ``sentry_*`` record type
that does not have a classifier yet, so this module continues to work
unmodified as an incremental target for those insertions.
"""

from __future__ import annotations

from typing import Any

from app.connectors.sentry_schema import (
    CAPABILITY_AVAILABLE,
    ORG_ROLE_ADMIN,
    ORG_ROLE_MANAGER,
    ORG_ROLE_OWNER,
    SENTRY_ALERT_ACTION,
    SENTRY_API_CAPABILITY,
    SENTRY_ISSUE_ALERT_RULE,
    SENTRY_MEMBER,
    SENTRY_METRIC_ALERT_RULE,
    SENTRY_METRIC_ALERT_TRIGGER,
    SENTRY_ORGANIZATION,
    SENTRY_PROJECT,
    SENTRY_PROJECT_TEAM_ASSIGNMENT,
    SENTRY_TEAM,
    SENTRY_TEAM_MEMBERSHIP,
    THRESHOLD_TYPE_ABOVE,
    THRESHOLD_TYPE_BELOW,
)

_PRIVILEGED_ORG_ROLES = frozenset({ORG_ROLE_OWNER, ORG_ROLE_MANAGER, ORG_ROLE_ADMIN})


def _get(obj: Any, field: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _classify_organization_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Sentry organization was added to monitoring."
    if ct == "removed":
        return (
            "medium",
            "A Sentry organization is no longer visible to ConfigTrace. "
            "Verify the integration still has a valid auth token.",
        )

    fp = (_get(change, "field_path") or "").lower()
    if fp in ("slug", "name", "status_category"):
        return "low", "The Sentry organization's identifying metadata changed."
    return "low", "A Sentry organization configuration field changed."


def _classify_api_capability_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Sentry API capability probe was recorded."
    if ct == "removed":
        return "low", "A Sentry API capability probe is no longer recorded."

    fp = (_get(change, "field_path") or "").lower()
    if fp == "status":
        nv = _get(change, "new_value")
        pv = _get(change, "prev_value")
        if pv == CAPABILITY_AVAILABLE and nv != CAPABILITY_AVAILABLE:
            return (
                "medium",
                "ConfigTrace's Sentry monitoring token lost read access to a "
                "previously available metadata family. Review the token's "
                "scopes if this was not expected.",
            )
        if pv != CAPABILITY_AVAILABLE and nv == CAPABILITY_AVAILABLE:
            return "low", "ConfigTrace's Sentry monitoring token gained read access to a metadata family."
        return "low", "A Sentry API capability probe's status changed."
    return "low", "A Sentry API capability record changed."


def _classify_project_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Sentry project was added to monitoring."
    if ct == "removed":
        return (
            "medium",
            "A Sentry project is no longer visible to ConfigTrace. Verify "
            "it was intentionally deleted/renamed rather than access being lost.",
        )

    fp = (_get(change, "field_path") or "").lower()
    if fp in ("slug", "name", "platform_category"):
        return "low", "A Sentry project's identifying metadata changed."
    if fp == "status_category":
        nv = (_get(change, "new_value") or "").lower() if isinstance(_get(change, "new_value"), str) else ""
        if nv in ("disabled", "pending_deletion", "deletion_in_progress"):
            return "medium", "A Sentry project is being disabled or deleted."
        return "low", "A Sentry project's status changed."
    return "low", "A Sentry project configuration field changed."


def _classify_team_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Sentry team was added."
    if ct == "removed":
        return "medium", "A Sentry team is no longer visible to ConfigTrace."

    return "low", "A Sentry team's identifying metadata changed."


def _classify_member_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    org_role = (pm.get("org_role_category") or "").lower()

    if ct == "added":
        if org_role in _PRIVILEGED_ORG_ROLES:
            return (
                "high",
                f"A new Sentry organization member was added with a privileged "
                f"organization role ({org_role}). Verify this was intentional.",
            )
        return "low", "A new Sentry organization member was added."
    if ct == "removed":
        return "low", "A Sentry organization member is no longer visible (disabled or removed)."

    fp = (_get(change, "field_path") or "")
    if fp == "org_role_category":
        pv = (_get(change, "prev_value") or "").lower() if isinstance(_get(change, "prev_value"), str) else ""
        nv = (_get(change, "new_value") or "").lower() if isinstance(_get(change, "new_value"), str) else ""
        if nv in _PRIVILEGED_ORG_ROLES and pv not in _PRIVILEGED_ORG_ROLES:
            return (
                "high",
                f"A Sentry organization member was promoted to a privileged "
                f"organization role ({nv}). Verify this was intentional.",
            )
        if pv in _PRIVILEGED_ORG_ROLES and nv not in _PRIVILEGED_ORG_ROLES:
            return "low", "A Sentry organization member's privileged role was removed."
        return "low", "A Sentry organization member's organization role changed."
    if fp == "member_status_category":
        nv = _get(change, "new_value")
        if nv == "unknown":
            return (
                "medium",
                "A Sentry organization member's pending/active status could no "
                "longer be determined.",
            )
        return "low", "A Sentry organization member's pending/active status changed."
    return "low", "A Sentry organization member's record changed."


def _classify_team_membership_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Sentry organization member was added to a team."
    if ct == "removed":
        return "low", "A Sentry organization member was removed from a team."

    fp = (_get(change, "field_path") or "")
    if fp == "team_role_category":
        nv = (_get(change, "new_value") or "").lower() if isinstance(_get(change, "new_value"), str) else ""
        if nv == "admin":
            return "medium", "A Sentry team member was promoted to team admin."
        return "low", "A Sentry team member's team-level role changed."
    return "low", "A Sentry team membership record changed."


def _classify_project_team_assignment_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Sentry team was granted access to a project."
    if ct == "removed":
        return "low", "A Sentry team's access to a project was revoked."
    return "low", "A Sentry project-team assignment changed."


def _classify_metric_alert_rule_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    status_category = pm.get("status_category")
    action_count = pm.get("action_count")

    if ct == "added":
        if status_category == "enabled" and action_count == 0:
            return (
                "medium",
                "A new Sentry metric alert rule was added enabled with zero notification actions "
                "— it will not notify anyone if it fires.",
            )
        return "low", "A new Sentry metric alert rule was added."
    if ct == "removed":
        return "medium", "A Sentry metric alert rule is no longer visible to ConfigTrace — monitoring coverage may have been lost."

    fp = (_get(change, "field_path") or "")
    if fp == "status_category":
        nv = _get(change, "new_value")
        if nv == "disabled":
            return "medium", "A Sentry metric alert rule was disabled."
        if nv == "enabled":
            return "low", "A Sentry metric alert rule was re-enabled."
        return "low", "A Sentry metric alert rule's status could no longer be determined."
    if fp == "action_count":
        pv = _get(change, "prev_value")
        nv = _get(change, "new_value")
        if isinstance(pv, int) and isinstance(nv, int):
            if pv > 0 and nv == 0:
                if status_category == "enabled":
                    return (
                        "high",
                        "An enabled Sentry metric alert rule lost its last notification action "
                        "— it will no longer notify anyone when it fires.",
                    )
                return "medium", "A Sentry metric alert rule lost its last notification action."
            if nv > pv:
                return "low", "A Sentry metric alert rule gained a notification action."
            if nv < pv:
                return "medium", "A Sentry metric alert rule lost one or more notification actions."
        return "low", "A Sentry metric alert rule's action count changed."
    if fp == "resolve_threshold":
        return "low", "A Sentry metric alert rule's resolve threshold changed."
    if fp in ("threshold_type_category", "environment_category", "dataset_category", "aggregate_category", "time_window_minutes"):
        return "low", "A Sentry metric alert rule's detection configuration changed — verify sensitivity was not unintentionally reduced."
    if fp in ("owner_type_category", "owner_id"):
        return "medium", "A Sentry metric alert rule's owner changed."
    return "low", "A Sentry metric alert rule configuration field changed."


def _classify_metric_alert_trigger_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Sentry metric alert trigger was added."
    if ct == "removed":
        return "medium", "A Sentry metric alert trigger is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "")
    if fp == "alert_threshold":
        raw_pm = _get(change, "provider_metadata")
        pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
        direction = pm.get("threshold_type_category")
        pv = _get(change, "prev_value")
        nv = _get(change, "new_value")
        if isinstance(pv, (int, float)) and isinstance(nv, (int, float)) and direction in (THRESHOLD_TYPE_ABOVE, THRESHOLD_TYPE_BELOW):
            if direction == THRESHOLD_TYPE_ABOVE:
                if nv > pv:
                    return "medium", "A Sentry metric alert trigger's above-threshold was weakened (raised), reducing detection sensitivity."
                if nv < pv:
                    return "low", "A Sentry metric alert trigger's above-threshold was strengthened (lowered)."
            else:  # BELOW
                if nv < pv:
                    return "medium", "A Sentry metric alert trigger's below-threshold was weakened (lowered), reducing detection sensitivity."
                if nv > pv:
                    return "low", "A Sentry metric alert trigger's below-threshold was strengthened (raised)."
        return "low", "A Sentry metric alert trigger's threshold changed (comparison direction unknown — verify sensitivity manually)."
    if fp == "action_count":
        pv = _get(change, "prev_value")
        nv = _get(change, "new_value")
        if isinstance(pv, int) and isinstance(nv, int) and pv > 0 and nv == 0:
            return "medium", "A Sentry metric alert trigger lost its last notification action."
        return "low", "A Sentry metric alert trigger's action count changed."
    if fp == "label_category":
        return "low", "A Sentry metric alert trigger's label changed."
    return "low", "A Sentry metric alert trigger configuration field changed."


def _classify_issue_alert_rule_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    status_category = pm.get("status_category")
    action_count = pm.get("action_count")

    if ct == "added":
        if status_category == "enabled" and action_count == 0:
            return (
                "medium",
                "A new Sentry issue alert rule was added enabled with zero notification actions "
                "— it will not notify anyone when it fires.",
            )
        return "low", "A new Sentry issue alert rule was added."
    if ct == "removed":
        return "medium", "A Sentry issue alert rule is no longer visible to ConfigTrace — monitoring coverage may have been lost."

    fp = (_get(change, "field_path") or "")
    if fp == "status_category":
        nv = _get(change, "new_value")
        if nv == "disabled":
            return "medium", "A Sentry issue alert rule was disabled."
        if nv == "enabled":
            return "low", "A Sentry issue alert rule was re-enabled."
        return "low", "A Sentry issue alert rule's status could no longer be determined."
    if fp == "action_count":
        pv = _get(change, "prev_value")
        nv = _get(change, "new_value")
        if isinstance(pv, int) and isinstance(nv, int):
            if pv > 0 and nv == 0:
                if status_category == "enabled":
                    return (
                        "high",
                        "An enabled Sentry issue alert rule lost its last notification action "
                        "— it will no longer notify anyone when it fires.",
                    )
                return "medium", "A Sentry issue alert rule lost its last notification action."
            if nv > pv:
                return "low", "A Sentry issue alert rule gained a notification action."
            if nv < pv:
                return "medium", "A Sentry issue alert rule lost one or more notification actions."
        return "low", "A Sentry issue alert rule's action count changed."
    if fp in ("action_match_category", "filter_match_category", "condition_count", "filter_count", "frequency_minutes"):
        return "low", "A Sentry issue alert rule's condition/filter/frequency configuration changed."
    if fp == "environment_category":
        return "low", "A Sentry issue alert rule's environment scope changed."
    if fp in ("owner_type_category", "owner_id"):
        return "medium", "A Sentry issue alert rule's owner changed."
    return "low", "A Sentry issue alert rule configuration field changed."


def _classify_alert_action_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Sentry alert notification action was added."
    if ct == "removed":
        return "medium", "A Sentry alert notification action was removed — verify the owning rule still notifies someone."

    fp = (_get(change, "field_path") or "")
    if fp in ("target_type_category", "target_id"):
        return "medium", "A Sentry alert notification action's target changed."
    if fp == "integration_id":
        return "medium", "A Sentry alert notification action's integration target changed."
    if fp == "action_category":
        return "medium", "A Sentry alert notification action's delivery channel changed."
    return "low", "A Sentry alert notification action configuration field changed."


def classify_sentry_change(change: object) -> tuple[str, str]:
    """Route a Sentry Change to its record-type classifier.

    Unknown/future ``sentry_*`` record types (i.e. any later-message
    planned taxonomy, before their classifiers exist) fail safely into a
    generic low-severity message rather than raising or falling through
    to an unrelated provider's classifier.
    """
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    record_type = (pm.get("record_type") or "").lower()

    if record_type == SENTRY_ORGANIZATION:
        return _classify_organization_change(change)
    if record_type == SENTRY_API_CAPABILITY:
        return _classify_api_capability_change(change)
    if record_type == SENTRY_PROJECT:
        return _classify_project_change(change)
    if record_type == SENTRY_TEAM:
        return _classify_team_change(change)
    if record_type == SENTRY_MEMBER:
        return _classify_member_change(change)
    if record_type == SENTRY_TEAM_MEMBERSHIP:
        return _classify_team_membership_change(change)
    if record_type == SENTRY_PROJECT_TEAM_ASSIGNMENT:
        return _classify_project_team_assignment_change(change)
    if record_type == SENTRY_METRIC_ALERT_RULE:
        return _classify_metric_alert_rule_change(change)
    if record_type == SENTRY_METRIC_ALERT_TRIGGER:
        return _classify_metric_alert_trigger_change(change)
    if record_type == SENTRY_ISSUE_ALERT_RULE:
        return _classify_issue_alert_rule_change(change)
    if record_type == SENTRY_ALERT_ACTION:
        return _classify_alert_action_change(change)
    return "low", "A Sentry configuration field changed."
