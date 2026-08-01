"""Sentry risk classification rules (Sentry messages 1-5 of 8).

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

- Integrations/repositories/code mappings/ownership rules (message 4):
  an integration or repository being disabled/removed is Medium (routing/
  code-context coverage may be lost); routine addition/rename is Low. A
  code mapping losing its stack/source-root configuration is Medium
  (stack-trace-to-source linkage degrades). An ownership rule's owner
  team/member changing, or the rule/config disappearing, is Medium — this
  message never claims issues will definitely go unassigned (message 5+
  owns effective-access conclusions), only that the routing evidence
  changed.

- Effective access (message 5): all severities below reflect purely
  DERIVED evidence (zero additional API calls) — a member gaining the
  ``owner``/``manager`` tier or organization-wide project access is HIGH;
  gaining ``admin`` (or a bare team-admin bump) is MEDIUM; any reduction
  is Low/restorative. A routing target flipping from resolved to
  unresolved (an ownership rule or alert action now points at a
  team/member that no longer exists) is HIGH when the owning rule/config
  is still enabled/active, MEDIUM otherwise — this module never claims
  issues are DEFINITELY unassigned or unrouted, only that the routing
  evidence itself changed (message 6 owns Finding-level conclusions).

Future messages (6-7) will add Security Findings and exhaustive
reliability hardening as those concerns are introduced — this module's
dispatcher already fails safely into a generic low-severity message for
any ``sentry_*`` record type that does not have a classifier yet, so this
module continues to work unmodified as an incremental target for those
insertions.
"""

from __future__ import annotations

from typing import Any

from app.connectors.sentry_schema import (
    CAPABILITY_AVAILABLE,
    ORG_ROLE_ADMIN,
    ORG_ROLE_MANAGER,
    ORG_ROLE_OWNER,
    PRIVILEGE_TIER_CRITICAL,
    PRIVILEGE_TIER_HIGH,
    PRIVILEGE_TIER_MEDIUM,
    SENTRY_ALERT_ACTION,
    SENTRY_API_CAPABILITY,
    SENTRY_CODE_MAPPING,
    SENTRY_ISSUE_ALERT_RULE,
    SENTRY_MEMBER,
    SENTRY_METRIC_ALERT_RULE,
    SENTRY_METRIC_ALERT_TRIGGER,
    SENTRY_ORGANIZATION,
    SENTRY_ORGANIZATION_INTEGRATION,
    SENTRY_OWNERSHIP_RULE,
    SENTRY_PRIVILEGED_MEMBER,
    SENTRY_PRIVILEGED_TEAM,
    SENTRY_PROJECT,
    SENTRY_PROJECT_TEAM_ASSIGNMENT,
    SENTRY_REPOSITORY,
    SENTRY_ROUTING_CONTEXT,
    SENTRY_TEAM,
    SENTRY_TEAM_MEMBERSHIP,
    THRESHOLD_TYPE_ABOVE,
    THRESHOLD_TYPE_BELOW,
)

_PRIVILEGED_ORG_ROLES = frozenset({ORG_ROLE_OWNER, ORG_ROLE_MANAGER, ORG_ROLE_ADMIN})
_HIGH_OR_ABOVE_TIERS = frozenset({PRIVILEGE_TIER_CRITICAL, PRIVILEGE_TIER_HIGH})
_TIER_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


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


def _classify_organization_integration_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Sentry organization integration was installed."
    if ct == "removed":
        return "medium", "A Sentry organization integration is no longer visible to ConfigTrace — routing/coverage through it may be lost."

    fp = (_get(change, "field_path") or "")
    if fp == "status_category":
        nv = _get(change, "new_value")
        if nv in ("disabled", "pending_deletion", "deletion_in_progress"):
            return "medium", "A Sentry organization integration was disabled or is being removed."
        if nv == "active":
            return "low", "A Sentry organization integration was re-enabled."
        return "low", "A Sentry organization integration's status could no longer be determined."
    if fp == "name":
        return "low", "A Sentry organization integration's display name changed."
    if fp == "provider_category":
        return "medium", "A Sentry organization integration's provider changed."
    return "low", "A Sentry organization integration configuration field changed."


def _classify_repository_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Sentry-tracked repository was added."
    if ct == "removed":
        return "low", "A Sentry-tracked repository is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "")
    if fp == "status_category":
        nv = _get(change, "new_value")
        if nv in ("disabled", "pending_deletion", "deletion_in_progress"):
            return "medium", "A Sentry-tracked repository was disabled or is being removed."
        return "low", "A Sentry-tracked repository's status changed."
    if fp == "integration_id":
        return "medium", "A Sentry-tracked repository's owning integration changed — verify the new integration is still trusted."
    if fp == "name":
        return "low", "A Sentry-tracked repository's display name changed."
    return "low", "A Sentry repository configuration field changed."


def _classify_code_mapping_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Sentry code mapping was added."
    if ct == "removed":
        return "medium", "A Sentry code mapping was removed — stack-trace-to-source linkage for this project/repository may be lost."

    fp = (_get(change, "field_path") or "")
    if fp in ("repository_id", "project_id"):
        return "medium", "A Sentry code mapping's repository or project target changed."
    if fp in ("stack_root_configured", "source_root_configured"):
        nv = _get(change, "new_value")
        if nv is False:
            return "medium", "A Sentry code mapping's stack/source root configuration was cleared."
        return "low", "A Sentry code mapping's stack/source root configuration changed."
    if fp == "default_branch_configured":
        return "low", "A Sentry code mapping's default branch configuration changed."
    return "low", "A Sentry code mapping configuration field changed."


def _classify_ownership_rule_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Sentry ownership rule was added."
    if ct == "removed":
        return (
            "medium",
            "A Sentry ownership rule was removed. This does not by itself prove issues will go "
            "unassigned — message 5 owns effective-access conclusions.",
        )

    fp = (_get(change, "field_path") or "")
    if fp in ("owner_type_category", "owner_id"):
        return "medium", "A Sentry ownership rule's owner team/member changed."
    if fp == "matcher_category":
        return "low", "A Sentry ownership rule's matcher type changed."
    if fp == "is_active":
        nv = _get(change, "new_value")
        if nv is False:
            return "medium", "A Sentry project's ownership configuration was deactivated."
        return "low", "A Sentry project's ownership configuration was activated."
    if fp in ("fallthrough", "auto_assignment_category"):
        return "low", "A Sentry project's ownership fallback configuration changed."
    return "low", "A Sentry ownership rule configuration field changed."


def _classify_privileged_member_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    privilege_tier = pm.get("privilege_tier")

    if ct == "added":
        if privilege_tier in _HIGH_OR_ABOVE_TIERS:
            return (
                "high",
                f"A Sentry member was newly identified with {privilege_tier}-tier organization/routing "
                "authority. Verify this was intentional.",
            )
        if privilege_tier == "medium":
            return "medium", "A Sentry member was newly identified with medium-tier organization/routing authority."
        return "low", "A Sentry member was newly identified with meaningful (low-tier) routing authority."
    if ct == "removed":
        return "low", "A Sentry member no longer has meaningful organization/routing authority (privileged-member evidence removed)."

    fp = (_get(change, "field_path") or "")
    if fp == "privilege_tier":
        pv = _get(change, "prev_value")
        nv = _get(change, "new_value")
        pv_rank = _TIER_RANK.get(pv, 0)
        nv_rank = _TIER_RANK.get(nv, 0)
        if nv_rank > pv_rank:
            if nv in _HIGH_OR_ABOVE_TIERS:
                return "high", f"A Sentry member's privilege tier increased to {nv}."
            return "medium", f"A Sentry member's privilege tier increased to {nv}."
        if nv_rank < pv_rank:
            return "low", f"A Sentry member's privilege tier decreased to {nv}."
        return "low", "A Sentry member's privilege tier changed without a clear direction."
    if fp == "organization_wide_project_access":
        nv = _get(change, "new_value")
        if nv is True:
            return "high", "A Sentry member gained organization-wide project access."
        if nv is False:
            return "low", "A Sentry member's organization-wide project access was removed."
        return "medium", "A Sentry member's organization-wide project access could no longer be determined."
    if fp == "effective_project_count":
        pv = _get(change, "prev_value")
        nv = _get(change, "new_value")
        if isinstance(pv, int) and isinstance(nv, int) and nv > pv:
            return "medium", "A Sentry member's effective project access broadened."
        return "low", "A Sentry member's effective project access changed."
    if fp in ("integration_control_context", "repository_control_context"):
        nv = _get(change, "new_value")
        if nv == "full":
            return "medium", "A Sentry member gained broader integration/repository control authority."
        return "low", "A Sentry member's integration/repository control context changed."
    if fp in ("team_admin_team_count", "alert_routing_target_count", "ownership_rule_target_count"):
        return "low", "A Sentry member's routing-authority scope changed."
    return "low", "A Sentry privileged-member record field changed."


def _classify_privileged_team_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Sentry team was newly identified with meaningful project/routing authority."
    if ct == "removed":
        return "low", "A Sentry team no longer has meaningful project/routing authority."

    fp = (_get(change, "field_path") or "")
    if fp == "privileged_member_count":
        pv = _get(change, "prev_value")
        nv = _get(change, "new_value")
        if isinstance(pv, int) and isinstance(nv, int) and nv > pv:
            return "medium", "A Sentry team gained an additional team-admin member."
        return "low", "A Sentry team's team-admin member count changed."
    if fp == "project_count":
        return "low", "A Sentry team's assigned project count changed."
    if fp in ("ownership_rule_target_count", "alert_action_target_count"):
        return "low", "A Sentry team's routing-target count changed."
    if fp == "unresolved_member_count":
        pv = _get(change, "prev_value")
        nv = _get(change, "new_value")
        if isinstance(pv, int) and isinstance(nv, int) and nv > pv:
            return "medium", "A Sentry team gained an unresolved membership reference (member no longer found)."
        return "low", "A Sentry team's unresolved-membership count changed."
    return "low", "A Sentry privileged-team record field changed."


def _classify_routing_context_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    context_enabled = pm.get("context_enabled")

    if ct == "added":
        target_resolved = pm.get("target_resolved")
        if target_resolved is False and context_enabled:
            return (
                "medium",
                "A new Sentry routing target was identified as unresolved on an active/enabled rule.",
            )
        return "low", "A new Sentry routing context was identified."
    if ct == "removed":
        return "low", "A Sentry routing context is no longer visible to ConfigTrace."

    fp = (_get(change, "field_path") or "")
    if fp == "target_resolved":
        nv = _get(change, "new_value")
        if nv is False:
            severity = "high" if context_enabled else "medium"
            return severity, "A Sentry routing target became unresolved (points to a team/member that no longer exists)."
        return "low", "A previously-unresolved Sentry routing target was restored."
    if fp == "target_active":
        nv = _get(change, "new_value")
        if nv is False:
            return "medium", "A Sentry routing target is no longer an active member."
        return "low", "A Sentry routing target's active status changed."
    if fp == "integration_status_category":
        nv = _get(change, "new_value")
        if nv == "disabled":
            severity = "high" if context_enabled else "medium"
            return severity, "A Sentry routing target's delivery integration was disabled."
        return "low", "A Sentry routing target's delivery integration status changed."
    if fp == "context_enabled":
        nv = _get(change, "new_value")
        if nv is True:
            return "low", "A Sentry routing context's owning rule/configuration became enabled/active."
        return "low", "A Sentry routing context's owning rule/configuration changed enabled/active state."
    if fp in ("target_type_category", "target_id"):
        return "medium", "A Sentry routing context's target changed."
    return "low", "A Sentry routing context field changed."


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
    if record_type == SENTRY_ORGANIZATION_INTEGRATION:
        return _classify_organization_integration_change(change)
    if record_type == SENTRY_REPOSITORY:
        return _classify_repository_change(change)
    if record_type == SENTRY_CODE_MAPPING:
        return _classify_code_mapping_change(change)
    if record_type == SENTRY_OWNERSHIP_RULE:
        return _classify_ownership_rule_change(change)
    if record_type == SENTRY_PRIVILEGED_MEMBER:
        return _classify_privileged_member_change(change)
    if record_type == SENTRY_PRIVILEGED_TEAM:
        return _classify_privileged_team_change(change)
    if record_type == SENTRY_ROUTING_CONTEXT:
        return _classify_routing_context_change(change)
    return "low", "A Sentry configuration field changed."
