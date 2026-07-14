"""Terraform Cloud drift risk classification rules (M88A).

Entry point: ``classify_terraform_cloud_change(change)``

Classifies drift changes for Terraform Cloud configuration records.

Risk levels
-----------
high   — workspace auto_apply changed to true; global_remote_state changed
         to true; notification webhook changed from HTTPS to HTTP or token
         removed; admin/apply/write access count increased materially;
         sensitive variable count decreased while non-sensitive increased.

medium — VCS connection removed from workspace; queue_all_runs disabled;
         speculative planning disabled; run trigger count increased;
         team access count increased; policy set no longer attached (global
         scope removed); enforcement level weakened; variable count increased
         without matching sensitive increase.

low    — Count-only changes with unclear impact; safe enablement;
         metadata-only drift; unknown optional field changes.

Claim discipline
----------------
All reason strings use safe review-framing:
  "Terraform Cloud configuration evidence may require review."
  "may require review"
  "does not confirm"
Forbidden phrases: breach, compromise, attacker, leaked, unauthorized access,
exfiltration, stolen, fraud, attack, secret leaked, token leaked, state leaked,
credentials exposed, infrastructure exposed.
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


def _int_val(val: object) -> int:
    try:
        return int(val)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


# ── terraform_cloud_organization ─────────────────────────────────────────────


def _classify_organization_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return (
            "low",
            "Terraform Cloud organization configuration record was added or removed during sync.",
        )

    if fp == "two_factor_requirement_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "high",
                "Terraform Cloud organization two-factor authentication requirement was disabled. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud organization 2FA requirement was enabled.")

    if fp == "sso_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Terraform Cloud organization SSO was disabled. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud organization SSO was enabled.")

    if fp == "cost_estimation_enabled":
        return ("low", "Terraform Cloud organization cost estimation setting changed.")

    if fp == "collaborator_auth_policy_category":
        if new_v == "password":
            return (
                "medium",
                "Terraform Cloud organization collaborator authentication policy changed "
                "to password-only (two_factor_mandatory was stronger). "
                "Terraform Cloud configuration evidence may require review.",
            )
        return (
            "low",
            "Terraform Cloud organization collaborator authentication policy changed.",
        )

    return (
        "low",
        f"Terraform Cloud organization configuration field '{fp}' changed.",
    )


# ── terraform_cloud_workspace ─────────────────────────────────────────────────


def _classify_workspace_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")
    old_v = _get(change, "prev_value")

    if ct in ("added", "removed"):
        return (
            "low",
            "Terraform Cloud workspace configuration record was added or removed during sync.",
        )

    if fp == "auto_apply":
        if _is_truthy(new_v):
            return (
                "high",
                "Terraform Cloud workspace auto-apply was enabled — runs will apply "
                "automatically without manual confirmation. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace auto-apply was disabled.")

    if fp == "global_remote_state":
        if _is_truthy(new_v):
            return (
                "high",
                "Terraform Cloud workspace global remote state sharing was enabled — "
                "all workspaces in the organization may now access this workspace's "
                "state outputs. Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace global remote state sharing was disabled.")

    if fp == "vcs_connected":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Terraform Cloud workspace VCS connection was removed. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace VCS connection was added.")

    if fp == "execution_mode_category":
        old_s = str(old_v or "").lower()
        new_s = str(new_v or "").lower()
        if old_s == "remote" and new_s in ("local", "agent"):
            return (
                "high",
                f"Terraform Cloud workspace execution mode changed from remote to {new_s}. "
                "Terraform Cloud configuration evidence may require review.",
            )
        if new_s in ("local", "agent") and old_s not in ("local", "agent"):
            return (
                "medium",
                f"Terraform Cloud workspace execution mode changed to {new_s}. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return (
            "low",
            f"Terraform Cloud workspace execution mode changed to {new_s}.",
        )

    if fp == "queue_all_runs":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Terraform Cloud workspace queue-all-runs was disabled. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace queue-all-runs was enabled.")

    if fp == "speculative_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Terraform Cloud workspace speculative planning was disabled. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace speculative planning was enabled.")

    if fp == "run_trigger_count":
        try:
            n_old = int(old_v or 0)
            n_new = int(new_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud workspace run trigger count changed.")
        if n_new > n_old:
            return (
                "medium",
                f"Terraform Cloud workspace run trigger count increased from {n_old} to {n_new}. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace run trigger count decreased.")

    if fp == "team_access_count":
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud workspace team access count changed.")
        if n_new > n_old:
            return (
                "medium",
                f"Terraform Cloud workspace team access count increased from {n_old} to {n_new}. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace team access count decreased.")

    if fp in ("variable_count",):
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud workspace variable count changed.")
        if n_new > n_old:
            return (
                "medium",
                "Terraform Cloud workspace variable count increased. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace variable count decreased.")

    if fp == "sensitive_variable_count":
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud workspace sensitive variable count changed.")
        if n_new < n_old:
            return (
                "high",
                "Terraform Cloud workspace sensitive variable count decreased — "
                "variables may have been re-classified as non-sensitive. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace sensitive variable count increased.")

    if fp == "notification_count":
        return ("low", "Terraform Cloud workspace notification configuration count changed.")

    if fp == "latest_run_status_category":
        return ("low", "Terraform Cloud workspace latest run status category changed.")

    if fp == "terraform_version_category":
        if str(new_v or "").lower() == "latest":
            return (
                "medium",
                "Terraform Cloud workspace Terraform version changed to 'latest' — "
                "uncontrolled version upgrades may occur. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace Terraform version category changed.")

    return (
        "low",
        f"Terraform Cloud workspace configuration field '{fp}' changed.",
    )


# ── terraform_cloud_workspace_variable_summary ────────────────────────────────


def _classify_workspace_variable_summary_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    new_v = _get(change, "new_value")
    old_v = _get(change, "prev_value")

    if fp == "sensitive_variable_count":
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud workspace sensitive variable count changed.")
        if n_new < n_old:
            return (
                "high",
                "Terraform Cloud workspace sensitive variable count decreased — "
                "variables may have been re-classified as non-sensitive. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace sensitive variable count increased.")

    if fp == "unprotected_non_sensitive_count":
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud workspace non-sensitive variable count changed.")
        if n_new > n_old:
            return (
                "medium",
                "Terraform Cloud workspace unprotected non-sensitive environment variable "
                "count increased. Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace unprotected variable count decreased.")

    if fp == "variable_count":
        return ("low", "Terraform Cloud workspace variable count changed.")

    return (
        "low",
        f"Terraform Cloud workspace variable summary field '{fp}' changed.",
    )


# ── terraform_cloud_variable_set ──────────────────────────────────────────────


def _classify_variable_set_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")
    old_v = _get(change, "prev_value")

    if ct in ("added", "removed"):
        return (
            "low",
            "Terraform Cloud variable set record was added or removed during sync.",
        )

    if fp == "global_scope":
        if _is_truthy(new_v):
            return (
                "high",
                "Terraform Cloud variable set scope changed to global — "
                "all workspaces in the organization now inherit these variables. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return (
            "medium",
            "Terraform Cloud variable set global scope was removed. "
            "Terraform Cloud configuration evidence may require review.",
        )

    if fp == "sensitive_variable_count":
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud variable set sensitive variable count changed.")
        if n_new < n_old:
            return (
                "high",
                "Terraform Cloud variable set sensitive variable count decreased — "
                "variables may have been re-classified as non-sensitive. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud variable set sensitive variable count increased.")

    if fp == "workspace_count":
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud variable set workspace count changed.")
        if n_new > n_old:
            return (
                "medium",
                "Terraform Cloud variable set workspace scope increased. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud variable set workspace scope decreased.")

    return (
        "low",
        f"Terraform Cloud variable set field '{fp}' changed.",
    )


# ── terraform_cloud_policy_set ────────────────────────────────────────────────


def _classify_policy_set_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")
    old_v = _get(change, "prev_value")

    if ct in ("added", "removed"):
        return (
            "low",
            "Terraform Cloud policy set record was added or removed during sync.",
        )

    if fp == "global_scope":
        if _is_falsy_explicit(new_v):
            return (
                "high",
                "Terraform Cloud policy set global scope was removed — "
                "workspaces may no longer have this policy enforced. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud policy set was changed to global scope.")

    if fp == "enforcement_level_category":
        old_s = str(old_v or "").lower()
        new_s = str(new_v or "").lower()
        if old_s == "mandatory" and new_s in ("soft_mandatory", "advisory"):
            return (
                "high",
                f"Terraform Cloud policy set enforcement level weakened from mandatory to {new_s}. "
                "Terraform Cloud configuration evidence may require review.",
            )
        if old_s == "soft_mandatory" and new_s == "advisory":
            return (
                "medium",
                "Terraform Cloud policy set enforcement level weakened from soft_mandatory to advisory. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", f"Terraform Cloud policy set enforcement level changed to {new_s}.")

    if fp == "policy_count":
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud policy set policy count changed.")
        if n_new < n_old:
            return (
                "medium",
                "Terraform Cloud policy set policy count decreased. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud policy set policy count increased.")

    if fp == "workspace_count":
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud policy set workspace count changed.")
        if n_new < n_old:
            return (
                "medium",
                "Terraform Cloud policy set workspace scope decreased — "
                "fewer workspaces have this policy enforced. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud policy set workspace scope increased.")

    return (
        "low",
        f"Terraform Cloud policy set field '{fp}' changed.",
    )


# ── terraform_cloud_notification_configuration ────────────────────────────────


def _classify_notification_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return (
            "low",
            "Terraform Cloud notification configuration was added or removed during sync.",
        )

    if fp == "webhook_url_scheme_category":
        if str(new_v or "").lower() == "http":
            return (
                "high",
                "Terraform Cloud notification webhook URL scheme changed to HTTP — "
                "run event payloads may be delivered over an unencrypted connection. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud notification webhook URL scheme changed.")

    if fp == "token_present":
        if _is_falsy_explicit(new_v):
            return (
                "high",
                "Terraform Cloud notification configuration token was removed. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud notification configuration token was added.")

    if fp == "enabled":
        if _is_falsy_explicit(new_v):
            return ("low", "Terraform Cloud notification configuration was disabled.")
        return ("low", "Terraform Cloud notification configuration was enabled.")

    if fp == "trigger_count":
        return ("low", "Terraform Cloud notification trigger count changed.")

    if fp == "destination_type_category":
        return ("low", "Terraform Cloud notification destination type changed.")

    return (
        "low",
        f"Terraform Cloud notification configuration field '{fp}' changed.",
    )


# ── terraform_cloud_team_access_summary ───────────────────────────────────────


def _classify_team_access_summary_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")
    old_v = _get(change, "prev_value")

    if ct in ("added", "removed"):
        return (
            "low",
            "Terraform Cloud team access summary record was added or removed during sync.",
        )

    if fp == "admin_access_count":
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud workspace admin access count changed.")
        if n_new > n_old:
            return (
                "high",
                f"Terraform Cloud workspace admin team access count increased from {n_old} to {n_new}. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace admin access count decreased.")

    if fp in ("write_access_count", "apply_access_count"):
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", f"Terraform Cloud workspace {fp} changed.")
        if n_new > n_old:
            return (
                "high",
                f"Terraform Cloud workspace {fp.replace('_', ' ')} increased from {n_old} to {n_new}. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", f"Terraform Cloud workspace {fp.replace('_', ' ')} decreased.")

    if fp == "team_access_count":
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud workspace team access count changed.")
        if n_new > n_old:
            return (
                "medium",
                "Terraform Cloud workspace total team access count increased. "
                "Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace team access count decreased.")

    if fp == "plan_access_count":
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud workspace plan access count changed.")
        if n_new > n_old:
            return (
                "medium",
                f"Terraform Cloud workspace plan-only team access count increased from "
                f"{n_old} to {n_new}. Terraform Cloud configuration evidence may require review.",
            )
        return ("low", "Terraform Cloud workspace plan access count decreased.")

    if fp == "custom_permission_count":
        try:
            n_new = int(new_v or 0)
            n_old = int(old_v or 0)
        except (TypeError, ValueError):
            return ("low", "Terraform Cloud workspace custom permission count changed.")
        if n_new > n_old:
            return (
                "medium",
                f"Terraform Cloud workspace custom-permission team access count increased "
                f"from {n_old} to {n_new}. Terraform Cloud configuration evidence may "
                "require review.",
            )
        return ("low", "Terraform Cloud workspace custom permission count decreased.")

    if fp == "read_access_count":
        return ("low", "Terraform Cloud workspace read access count changed.")

    return (
        "low",
        f"Terraform Cloud team access field '{fp}' changed.",
    )


# ── terraform_cloud_project ───────────────────────────────────────────────────


def _classify_project_change(change: Change) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()

    if ct in ("added", "removed"):
        return (
            "low",
            "Terraform Cloud project record was added or removed during sync.",
        )

    return (
        "low",
        f"Terraform Cloud project configuration field '{fp}' changed.",
    )


# ── terraform_cloud_run_trigger ───────────────────────────────────────────────


def _classify_run_trigger_change(change: Change) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return (
            "medium",
            "A Terraform Cloud run trigger was added to a workspace. "
            "Terraform Cloud configuration evidence may require review.",
        )
    if ct == "removed":
        return (
            "low",
            "A Terraform Cloud run trigger was removed from a workspace.",
        )
    return ("low", "Terraform Cloud run trigger changed.")


# ── terraform_cloud_state_version_summary ────────────────────────────────────


def _classify_state_version_summary_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    new_v = _get(change, "new_value")
    if fp == "state_version_present":
        if _is_truthy(new_v):
            return ("low", "Terraform Cloud workspace state version is now present.")
        return ("low", "Terraform Cloud workspace no longer has a current state version.")
    return (
        "low",
        f"Terraform Cloud state version summary field '{fp}' changed.",
    )


# ── Main dispatcher ───────────────────────────────────────────────────────────


def classify_terraform_cloud_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for a Terraform Cloud configuration change.

    Dispatches on ``provider_metadata["record_type"]``:
      * ``terraform_cloud_organization``               → organization-level rules
      * ``terraform_cloud_workspace``                  → workspace posture rules
      * ``terraform_cloud_workspace_variable_summary`` → variable count rules
      * ``terraform_cloud_variable_set``               → variable set scope rules
      * ``terraform_cloud_policy_set``                 → policy enforcement rules
      * ``terraform_cloud_notification_configuration`` → notification posture rules
      * ``terraform_cloud_team_access_summary``        → team access level rules
      * ``terraform_cloud_project``                    → project-level rules
      * ``terraform_cloud_run_trigger``                → run trigger rules
      * ``terraform_cloud_state_version_summary``      → state presence rules

    Does not confirm breach, compromise, or unauthorized access.
    Terraform Cloud configuration evidence may require review.
    """
    pm = _get(change, "provider_metadata") or {}
    if isinstance(pm, dict):
        record_type = (pm.get("record_type") or "").lower()
    else:
        record_type = ""

    if record_type == "terraform_cloud_organization":
        return _classify_organization_change(change)
    if record_type == "terraform_cloud_workspace":
        return _classify_workspace_change(change)
    if record_type == "terraform_cloud_workspace_variable_summary":
        return _classify_workspace_variable_summary_change(change)
    if record_type == "terraform_cloud_variable_set":
        return _classify_variable_set_change(change)
    if record_type == "terraform_cloud_policy_set":
        return _classify_policy_set_change(change)
    if record_type == "terraform_cloud_notification_configuration":
        return _classify_notification_change(change)
    if record_type == "terraform_cloud_team_access_summary":
        return _classify_team_access_summary_change(change)
    if record_type == "terraform_cloud_project":
        return _classify_project_change(change)
    if record_type == "terraform_cloud_run_trigger":
        return _classify_run_trigger_change(change)
    if record_type == "terraform_cloud_state_version_summary":
        return _classify_state_version_summary_change(change)

    # Fallback for unknown terraform_cloud_ subtypes
    return (
        "low",
        f"Terraform Cloud configuration changed (record type: {record_type or 'unknown'}). "
        "Terraform Cloud configuration evidence may require review.",
    )
