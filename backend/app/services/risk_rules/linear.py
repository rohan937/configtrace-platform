"""Linear drift risk classification rules.

Entry point: ``classify_linear_change(change)``

Classifies drift changes for Linear configuration records. Built during the
Linear detection QA pass — this module previously did not exist, so every
Linear change silently fell through to the Cloudflare DNS classifier
fallback in ``risk_service.py``.

Risk levels
-----------
high   — webhook secret indicator removed; webhook URL scheme changed to
         non-HTTPS.

medium — team visibility broadened (private → not private); project lost
         all team scope or lead presence; label lost team scope; webhook
         disabled, has no resource types, resource-type scope broadens, or
         gains comment-type scope; integration disabled; workspace/team
         lost its only completed-category workflow state.

low    — count-only changes with unclear impact; metadata-only drift;
         unknown/missing category fields; safe restoration/improvement
         transitions (e.g. a webhook secret added, HTTPS restored, a team
         made private again).

Claim discipline
----------------
All reason strings use safe review-framing:
  "Linear configuration evidence may require review."
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


# ── linear_workspace ────────────────────────────────────────────────────────────


def _classify_workspace_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Linear workspace configuration record was added or removed during sync.")

    if fp == "webhook_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return (
                "low",
                "Linear workspace webhook count dropped to zero.",
            )
        return ("low", f"Linear workspace webhook count changed from {n_old} to {n_new}.")

    if fp == "integration_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return ("low", "Linear workspace integration count dropped to zero.")
        return ("low", f"Linear workspace integration count changed from {n_old} to {n_new}.")

    return ("low", f"Linear workspace configuration field '{fp}' changed.")


# ── linear_team ──────────────────────────────────────────────────────────────────


def _classify_team_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Linear team configuration record was added or removed during sync.")

    if fp == "private_team":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Linear team visibility was broadened — the team is no longer "
                "private. Linear configuration evidence may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Linear team was made private (restricted).")
        return ("low", "Linear team private flag is now unknown or missing.")

    if fp == "has_completed_state":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Linear team no longer has a completed-category workflow state. "
                "Linear configuration evidence may require review.",
            )
        return ("low", "Linear team completed-category workflow state presence changed.")

    if fp in ("project_count", "workflow_state_count", "label_count", "webhook_count"):
        return ("low", f"Linear team {fp.replace('_', ' ')} changed.")

    return ("low", f"Linear team configuration field '{fp}' changed.")


# ── linear_project ───────────────────────────────────────────────────────────────


def _classify_project_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Linear project configuration record was added or removed during sync.")

    if fp == "lead_present":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Linear project lost its lead assignment. "
                "Linear configuration evidence may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Linear project lead was assigned.")
        return ("low", "Linear project lead presence is now unknown or missing.")

    if fp == "team_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return (
                "medium",
                "Linear project lost all team scope. "
                "Linear configuration evidence may require review.",
            )
        return ("low", f"Linear project team count changed from {n_old} to {n_new}.")

    if fp == "project_health_category":
        if new_v == "unhealthy":
            return (
                "medium",
                "Linear project health status changed to unhealthy. "
                "Linear configuration evidence may require review.",
            )
        return ("low", f"Linear project health category changed to {new_v}.")

    return ("low", f"Linear project configuration field '{fp}' changed.")


# ── linear_workflow_state ─────────────────────────────────────────────────────────


def _classify_workflow_state_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()

    if ct in ("added", "removed"):
        return ("low", "Linear workflow state configuration record was added or removed during sync.")

    return ("low", f"Linear workflow state configuration field '{fp}' changed.")


# ── linear_label ─────────────────────────────────────────────────────────────────


def _classify_label_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Linear label configuration record was added or removed during sync.")

    if fp == "team_id":
        if new_v is None:
            return (
                "medium",
                "Linear label lost its team scope — it is now workspace-wide. "
                "Linear configuration evidence may require review.",
            )
        return ("low", "Linear label team scope changed.")

    return ("low", f"Linear label configuration field '{fp}' changed.")


# ── linear_webhook ───────────────────────────────────────────────────────────────


def _classify_webhook_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("medium", "A new Linear webhook was added. Linear configuration evidence may require review.")
    if ct == "removed":
        return ("low", "A Linear webhook was removed.")

    if fp == "webhook_enabled":
        if _is_falsy_explicit(new_v):
            return ("medium", "Linear webhook was disabled. Linear configuration evidence may require review.")
        if _is_truthy(new_v):
            return ("low", "Linear webhook was enabled.")
        return ("low", "Linear webhook enabled state is now unknown or missing.")

    if fp == "webhook_secret_present":
        if _is_falsy_explicit(new_v):
            return (
                "high",
                "Linear webhook secret indicator was removed. "
                "Linear configuration evidence may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Linear webhook secret indicator was added.")
        return ("low", "Linear webhook secret presence is now unknown or missing.")

    if fp == "webhook_url_scheme_category":
        if new_v == "https":
            return ("low", "Linear webhook URL scheme changed to HTTPS.")
        if new_v == "non_https":
            return (
                "high",
                "Linear webhook URL scheme changed to a non-HTTPS scheme. "
                "Linear configuration evidence may require review.",
            )
        return ("low", "Linear webhook URL scheme is now unknown or missing.")

    if fp == "webhook_resource_types_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0:
            return (
                "medium",
                "Linear webhook resource type scope dropped to zero. "
                "Linear configuration evidence may require review.",
            )
        if n_new > n_old:
            return (
                "medium",
                f"Linear webhook resource type scope increased from {n_old} to {n_new}. "
                "Linear configuration evidence may require review.",
            )
        return ("low", f"Linear webhook resource type count changed from {n_old} to {n_new}.")

    if fp == "webhook_has_comment_type":
        if _is_truthy(new_v):
            return (
                "medium",
                "Linear webhook gained comment-type event scope. "
                "Linear configuration evidence may require review.",
            )
        return ("low", "Linear webhook comment-type event scope changed.")

    if fp == "webhook_has_attachment_type":
        return ("low", "Linear webhook attachment-type event scope changed.")

    return ("low", f"Linear webhook field '{fp}' changed.")


# ── linear_view ──────────────────────────────────────────────────────────────────


def _classify_view_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Linear view configuration record was added or removed during sync.")

    if fp == "view_shared":
        if _is_truthy(new_v):
            return (
                "low",
                "Linear view was shared. Linear configuration evidence may require review.",
            )
        return ("low", "Linear view sharing was disabled (restricted).")

    return ("low", f"Linear view configuration field '{fp}' changed.")


# ── linear_cycle ─────────────────────────────────────────────────────────────────


def _classify_cycle_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()

    if ct == "added":
        return ("low", "A new Linear cycle became active.")
    if ct == "removed":
        return ("low", "A Linear cycle is no longer active.")

    return ("low", f"Linear cycle configuration field '{fp}' changed.")


# ── linear_integration ───────────────────────────────────────────────────────────


def _classify_integration_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Linear integration configuration record was added or removed during sync.")

    if fp == "integration_enabled":
        if _is_falsy_explicit(new_v):
            return ("medium", "Linear integration was disabled. Linear configuration evidence may require review.")
        if _is_truthy(new_v):
            return ("low", "Linear integration was enabled.")
        return ("low", "Linear integration enabled state is now unknown or missing.")

    if fp == "team_id":
        if new_v is None:
            return ("low", "Linear integration is now workspace-scoped (no team restriction).")
        return ("low", "Linear integration team scope changed.")

    return ("low", f"Linear integration field '{fp}' changed.")


# ── Main dispatcher ───────────────────────────────────────────────────────────


def classify_linear_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for a Linear configuration change.

    Dispatches on ``provider_metadata["record_type"]``:
      * ``linear_workspace``      → workspace posture rules
      * ``linear_team``           → team visibility/posture rules
      * ``linear_project``        → project posture rules
      * ``linear_workflow_state`` → workflow state rules
      * ``linear_label``          → label scope rules
      * ``linear_webhook``        → webhook transport/scope rules
      * ``linear_view``           → view sharing rules
      * ``linear_cycle``          → cycle rules
      * ``linear_integration``    → integration posture rules

    Does not confirm breach, compromise, or unauthorized access.
    Linear configuration evidence may require review.
    """
    pm = _get(change, "provider_metadata") or {}
    if isinstance(pm, dict):
        record_type = (pm.get("record_type") or "").lower()
    else:
        record_type = ""

    if record_type == "linear_workspace":
        return _classify_workspace_change(change)
    if record_type == "linear_team":
        return _classify_team_change(change)
    if record_type == "linear_project":
        return _classify_project_change(change)
    if record_type == "linear_workflow_state":
        return _classify_workflow_state_change(change)
    if record_type == "linear_label":
        return _classify_label_change(change)
    if record_type == "linear_webhook":
        return _classify_webhook_change(change)
    if record_type == "linear_view":
        return _classify_view_change(change)
    if record_type == "linear_cycle":
        return _classify_cycle_change(change)
    if record_type == "linear_integration":
        return _classify_integration_change(change)

    # Fallback for unknown linear_ subtypes
    return (
        "low",
        f"Linear configuration changed (record type: {record_type or 'unknown'}). "
        "Linear configuration evidence may require review.",
    )
