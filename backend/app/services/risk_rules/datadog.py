"""Datadog drift risk classification rules.

Entry point: ``classify_datadog_change(change)``

Classifies drift changes for Datadog configuration records. Built during
the Datadog detection QA pass — this module previously did not exist, so
every Datadog change silently fell through to the Cloudflare DNS
classifier fallback in ``risk_service.py``.

Risk levels
-----------
high   — webhook secret header indicator removed; webhook URL scheme
         changed to HTTP.

medium — monitor disabled; monitor loses notification routing, gains a
         wildcard-scope query, gains silenced scopes, or loses its warning
         threshold; dashboard gains a public URL; role permission count or
         application key scope count crosses the review threshold; webhook
         gains authentication-material headers; cloud integration gains
         log collection; notification integration disabled.

low    — count-only changes with unclear impact; metadata-only drift;
         unknown/missing category fields; safe restoration/improvement
         transitions (e.g. a monitor re-enabled, HTTPS restored, a webhook
         secret header added, a dashboard's public URL revoked).

Claim discipline
----------------
All reason strings use safe review-framing:
  "Datadog configuration evidence may require review."
  "may require review"
  "does not confirm"
Forbidden phrases: breach, compromise, attacker, leaked, unauthorized access,
exfiltration, stolen, fraud, attack, log exposed, dashboard exposed, secret
exposed, data exposed.
"""

from __future__ import annotations

from typing import Optional

from app.models.change import Change

# Thresholds mirrored from security_rules/datadog.py so Change severities
# stay aligned with the corresponding Security Findings.
_BROAD_SCOPES_THRESHOLD = 10
_HIGH_PERMISSION_THRESHOLD = 25
_BROAD_GROUP_BY_THRESHOLD = 3


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


def _int_or_none(val: object) -> Optional[int]:
    """Coerce to int, but return None (not 0) for missing/unparseable values.

    A count that is genuinely unknown/missing must never be silently
    treated as an explicit ``0`` or as crossing a threshold — doing so
    would let an unknown transition falsely trigger a finding.
    """
    if isinstance(val, bool) or val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


# ── datadog_monitor ──────────────────────────────────────────────────────────


def _classify_monitor_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Datadog monitor configuration record was added or removed during sync.")

    if fp == "enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Datadog monitor alerting posture changed — the monitor was disabled. "
                "Datadog configuration evidence may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Datadog monitor was re-enabled.")
        return ("low", "Datadog monitor enabled state is now unknown or missing.")

    if fp == "notification_routing_present":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Datadog monitor lost its notification routing — alerts from this "
                "monitor may no longer reach a destination. Datadog configuration "
                "evidence may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Datadog monitor gained notification routing.")
        return ("low", "Datadog monitor notification routing presence is now unknown or missing.")

    if fp == "query_uses_wildcard_scope":
        if _is_truthy(new_v):
            return (
                "medium",
                "Datadog monitor query scope was broadened to a wildcard. "
                "Datadog configuration evidence may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Datadog monitor query scope was narrowed from wildcard.")
        return ("low", "Datadog monitor wildcard scope state is now unknown or missing.")

    if fp == "silenced_scope_count":
        n_old = _int_or_none(prev_v)
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Datadog monitor silenced scope count is now unknown or missing.")
        if n_new > (n_old or 0):
            return (
                "medium",
                f"Datadog monitor silenced scope count increased from {n_old} to {n_new}. "
                "Datadog configuration evidence may require review.",
            )
        return ("low", f"Datadog monitor silenced scope count changed from {n_old} to {n_new}.")

    if fp == "threshold_warning_present":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Datadog monitor alerting posture changed — its warning threshold "
                "was removed. Datadog configuration evidence may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Datadog monitor warning threshold was added.")
        return ("low", "Datadog monitor warning threshold presence is now unknown or missing.")

    if fp == "threshold_recovery_present":
        if _is_falsy_explicit(new_v):
            return ("low", "Datadog monitor recovery threshold was removed.")
        if _is_truthy(new_v):
            return ("low", "Datadog monitor recovery threshold was added.")
        return ("low", "Datadog monitor recovery threshold presence is now unknown or missing.")

    if fp == "notify_no_data":
        if _is_falsy_explicit(new_v):
            return ("low", "Datadog monitor no-data notification was disabled.")
        if _is_truthy(new_v):
            return ("low", "Datadog monitor no-data notification was enabled.")
        return ("low", "Datadog monitor no-data notification state is now unknown or missing.")

    if fp == "notify_audit":
        return ("low", "Datadog monitor audit notification setting changed.")

    if fp == "require_full_window":
        return ("low", "Datadog monitor evaluation window requirement changed.")

    if fp == "restricted_roles_count":
        n_old = _int_or_none(prev_v)
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Datadog monitor restricted role count is now unknown or missing.")
        if n_new == 0 and (n_old or 0) > 0:
            return ("low", "Datadog monitor restricted role count dropped to zero.")
        return ("low", f"Datadog monitor restricted role count changed from {n_old} to {n_new}.")

    if fp == "query_complexity_category":
        if new_v == "long":
            return ("low", "Datadog monitor query complexity is now classified as long.")
        return ("low", f"Datadog monitor query complexity category changed to {new_v}.")

    if fp == "no_data_timeframe_category":
        if new_v == "extended":
            return ("low", "Datadog monitor no-data timeframe is now classified as extended.")
        return ("low", f"Datadog monitor no-data timeframe category changed to {new_v}.")

    if fp == "query_group_by_count":
        n_old = _int_or_none(prev_v)
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Datadog monitor group-by count is now unknown or missing.")
        if n_new >= _BROAD_GROUP_BY_THRESHOLD and (n_old or 0) < _BROAD_GROUP_BY_THRESHOLD:
            return (
                "low",
                f"Datadog monitor group-by count increased from {n_old} to {n_new}, "
                "crossing the broad-scope review threshold.",
            )
        return ("low", f"Datadog monitor group-by count changed from {n_old} to {n_new}.")

    return ("low", f"Datadog monitor configuration field '{fp}' changed.")


# ── datadog_slo ──────────────────────────────────────────────────────────────


def _classify_slo_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Datadog SLO configuration record was added or removed during sync.")

    if fp == "monitor_count":
        n_old = _int_or_none(prev_v)
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Datadog SLO monitor count is now unknown or missing.")
        if n_new == 0 and (n_old or 0) > 0:
            return (
                "medium",
                "Datadog SLO lost all linked monitors. "
                "Datadog configuration evidence may require review.",
            )
        return ("low", f"Datadog SLO monitor count changed from {n_old} to {n_new}.")

    if fp == "target_category":
        if new_v == "below_95":
            return ("low", "Datadog SLO target category dropped below 95%.")
        return ("low", f"Datadog SLO target category changed to {new_v}.")

    return ("low", f"Datadog SLO field '{fp}' changed.")


# ── datadog_dashboard ────────────────────────────────────────────────────────


def _classify_dashboard_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Datadog dashboard configuration record was added or removed during sync.")

    if fp == "public_url_present":
        if _is_truthy(new_v):
            return (
                "medium",
                "Datadog dashboard sharing posture changed — a public URL is now "
                "present. Datadog configuration evidence may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Datadog dashboard public URL was revoked (restricted).")
        return ("low", "Datadog dashboard public URL presence is now unknown or missing.")

    if fp == "restricted_roles_count":
        n_old = _int_or_none(prev_v)
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Datadog dashboard restricted role count is now unknown or missing.")
        if n_new == 0 and (n_old or 0) > 0:
            return ("low", "Datadog dashboard restricted role count dropped to zero.")
        return ("low", f"Datadog dashboard restricted role count changed from {n_old} to {n_new}.")

    return ("low", f"Datadog dashboard field '{fp}' changed.")


# ── datadog_webhook_integration ──────────────────────────────────────────────


def _classify_webhook_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("medium", "A new Datadog webhook integration was added. Datadog configuration evidence may require review.")
    if ct == "removed":
        return ("low", "A Datadog webhook integration was removed.")

    if fp == "url_scheme_category":
        if new_v == "http":
            return (
                "high",
                "Datadog webhook posture may require review — the endpoint URL scheme "
                "changed to HTTP (non-encrypted).",
            )
        if new_v == "https":
            return ("low", "Datadog webhook endpoint URL scheme changed to HTTPS.")
        return ("low", "Datadog webhook endpoint URL scheme is now unknown or missing.")

    if fp == "secret_headers_present":
        if _is_falsy_explicit(new_v):
            return (
                "high",
                "Datadog webhook posture may require review — its secret header "
                "indicator was removed.",
            )
        if _is_truthy(new_v):
            return ("low", "Datadog webhook secret header indicator was added.")
        return ("low", "Datadog webhook secret header presence is now unknown or missing.")

    if fp == "auth_material_present":
        if _is_truthy(new_v):
            return (
                "medium",
                "Datadog webhook configuration now includes authentication-material "
                "headers. Datadog configuration evidence may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Datadog webhook authentication-material header indicator was removed.")
        return ("low", "Datadog webhook authentication-material presence is now unknown or missing.")

    if fp == "payload_template_present":
        if _is_truthy(new_v):
            return ("low", "Datadog webhook gained a custom payload template.")
        return ("low", "Datadog webhook custom payload template presence changed.")

    if fp == "payload_template_length_category":
        if new_v == "long":
            return ("low", "Datadog webhook payload template is now classified as long.")
        return ("low", f"Datadog webhook payload template length category changed to {new_v}.")

    if fp == "custom_headers_present":
        return ("low", "Datadog webhook custom header presence changed.")

    return ("low", f"Datadog webhook field '{fp}' changed.")


# ── datadog_notification_integration ─────────────────────────────────────────


def _classify_notification_integration_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Datadog notification integration record was added or removed during sync.")

    if fp == "enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Datadog integration posture changed — this notification integration "
                "was disabled. Datadog configuration evidence may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Datadog notification integration was enabled.")
        return ("low", "Datadog notification integration enabled state is now unknown or missing.")

    if fp in ("handle_count", "channel_count"):
        n_old = _int_or_none(prev_v)
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", f"Datadog notification integration {fp} is now unknown or missing.")
        if n_new == 0 and (n_old or 0) > 0:
            return ("low", f"Datadog notification integration {fp.replace('_', ' ')} dropped to zero.")
        return ("low", f"Datadog notification integration {fp} changed from {n_old} to {n_new}.")

    return ("low", f"Datadog notification integration field '{fp}' changed.")


# ── datadog_api_key_metadata ─────────────────────────────────────────────────


def _classify_api_key_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Datadog API key metadata record was added or removed during sync.")

    if fp == "disabled":
        if _is_truthy(new_v):
            return ("low", "Datadog key metadata changed — the API key was disabled.")
        if _is_falsy_explicit(new_v):
            return ("low", "Datadog API key was re-enabled.")
        return ("low", "Datadog API key disabled state is now unknown or missing.")

    return ("low", f"Datadog API key metadata field '{fp}' changed.")


# ── datadog_application_key_metadata ─────────────────────────────────────────


def _classify_application_key_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Datadog application key metadata record was added or removed during sync.")

    if fp == "scopes_count":
        n_old = _int_or_none(prev_v)
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Datadog application key scope count is now unknown or missing.")
        if n_new > _BROAD_SCOPES_THRESHOLD and n_new > (n_old or 0):
            return (
                "medium",
                f"Datadog key metadata changed — application key scope count increased "
                f"from {n_old} to {n_new}, exceeding the broad-scope review threshold. "
                "Datadog configuration evidence may require review.",
            )
        if n_old is not None and n_new < n_old:
            return ("low", f"Datadog application key scope count decreased from {n_old} to {n_new}.")
        return ("low", f"Datadog application key scope count changed from {n_old} to {n_new}.")

    return ("low", f"Datadog application key metadata field '{fp}' changed.")


# ── datadog_role ─────────────────────────────────────────────────────────────


def _classify_role_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Datadog role configuration record was added or removed during sync.")

    if fp == "permission_count":
        n_old = _int_or_none(prev_v)
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Datadog role permission count is now unknown or missing.")
        if n_new > _HIGH_PERMISSION_THRESHOLD and n_new > (n_old or 0):
            return (
                "medium",
                f"Datadog role permission count increased from {n_old} to {n_new}, "
                "exceeding the broad-access review threshold. Datadog configuration "
                "evidence may require review.",
            )
        if n_old is not None and n_new < n_old:
            return ("low", f"Datadog role permission count decreased from {n_old} to {n_new}.")
        return ("low", f"Datadog role permission count changed from {n_old} to {n_new}.")

    if fp in ("user_count", "team_count"):
        return ("low", f"Datadog role {fp.replace('_', ' ')} changed.")

    return ("low", f"Datadog role field '{fp}' changed.")


# ── datadog_team ─────────────────────────────────────────────────────────────


def _classify_team_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Datadog team configuration record was added or removed during sync.")

    if fp == "member_count":
        n_old = _int_or_none(prev_v)
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Datadog team member count is now unknown or missing.")
        if n_new == 0 and (n_old or 0) > 0:
            return ("low", "Datadog team member count dropped to zero.")
        return ("low", f"Datadog team member count changed from {n_old} to {n_new}.")

    return ("low", f"Datadog team field '{fp}' changed.")


# ── datadog_cloud_integration ─────────────────────────────────────────────────


def _classify_cloud_integration_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Datadog cloud integration record was added or removed during sync.")

    if fp == "log_collection_enabled":
        if _is_truthy(new_v):
            return (
                "medium",
                "Datadog cloud integration gained log collection. "
                "Datadog configuration evidence may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Datadog cloud integration log collection was disabled.")
        return ("low", "Datadog cloud integration log collection state is now unknown or missing.")

    if fp in ("resource_collection_enabled", "metric_collection_enabled"):
        return ("low", f"Datadog cloud integration {fp.replace('_', ' ')} changed.")

    return ("low", f"Datadog cloud integration field '{fp}' changed.")


# ── Main dispatcher ───────────────────────────────────────────────────────────


def classify_datadog_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for a Datadog configuration change.

    Dispatches on ``provider_metadata["record_type"]``:
      * ``datadog_monitor``                  → monitor alerting posture rules
      * ``datadog_slo``                      → SLO posture rules
      * ``datadog_dashboard``                → dashboard sharing rules
      * ``datadog_webhook_integration``      → webhook transport/scope rules
      * ``datadog_notification_integration`` → notification posture rules
      * ``datadog_api_key_metadata``         → API key metadata rules
      * ``datadog_application_key_metadata`` → application key scope rules
      * ``datadog_role``                     → role permission rules
      * ``datadog_team``                     → team membership rules
      * ``datadog_cloud_integration``        → cloud integration rules

    Does not confirm breach, compromise, or unauthorized access.
    Datadog configuration evidence may require review.
    """
    pm = _get(change, "provider_metadata") or {}
    if isinstance(pm, dict):
        record_type = (pm.get("record_type") or "").lower()
    else:
        record_type = ""

    if record_type == "datadog_monitor":
        return _classify_monitor_change(change)
    if record_type == "datadog_slo":
        return _classify_slo_change(change)
    if record_type == "datadog_dashboard":
        return _classify_dashboard_change(change)
    if record_type == "datadog_webhook_integration":
        return _classify_webhook_change(change)
    if record_type == "datadog_notification_integration":
        return _classify_notification_integration_change(change)
    if record_type == "datadog_api_key_metadata":
        return _classify_api_key_change(change)
    if record_type == "datadog_application_key_metadata":
        return _classify_application_key_change(change)
    if record_type == "datadog_role":
        return _classify_role_change(change)
    if record_type == "datadog_team":
        return _classify_team_change(change)
    if record_type == "datadog_cloud_integration":
        return _classify_cloud_integration_change(change)

    # Fallback for unknown datadog_ subtypes
    return (
        "low",
        f"Datadog configuration changed (record type: {record_type or 'unknown'}). "
        "Datadog configuration evidence may require review.",
    )
