"""PagerDuty drift risk classification rules.

Entry point: ``classify_pagerduty_change(change)``

Classifies drift changes for PagerDuty configuration records. Built during
the PagerDuty detection QA pass — this module previously did not exist, so
every PagerDuty change silently fell through to the Cloudflare DNS
classifier fallback in ``risk_service.py``.

Risk levels
-----------
high   — service lost its escalation policy linkage; escalation policy or
         schedule dropped to zero targets/on-call users; response play
         dropped to zero responders; webhook URL scheme changed to HTTP.

medium — timeout/ack/auto-resolve disabled; integration key or routing key
         missing; webhook disabled, has no events, gains account-wide
         scope, or loses its custom-headers (signing) indicator;
         escalation/schedule/orchestration/response-play counts drop to a
         low-but-nonzero level; escalation policy single-level; schedule
         single-layer with no coverage; response play becomes not
         runnable.

low    — count-only changes with unclear impact; metadata-only drift;
         unknown/missing category fields; safe restoration/improvement
         transitions (e.g. an escalation policy reassigned to a service,
         HTTPS restored, a webhook re-enabled).

Claim discipline
----------------
All reason strings use safe review-framing:
  "PagerDuty configuration evidence may require review."
  "may require review"
  "does not confirm"
Forbidden phrases: breach, compromise, attacker, leaked, unauthorized access,
exfiltration, stolen, fraud, attack, incident exposed, alert exposed, secret
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


# ── pagerduty_service ───────────────────────────────────────────────────────────


def _classify_service_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "PagerDuty service configuration record was added or removed during sync.")

    if fp == "escalation_policy_id":
        if not new_v:
            return (
                "high",
                "PagerDuty service lost its escalation policy linkage — response "
                "routing for this service may no longer be defined. "
                "PagerDuty configuration evidence may require review.",
            )
        if not prev_v:
            return ("low", "PagerDuty service was assigned an escalation policy.")
        return (
            "medium",
            "PagerDuty service response routing changed — its escalation policy "
            "linkage was reassigned. PagerDuty configuration evidence may require review.",
        )

    if fp == "acknowledgement_timeout_category":
        if new_v == "disabled":
            return (
                "medium",
                "PagerDuty service acknowledgement timeout was disabled. "
                "PagerDuty configuration evidence may require review.",
            )
        if prev_v == "disabled":
            return ("low", "PagerDuty service acknowledgement timeout was enabled (restored).")
        return ("low", f"PagerDuty service acknowledgement timeout category changed to {new_v}.")

    if fp == "auto_resolve_timeout_category":
        if new_v == "disabled":
            return (
                "medium",
                "PagerDuty service auto-resolve timeout was disabled. "
                "PagerDuty configuration evidence may require review.",
            )
        if prev_v == "disabled":
            return ("low", "PagerDuty service auto-resolve timeout was enabled (restored).")
        return ("low", f"PagerDuty service auto-resolve timeout category changed to {new_v}.")

    if fp == "alert_creation_category":
        if new_v == "incidents_only":
            return ("low", "PagerDuty service alert creation is now limited to incidents only.")
        return ("low", f"PagerDuty service alert creation category changed to {new_v}.")

    if fp == "integration_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return ("medium", "PagerDuty service integration count dropped to zero. PagerDuty configuration evidence may require review.")
        return ("low", f"PagerDuty service integration count changed from {n_old} to {n_new}.")

    if fp == "team_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return ("low", "PagerDuty service team count dropped to zero.")
        return ("low", f"PagerDuty service team count changed from {n_old} to {n_new}.")

    return ("low", f"PagerDuty service configuration field '{fp}' changed.")


# ── pagerduty_escalation_policy ─────────────────────────────────────────────────


def _classify_escalation_policy_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "PagerDuty escalation policy configuration record was added or removed during sync.")

    if fp == "escalation_rule_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return (
                "high",
                "PagerDuty escalation policy dropped to zero escalation rules — "
                "this policy may no longer route to any responder. "
                "PagerDuty configuration evidence may require review.",
            )
        return ("low", f"PagerDuty escalation policy rule count changed from {n_old} to {n_new}.")

    if fp == "target_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return (
                "high",
                "PagerDuty escalation policy lost all escalation targets. "
                "PagerDuty configuration evidence may require review.",
            )
        if n_new > 0 and n_new < n_old:
            return (
                "medium",
                f"PagerDuty escalation policy target count decreased from {n_old} to {n_new}. "
                "PagerDuty configuration evidence may require review.",
            )
        return ("low", f"PagerDuty escalation policy target count changed from {n_old} to {n_new}.")

    if fp == "escalation_level_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 1 and n_old > 1:
            return (
                "medium",
                "PagerDuty escalation policy dropped to a single escalation level. "
                "PagerDuty configuration evidence may require review.",
            )
        return ("low", f"PagerDuty escalation policy level count changed from {n_old} to {n_new}.")

    if fp == "has_schedule_targets":
        if _is_falsy_explicit(new_v):
            return ("low", "PagerDuty escalation policy no longer has schedule-based targets.")
        if _is_truthy(new_v):
            return ("low", "PagerDuty escalation policy gained a schedule-based target.")
        return ("low", "PagerDuty escalation policy schedule-target presence is now unknown or missing.")

    if fp == "team_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return ("low", "PagerDuty escalation policy team count dropped to zero.")
        return ("low", f"PagerDuty escalation policy team count changed from {n_old} to {n_new}.")

    return ("low", f"PagerDuty escalation policy field '{fp}' changed.")


# ── pagerduty_schedule ───────────────────────────────────────────────────────────


def _classify_schedule_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "PagerDuty schedule configuration record was added or removed during sync.")

    if fp == "user_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return (
                "high",
                "PagerDuty schedule dropped to zero on-call users — coverage "
                "may no longer be defined for this schedule. "
                "PagerDuty configuration evidence may require review.",
            )
        if n_new > 0 and n_new < n_old:
            return (
                "medium",
                f"PagerDuty schedule on-call coverage decreased from {n_old} to {n_new} users. "
                "PagerDuty configuration evidence may require review.",
            )
        return ("low", f"PagerDuty schedule user count changed from {n_old} to {n_new}.")

    if fp == "layer_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return (
                "medium",
                "PagerDuty schedule dropped to zero layers. "
                "PagerDuty configuration evidence may require review.",
            )
        return ("low", f"PagerDuty schedule layer count changed from {n_old} to {n_new}.")

    if fp == "team_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return ("low", "PagerDuty schedule team count dropped to zero.")
        return ("low", f"PagerDuty schedule team count changed from {n_old} to {n_new}.")

    if fp == "has_restrictions":
        return ("low", "PagerDuty schedule time-window restriction presence changed.")

    return ("low", f"PagerDuty schedule field '{fp}' changed.")


# ── pagerduty_service_integration ────────────────────────────────────────────────


def _classify_service_integration_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "PagerDuty service integration record was added or removed during sync.")

    if fp == "has_integration_key":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "PagerDuty service integration lost its integration key indicator. "
                "PagerDuty configuration evidence may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "PagerDuty service integration key indicator was added.")
        return ("low", "PagerDuty service integration key presence is now unknown or missing.")

    if fp == "routing_key_present":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "PagerDuty service integration lost its routing key indicator. "
                "PagerDuty configuration evidence may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "PagerDuty service integration routing key indicator was added.")
        return ("low", "PagerDuty service integration routing key presence is now unknown or missing.")

    return ("low", f"PagerDuty service integration field '{fp}' changed.")


# ── pagerduty_webhook_subscription ──────────────────────────────────────────────


def _classify_webhook_subscription_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("medium", "A new PagerDuty webhook subscription was added. PagerDuty configuration evidence may require review.")
    if ct == "removed":
        return ("low", "A PagerDuty webhook subscription was removed.")

    if fp == "active":
        if _is_falsy_explicit(new_v):
            return ("medium", "PagerDuty webhook subscription was disabled. PagerDuty configuration evidence may require review.")
        if _is_truthy(new_v):
            return ("low", "PagerDuty webhook subscription was enabled.")
        return ("low", "PagerDuty webhook subscription active state is now unknown or missing.")

    if fp == "delivery_url_scheme_category":
        if new_v == "http":
            return (
                "high",
                "PagerDuty webhook delivery URL scheme changed to HTTP (non-encrypted). "
                "PagerDuty configuration evidence may require review.",
            )
        if new_v == "https":
            return ("low", "PagerDuty webhook delivery URL scheme changed to HTTPS.")
        return ("low", "PagerDuty webhook delivery URL scheme is now unknown or missing.")

    if fp == "has_custom_headers":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "PagerDuty webhook lost its custom-header (signing) indicator. "
                "PagerDuty webhook posture may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "PagerDuty webhook custom-header indicator was added.")
        return ("low", "PagerDuty webhook custom-header presence is now unknown or missing.")

    if fp == "filter_type":
        if new_v == "account":
            return (
                "medium",
                "PagerDuty webhook subscription scope changed to account-wide. "
                "PagerDuty webhook posture may require review.",
            )
        return ("low", f"PagerDuty webhook subscription filter scope changed to {new_v}.")

    if fp == "event_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0:
            return (
                "medium",
                "PagerDuty webhook subscription event count dropped to zero. "
                "PagerDuty configuration evidence may require review.",
            )
        return ("low", f"PagerDuty webhook subscription event count changed from {n_old} to {n_new}.")

    return ("low", f"PagerDuty webhook subscription field '{fp}' changed.")


# ── pagerduty_event_orchestration ───────────────────────────────────────────────


def _classify_event_orchestration_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "PagerDuty event orchestration record was added or removed during sync.")

    if fp == "route_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return (
                "medium",
                "PagerDuty event orchestration dropped to zero routes. "
                "PagerDuty configuration evidence may require review.",
            )
        return ("low", f"PagerDuty event orchestration route count changed from {n_old} to {n_new}.")

    if fp == "team_present":
        return ("low", "PagerDuty event orchestration team assignment changed.")

    return ("low", f"PagerDuty event orchestration field '{fp}' changed.")


# ── pagerduty_business_service ──────────────────────────────────────────────────


def _classify_business_service_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()

    if ct in ("added", "removed"):
        return ("low", "PagerDuty business service record was added or removed during sync.")

    return ("low", f"PagerDuty business service field '{fp}' changed.")


# ── pagerduty_response_play ─────────────────────────────────────────────────────


def _classify_response_play_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "PagerDuty response play record was added or removed during sync.")

    if fp == "responder_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        if n_new == 0 and n_old > 0:
            return (
                "high",
                "PagerDuty response play dropped to zero responders. "
                "PagerDuty configuration evidence may require review.",
            )
        if n_new > 0 and n_new < n_old:
            return (
                "medium",
                f"PagerDuty response play responder count decreased from {n_old} to {n_new}. "
                "PagerDuty configuration evidence may require review.",
            )
        return ("low", f"PagerDuty response play responder count changed from {n_old} to {n_new}.")

    if fp == "runnability":
        if new_v == "unknown":
            return (
                "medium",
                "PagerDuty response play runnability could not be classified. "
                "PagerDuty configuration evidence may require review.",
            )
        return ("low", f"PagerDuty response play runnability changed to {new_v}.")

    if fp == "subscriber_count":
        n_old, n_new = _int_pair(prev_v, new_v)
        return ("low", f"PagerDuty response play subscriber count changed from {n_old} to {n_new}.")

    return ("low", f"PagerDuty response play field '{fp}' changed.")


# ── Main dispatcher ───────────────────────────────────────────────────────────


def classify_pagerduty_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for a PagerDuty configuration change.

    Dispatches on ``provider_metadata["record_type"]``:
      * ``pagerduty_service``              → service posture rules
      * ``pagerduty_escalation_policy``    → escalation policy rules
      * ``pagerduty_schedule``             → schedule/on-call coverage rules
      * ``pagerduty_service_integration``  → integration key posture rules
      * ``pagerduty_webhook_subscription`` → webhook transport/scope rules
      * ``pagerduty_event_orchestration``  → orchestration route rules
      * ``pagerduty_business_service``     → business service rules
      * ``pagerduty_response_play``        → response play rules

    Does not confirm breach, compromise, or unauthorized access.
    PagerDuty configuration evidence may require review.
    """
    pm = _get(change, "provider_metadata") or {}
    if isinstance(pm, dict):
        record_type = (pm.get("record_type") or "").lower()
    else:
        record_type = ""

    if record_type == "pagerduty_service":
        return _classify_service_change(change)
    if record_type == "pagerduty_escalation_policy":
        return _classify_escalation_policy_change(change)
    if record_type == "pagerduty_schedule":
        return _classify_schedule_change(change)
    if record_type == "pagerduty_service_integration":
        return _classify_service_integration_change(change)
    if record_type == "pagerduty_webhook_subscription":
        return _classify_webhook_subscription_change(change)
    if record_type == "pagerduty_event_orchestration":
        return _classify_event_orchestration_change(change)
    if record_type == "pagerduty_business_service":
        return _classify_business_service_change(change)
    if record_type == "pagerduty_response_play":
        return _classify_response_play_change(change)

    # Fallback for unknown pagerduty_ subtypes
    return (
        "low",
        f"PagerDuty configuration changed (record type: {record_type or 'unknown'}). "
        "PagerDuty configuration evidence may require review.",
    )
