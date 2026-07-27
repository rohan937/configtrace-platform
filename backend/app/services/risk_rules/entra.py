"""Microsoft Entra ID risk classification rules — foundation only (Entra
message 1 of 8).

This module exists to give every ``entra_*`` record type a dedicated,
correct classifier so that ``risk_service.classify_change()`` never falls
through to the unrelated Cloudflare DNS default classifier.

This is intentionally NOT a Security Finding taxonomy — that is message 6.
Classification here is deliberately structural, not incident-level:

- A tenant organization metadata change is informational to medium.
- A capability probe losing access is an informational/medium diagnostic
  signal, never a "security incident" — permission changes are common and
  expected (e.g. an app registration's assigned application permissions
  being intentionally re-scoped), not proof of compromise.
"""

from __future__ import annotations

from typing import Any

from app.connectors.entra_schema import CAPABILITY_AVAILABLE, ENTRA_API_CAPABILITY, ENTRA_ORGANIZATION


def _get(obj: Any, field: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _classify_organization_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Microsoft Entra ID tenant was added to monitoring."
    if ct == "removed":
        return (
            "medium",
            "A Microsoft Entra ID tenant is no longer visible to ConfigTrace. "
            "Verify the integration still has a valid app registration credential.",
        )

    fp = (_get(change, "field_path") or "").lower()
    if fp in ("display_name", "default_verified_domain"):
        return "low", "The Microsoft Entra ID tenant's identifying metadata changed."
    if fp == "on_premises_sync_enabled_category":
        return (
            "medium",
            "The Microsoft Entra ID tenant's on-premises directory sync "
            "posture changed. Verify this is expected.",
        )
    return "low", "A Microsoft Entra ID tenant configuration field changed."


def _classify_api_capability_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Microsoft Graph API capability probe was recorded."
    if ct == "removed":
        return "low", "A Microsoft Graph API capability probe is no longer recorded."

    fp = (_get(change, "field_path") or "").lower()
    if fp == "status":
        nv = _get(change, "new_value")
        pv = _get(change, "prev_value")
        if pv == CAPABILITY_AVAILABLE and nv != CAPABILITY_AVAILABLE:
            return (
                "medium",
                "ConfigTrace's Microsoft Entra ID app registration lost read "
                "access to a previously available Microsoft Graph API family. "
                "Review the app registration's assigned application "
                "permissions if this was not expected.",
            )
        if pv != CAPABILITY_AVAILABLE and nv == CAPABILITY_AVAILABLE:
            return "low", "ConfigTrace's Microsoft Entra ID app registration gained read access to an API family."
        return "low", "A Microsoft Graph API capability probe's status changed."
    return "low", "A Microsoft Entra ID API capability record changed."


def classify_entra_change(change: object) -> tuple[str, str]:
    """Route an Entra Change to its record-type classifier.

    Unknown/future ``entra_*`` record types (i.e. any later-message planned
    taxonomy, before their classifiers exist) fail safely into a generic
    low-severity message rather than raising or falling through to an
    unrelated provider's classifier.
    """
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    record_type = (pm.get("record_type") or "").lower()

    if record_type == ENTRA_ORGANIZATION:
        return _classify_organization_change(change)
    if record_type == ENTRA_API_CAPABILITY:
        return _classify_api_capability_change(change)

    return "low", f"A Microsoft Entra ID configuration record changed ({record_type or 'unknown record type'})."
