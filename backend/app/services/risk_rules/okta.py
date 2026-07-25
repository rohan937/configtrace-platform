"""Okta risk classification rules — foundation only (Okta message 1 of 8).

This module exists to give every ``okta_*`` record type a dedicated,
correct classifier so that ``risk_service.classify_change()`` never falls
through to the unrelated Cloudflare DNS default classifier.

This is intentionally NOT a Security Finding taxonomy — that is message 6.
Message 1 only classifies the two foundation record types:
``okta_organization`` and ``okta_api_capability``. Classification is
deliberately minimal: an org status/tenant posture change is informational
to medium; a capability probe losing access is an informational/medium
diagnostic signal, never a "security incident" — permission changes are
common and expected (e.g. a scoped API token being intentionally
re-scoped), not proof of compromise.
"""

from __future__ import annotations

from typing import Any

from app.connectors.okta_schema import (
    CAPABILITY_AVAILABLE,
    OKTA_API_CAPABILITY,
    OKTA_ORGANIZATION,
    ORG_STATUS_ACTIVE,
)


def _get(obj: Any, field: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _classify_organization_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "An Okta organization was added to monitoring."
    if ct == "removed":
        return (
            "medium",
            "An Okta organization is no longer visible to ConfigTrace. "
            "Verify the integration still has a valid API token.",
        )

    fp = (_get(change, "field_path") or "").lower()
    if fp == "status_category":
        nv = _get(change, "new_value")
        if nv != ORG_STATUS_ACTIVE:
            return (
                "medium",
                f"The Okta organization's status changed to {nv!r}, which is "
                "not 'active'. Verify this is expected.",
            )
        return "low", "The Okta organization's status changed."
    if fp in ("org_hostname", "org_display_name"):
        return "low", "The Okta organization's identifying metadata changed."
    return "low", "An Okta organization configuration field changed."


def _classify_api_capability_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Okta API capability probe was recorded."
    if ct == "removed":
        return "low", "An Okta API capability probe is no longer recorded."

    fp = (_get(change, "field_path") or "").lower()
    if fp == "status":
        nv = _get(change, "new_value")
        pv = _get(change, "prev_value")
        if pv == CAPABILITY_AVAILABLE and nv != CAPABILITY_AVAILABLE:
            return (
                "medium",
                "ConfigTrace's Okta API token lost read access to a "
                "previously available API family. Review the token's "
                "assigned admin role/scopes if this was not expected.",
            )
        if pv != CAPABILITY_AVAILABLE and nv == CAPABILITY_AVAILABLE:
            return "low", "ConfigTrace's Okta API token gained read access to an API family."
        return "low", "An Okta API capability probe's status changed."
    return "low", "An Okta API capability record changed."


def classify_okta_change(change: object) -> tuple[str, str]:
    """Route an Okta Change to its record-type classifier.

    Unknown/future ``okta_*`` record types (i.e. any later-message planned
    taxonomy, before their classifiers exist) fail safely into a generic
    low-severity message rather than raising or falling through to an
    unrelated provider's classifier.
    """
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    record_type = (pm.get("record_type") or "").lower()

    if record_type == OKTA_ORGANIZATION:
        return _classify_organization_change(change)
    if record_type == OKTA_API_CAPABILITY:
        return _classify_api_capability_change(change)

    return "low", f"An Okta configuration record changed ({record_type or 'unknown record type'})."
