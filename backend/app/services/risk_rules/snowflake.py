"""Snowflake risk classification rules — foundation (Snowflake message 1
of 8).

This module exists to give every ``snowflake_*`` record type a dedicated,
correct classifier so that ``risk_service.classify_change()`` never falls
through to an unrelated provider's default classifier.

This is intentionally NOT a Security Finding taxonomy — that is message 6.
Classification here is deliberately structural, not incident-level:

- An account identity metadata change (organization/account name, locator,
  monitoring role) is Low — these are informational identity fields, not
  security posture by themselves.
- A capability probe losing access is a Medium diagnostic signal, never a
  "security incident" — permission changes are common and expected (e.g.
  the monitoring role's grants being intentionally re-scoped), not proof
  of compromise. Regaining access is Low.

Future messages (2-7) will add classifiers for users, roles, grants,
databases/schemas/warehouses/shares, network/authentication policies,
security/storage/external-access integrations, and privileged-role
posture as those record types are introduced — this module's dispatcher
already fails safely into a generic low-severity message for any
``snowflake_*`` record type that does not have a classifier yet, so this
module continues to work unmodified as an incremental target for those
insertions.
"""

from __future__ import annotations

from typing import Any

from app.connectors.snowflake_schema import (
    CAPABILITY_AVAILABLE,
    SNOWFLAKE_ACCOUNT,
    SNOWFLAKE_API_CAPABILITY,
)


def _get(obj: Any, field: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _classify_account_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A Snowflake account was added to monitoring."
    if ct == "removed":
        return (
            "medium",
            "A Snowflake account is no longer visible to ConfigTrace. "
            "Verify the integration still has a valid programmatic access token.",
        )

    fp = (_get(change, "field_path") or "").lower()
    if fp in ("organization_name", "account_name", "account_locator", "monitoring_role"):
        return "low", "The Snowflake account's identifying metadata changed."
    return "low", "A Snowflake account configuration field changed."


def _classify_api_capability_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    if ct == "added":
        return "low", "A new Snowflake API capability probe was recorded."
    if ct == "removed":
        return "low", "A Snowflake API capability probe is no longer recorded."

    fp = (_get(change, "field_path") or "").lower()
    if fp == "status":
        nv = _get(change, "new_value")
        pv = _get(change, "prev_value")
        if pv == CAPABILITY_AVAILABLE and nv != CAPABILITY_AVAILABLE:
            return (
                "medium",
                "ConfigTrace's Snowflake monitoring role lost read access to a "
                "previously available metadata family. Review the role's "
                "grants if this was not expected.",
            )
        if pv != CAPABILITY_AVAILABLE and nv == CAPABILITY_AVAILABLE:
            return "low", "ConfigTrace's Snowflake monitoring role gained read access to a metadata family."
        return "low", "A Snowflake API capability probe's status changed."
    return "low", "A Snowflake API capability record changed."


def classify_snowflake_change(change: object) -> tuple[str, str]:
    """Route a Snowflake Change to its record-type classifier.

    Unknown/future ``snowflake_*`` record types (i.e. any later-message
    planned taxonomy, before their classifiers exist) fail safely into a
    generic low-severity message rather than raising or falling through
    to an unrelated provider's classifier.
    """
    raw_pm = _get(change, "provider_metadata")
    pm: dict = raw_pm if isinstance(raw_pm, dict) else {}
    record_type = (pm.get("record_type") or "").lower()

    if record_type == SNOWFLAKE_ACCOUNT:
        return _classify_account_change(change)
    if record_type == SNOWFLAKE_API_CAPABILITY:
        return _classify_api_capability_change(change)
    return "low", "A Snowflake configuration field changed."
