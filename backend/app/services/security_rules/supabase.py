"""Supabase security exposure rules — M60.4.

Backed by the normalized ``supabase_rls_status`` record
(app/connectors/supabase_schema.py): ``rls_enabled`` (bool), ``table_name``,
``schema_name``, ``record_id``.
"""

from __future__ import annotations

from typing import Any

from app.connectors.supabase_schema import SUPABASE_RLS_STATUS
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

_RULE_RLS_DISABLED = "supabase_rls_disabled"


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if record.get("record_type") != SUPABASE_RLS_STATUS:
        return []

    # Only fire when the field is explicitly present and False (conservative:
    # a missing/unknown flag must not produce a finding).
    if "rls_enabled" not in record:
        return []
    if record.get("rls_enabled") is not False:
        return []

    table = get_str(record, "table_name")
    schema = get_str(record, "schema_name") or "public"
    record_id = get_str(record, "record_id") or None
    where = f"{schema}.{table}" if table else (record_id or "a table")

    return [
        FindingCandidate(
            provider="supabase",
            rule_key=_RULE_RLS_DISABLED,
            finding_key=make_finding_key(_RULE_RLS_DISABLED, record_id),
            severity="high",
            title="Supabase table has Row Level Security disabled",
            description=(
                f"Row Level Security is disabled on {where}. Without RLS, rows "
                f"may be broadly readable or writable by any role that can reach "
                f"the table."
            ),
            evidence={
                "rule": _RULE_RLS_DISABLED,
                "schema": schema,
                "table": table,
            },
            remediation={
                "summary": "Enable Row Level Security and add explicit policies.",
                "steps": [
                    "Enable RLS on the table.",
                    "Add policies that scope access to the intended roles.",
                    "Verify application access still works under the new policies.",
                ],
            },
            record_id=record_id,
        )
    ]
