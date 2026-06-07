"""AWS security exposure rules — M60.4.

Backed by the normalized ``aws_security_group_rule`` record
(app/connectors/aws.py), which already carries the derived fields ``is_public``
(0.0.0.0/0 or ::/0), ``port_category`` ("admin"/"database"/"web"/"all"/"other"),
and ``direction``. We reuse those rather than re-deriving ports.
"""

from __future__ import annotations

from typing import Any

from app.connectors.aws_schema import AWS_SECURITY_GROUP_RULE
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

_RULE_PUBLIC_ADMIN_PORT = "aws_public_admin_port"

# Port categories that constitute an exposure when publicly reachable inbound.
_RISKY_CATEGORIES = {"admin", "database", "all"}


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if record.get("record_type") != AWS_SECURITY_GROUP_RULE:
        return []

    if get_str(record, "direction") != "ingress":
        return []
    if not bool(record.get("is_public")):
        return []
    category = get_str(record, "port_category")
    if category not in _RISKY_CATEGORIES:
        return []

    # database/all-traffic exposure is more severe than admin-only.
    severity = "critical" if category in ("database", "all") else "high"
    cidr = get_str(record, "cidr_ipv4") or get_str(record, "cidr_ipv6")
    group_id = get_str(record, "group_id")
    record_id = get_str(record, "record_id") or None

    label = {
        "admin": "administrative ports",
        "database": "database ports",
        "all": "all ports",
    }[category]

    return [
        FindingCandidate(
            provider="aws",
            rule_key=_RULE_PUBLIC_ADMIN_PORT,
            finding_key=make_finding_key(_RULE_PUBLIC_ADMIN_PORT, record_id),
            severity=severity,
            title=f"AWS security group exposes {label} to the internet",
            description=(
                f"An inbound security group rule allows public access "
                f"({cidr}) to {label}. This makes sensitive services reachable "
                f"from anywhere on the internet."
            ),
            evidence={
                "rule": _RULE_PUBLIC_ADMIN_PORT,
                "group_id": group_id,
                "direction": "ingress",
                "port_category": category,
                "cidr": cidr,
                "protocol": get_str(record, "protocol"),
            },
            remediation={
                "summary": "Restrict the rule to trusted source ranges.",
                "steps": [
                    "Replace 0.0.0.0/0 (or ::/0) with specific trusted CIDRs.",
                    "Prefer a bastion host or VPN for administrative access.",
                    "Remove the rule entirely if the exposure is unintended.",
                ],
            },
            record_id=record_id,
        )
    ]
