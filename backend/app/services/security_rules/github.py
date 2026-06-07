"""GitHub security exposure rules — M60.4.

Backed by the normalized ``github_webhook`` record (app/connectors/github.py),
which carries ``url`` (delivery URL), ``active``, and ``record_id``.
"""

from __future__ import annotations

from typing import Any

from app.connectors.github_schema import GITHUB_WEBHOOK
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

_RULE_WEBHOOK_HTTP = "github_webhook_http"


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if record.get("record_type") != GITHUB_WEBHOOK:
        return []

    url = get_str(record, "url").strip()
    active = bool(record.get("active", True))
    # Only an active webhook delivering over plain HTTP is an exposure.
    if not active:
        return []
    low = url.lower()
    if not low.startswith("http://"):
        return []

    record_id = get_str(record, "record_id") or None
    return [
        FindingCandidate(
            provider="github",
            rule_key=_RULE_WEBHOOK_HTTP,
            finding_key=make_finding_key(_RULE_WEBHOOK_HTTP, record_id),
            severity="critical",
            title="GitHub webhook uses plain HTTP",
            description=(
                "A GitHub webhook delivers events over plain HTTP. Event "
                "payloads and signature headers may be transmitted in cleartext, "
                "allowing interception or tampering."
            ),
            evidence={"rule": _RULE_WEBHOOK_HTTP, "url": url},
            remediation={
                "summary": "Restore HTTPS on the webhook endpoint and verify ownership.",
                "steps": [
                    "Change the webhook delivery URL back to https://.",
                    "Verify the endpoint is owned by your team.",
                    "Rotate the webhook secret if exposure is suspected.",
                ],
            },
            record_id=record_id,
        )
    ]
