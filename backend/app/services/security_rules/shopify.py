"""Shopify security exposure rules — M60.4.5.

Every rule fires only on explicit, reliable normalized fields produced by the
Shopify connector (app/connectors/shopify.py + shopify_schema.py). Evidence is
metadata-only: webhook topic, endpoint domain, scheme. The connector hashes the
webhook path and never stores customer/payment data; we surface none of it.

Record types consumed
---------------------
- ``shopify_webhook_subscription`` → webhook delivered over plain HTTP

Deferred Shopify rules (intentionally NOT implemented — see report)
------------------------------------------------------------------
* Webhook disabled: the webhook record has no enabled/disabled field.
* Dangerous app scopes: ``shopify_app_scope_summary`` reliably counts
  sensitive/write/payment scopes, but presence of those scopes is normal for
  legitimate apps and there is NO "expected scopes" baseline — flagging granted
  permissions would be noisy and is not a current exposure.
* Payment/policy risky state: ``shopify_store_policy`` only captures whether a
  policy body is present; a missing policy is a compliance/ops gap, not a
  security exposure.
"""

from __future__ import annotations

from typing import Any

from app.connectors.shopify_schema import SHOPIFY_WEBHOOK_SUBSCRIPTION
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

_RULE_WEBHOOK_HTTP = "shopify_webhook_http"


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if not isinstance(record, dict):
        return []
    if record.get("record_type") != SHOPIFY_WEBHOOK_SUBSCRIPTION:
        return []

    # Only flag an explicit plain-HTTP endpoint. Non-HTTP transports
    # (EventBridge / Pub-Sub) have a different scheme and are ignored.
    scheme = get_str(record, "endpoint_scheme").lower()
    if scheme != "http":
        return []

    record_id = get_str(record, "record_id") or None
    topic = get_str(record, "topic") or "a topic"
    domain = get_str(record, "endpoint_domain")

    return [
        FindingCandidate(
            provider="shopify",
            rule_key=_RULE_WEBHOOK_HTTP,
            finding_key=make_finding_key(_RULE_WEBHOOK_HTTP, record_id),
            severity="critical",
            title="Shopify webhook uses plain HTTP",
            description=(
                f"A Shopify webhook for '{topic}' delivers to a plain-HTTP "
                f"endpoint ({domain}). Event payloads and HMAC headers may be "
                f"transmitted in cleartext, which could expose webhook traffic "
                f"to interception or tampering."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_HTTP,
                "topic": topic,
                "endpoint_domain": domain,
                "endpoint_scheme": "http",
            },
            remediation={
                "summary": "Switch the webhook endpoint to HTTPS.",
                "steps": [
                    "Update the webhook subscription to an https:// endpoint.",
                    "Verify the endpoint is owned by your team.",
                    "Confirm HMAC verification still succeeds after the change.",
                ],
            },
            record_id=record_id,
        )
    ]
