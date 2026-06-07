"""Stripe security exposure rules — M60.4.

Backed by the normalized ``stripe_webhook_endpoint`` record
(app/connectors/stripe.py): ``url``, ``status`` ("enabled"/"disabled"),
``record_id``.

M60.4.5 review — no new Stripe rules added; all candidates deferred because the
normalized data does not reliably support them:
* Live-mode webhook HTTP: the ``stripe_webhook_endpoint`` record has no
  ``livemode`` field, so live vs test cannot be distinguished here. The existing
  HTTP rule already fires regardless of mode.
* Disabled webhook endpoint: a disabled endpoint stops delivery — that is a
  reliability concern, not a "dangerous current state" exposure.
* Restricted-key scope expansion: the connector does NOT emit
  ``stripe_restricted_api_key`` records (Stripe's API cannot enumerate other
  keys' scopes), so there is no scope data to evaluate.
"""

from __future__ import annotations

from typing import Any

from app.connectors.stripe_schema import STRIPE_WEBHOOK_ENDPOINT
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

_RULE_WEBHOOK_HTTP = "stripe_webhook_http"


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if record.get("record_type") != STRIPE_WEBHOOK_ENDPOINT:
        return []

    url = get_str(record, "url").strip()
    status = get_str(record, "status").lower()
    # Only an enabled endpoint over plain HTTP is an exposure.
    if status and status != "enabled":
        return []
    if not url.lower().startswith("http://"):
        return []

    record_id = get_str(record, "record_id") or None
    return [
        FindingCandidate(
            provider="stripe",
            rule_key=_RULE_WEBHOOK_HTTP,
            finding_key=make_finding_key(_RULE_WEBHOOK_HTTP, record_id),
            severity="critical",
            title="Stripe webhook uses plain HTTP",
            description=(
                "A Stripe webhook endpoint delivers events over plain HTTP. "
                "Event payloads and signature headers may be transmitted in "
                "cleartext, allowing interception or tampering."
            ),
            evidence={"rule": _RULE_WEBHOOK_HTTP, "url": url},
            remediation={
                "summary": "Restore HTTPS on the webhook endpoint and verify ownership.",
                "steps": [
                    "Update the endpoint URL to https:// in the Stripe dashboard.",
                    "Verify the endpoint is owned by your team.",
                    "Confirm signature verification still succeeds after the change.",
                ],
            },
            record_id=record_id,
        )
    ]
