"""Shopify security / business-critical configuration rules — M60.4.5 / M74A.

Every rule fires only on explicit, reliable normalized fields produced by the
Shopify connector (app/connectors/shopify.py + shopify_schema.py). Evidence is
metadata-only: webhook topic, endpoint domain, scheme, app scope NAMES (the
permission labels — never the access token or signing secret), domain host and
posture booleans, policy type + presence boolean. Customer PII / order data /
payment data / raw webhook payloads / raw API responses / tokens / signing
secrets / authorization headers / request/response bodies / bank-account
details / tax IDs / staff names / staff emails are NEVER read, stored, or
surfaced by the connector — none of those bytes are even present on the
normalized records here.

CLAIM DISCIPLINE
----------------
These are business-critical configuration risks, not confirmed incidents.
Copy says "may affect store/security/payment operations", "may increase
configuration risk", "evidence for review", and "does not confirm fraud,
compromise, unauthorized access, or data exposure". It never asserts disclosure
of customer records, exposure of order details, exposure of card details,
fraud, gained access, a breach, or an attack.

Record types consumed
---------------------
- ``shopify_webhook_subscription``  → plain-HTTP delivery / high-risk topic
- ``shopify_app_scope_summary``     → broad write scopes / customer data scope
- ``shopify_domain``                → primary domain SSL missing / unverified
- ``shopify_store_policy``          → standard policy missing

Deferred Shopify rules (intentionally NOT implemented — see report)
------------------------------------------------------------------
* Webhook disabled: the webhook record has no enabled/disabled field.
* Dangerous (raw count) scope rules: presence of granted scopes is normal
  for legitimate apps. Only the SPECIFIC high-risk write scopes and the
  customer-data scopes are flagged here — a per-scope presence rule with
  no expected-scope baseline would be noisy.
* Separate ``shopify_webhook_insecure_url`` key: the existing
  ``shopify_webhook_http`` rule already fires on a plain-HTTP webhook
  endpoint, so a second key would double-flag the identical state.
"""

from __future__ import annotations

from typing import Any

from app.connectors.shopify_schema import (
    SHOPIFY_APP_SCOPE_SUMMARY,
    SHOPIFY_DOMAIN,
    SHOPIFY_STORE_POLICY,
    SHOPIFY_WEBHOOK_SUBSCRIPTION,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# Existing (M60.4.5)
_RULE_WEBHOOK_HTTP = "shopify_webhook_http"
# M74A
_RULE_WEBHOOK_HIGH_RISK_TOPIC = "shopify_webhook_high_risk_topic"
_RULE_APP_BROAD_WRITE_SCOPES = "shopify_app_broad_write_scopes"
_RULE_APP_CUSTOMER_DATA_SCOPE = "shopify_app_customer_data_scope"
_RULE_DOMAIN_SSL_MISSING = "shopify_domain_ssl_missing"
_RULE_DOMAIN_UNVERIFIED = "shopify_domain_unverified"
_RULE_POLICY_MISSING = "shopify_policy_missing"

# Webhook topic prefixes/exact handles considered high-risk for review priority.
# Each token is matched as a prefix on the topic string (Shopify topics use
# slash-separated families like "orders/create" / "customers/update").
_HIGH_RISK_TOPIC_PREFIXES: frozenset[str] = frozenset({
    "orders",
    "customers",
    "checkouts",
    "draft_orders",
    "fulfillments",
    "refunds",
    "shopify_payments",
})

# Topic handles (exact match) considered high-risk because they signal an app
# lifecycle event that may affect store operations.
_HIGH_RISK_TOPIC_HANDLES: frozenset[str] = frozenset({
    "app/uninstalled",
    "app_subscriptions/update",
})

# The specific Shopify high-risk WRITE scopes the broad-write-scopes rule
# counts. Generic write scopes (e.g. write_themes) are not in this set —
# presence alone of those is normal for legitimate apps.
_HIGH_RISK_WRITE_SCOPES: frozenset[str] = frozenset({
    "write_orders",
    "write_products",
    "write_customers",
    "write_inventory",
    "write_fulfillments",
    "write_draft_orders",
    "write_checkouts",
})

# Severity tiers for the broad-write-scopes rule. The count is over the
# intersection with _HIGH_RISK_WRITE_SCOPES, NOT the raw write_scope_count.
_BROAD_WRITE_MIN = 3   # 3 or more high-risk write scopes -> medium
_BROAD_WRITE_HIGH = 4  # 4 or more high-risk write scopes -> high


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == SHOPIFY_WEBHOOK_SUBSCRIPTION:
        return _eval_webhook(record)
    if rtype == SHOPIFY_APP_SCOPE_SUMMARY:
        return _eval_app_scope_summary(record)
    if rtype == SHOPIFY_DOMAIN:
        return _eval_domain(record)
    if rtype == SHOPIFY_STORE_POLICY:
        return _eval_store_policy(record)
    return []


# ── Webhook subscriptions ─────────────────────────────────────────────────────


def _eval_webhook(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    topic = get_str(record, "topic")
    domain = get_str(record, "endpoint_domain")
    scheme = get_str(record, "endpoint_scheme").lower()

    # A. Plain-HTTP webhook (existing M60.4.5 rule, unchanged).
    if scheme == "http":
        out.append(
            FindingCandidate(
                provider="shopify",
                rule_key=_RULE_WEBHOOK_HTTP,
                finding_key=make_finding_key(_RULE_WEBHOOK_HTTP, record_id),
                severity="critical",
                title="Shopify webhook uses plain HTTP",
                description=(
                    f"A Shopify webhook for '{topic or 'a topic'}' delivers to a "
                    f"plain-HTTP endpoint ({domain}). Event payloads and HMAC "
                    f"headers may be transmitted in cleartext, which may "
                    f"increase webhook configuration risk. This is evidence for "
                    f"review and does not confirm fraud, compromise, "
                    f"unauthorized access, or data exposure."
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
        )

    # B. High-risk webhook topic (M74A). Only fires when the topic falls into
    #    one of the curated prefixes / handles (no provider-only matching).
    topic_lower = topic.lower()
    family = topic_lower.split("/", 1)[0] if topic_lower else ""
    is_high_risk = (
        topic_lower in _HIGH_RISK_TOPIC_HANDLES
        or (family and family in _HIGH_RISK_TOPIC_PREFIXES)
    )
    if topic and is_high_risk:
        out.append(
            FindingCandidate(
                provider="shopify",
                rule_key=_RULE_WEBHOOK_HIGH_RISK_TOPIC,
                finding_key=make_finding_key(_RULE_WEBHOOK_HIGH_RISK_TOPIC, record_id),
                severity="medium",
                title="Shopify webhook subscribes to a high-risk topic",
                description=(
                    f"A Shopify webhook subscribes to '{topic}', which covers a "
                    f"high-impact area (orders, customers, checkouts, "
                    f"fulfillments, refunds, payments, or app lifecycle). "
                    f"Depending on the receiving system, this may affect store "
                    f"or webhook operations and may require review. This is "
                    f"evidence for review and does not confirm fraud, "
                    f"compromise, unauthorized access, or data exposure."
                ),
                evidence={
                    "rule": _RULE_WEBHOOK_HIGH_RISK_TOPIC,
                    "topic": topic,
                    "topic_family": family,
                    "endpoint_domain": domain,
                },
                remediation={
                    "summary": "Confirm the receiving system is intended and trusted.",
                    "steps": [
                        "Verify the receiving endpoint is owned by your team.",
                        "Confirm HMAC verification is enabled on the receiver.",
                        "Scope the topic only to what the integration needs.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── App scope summary ─────────────────────────────────────────────────────────


def _eval_app_scope_summary(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    raw_scopes = record.get("scope_names")
    scopes: list[str] = [s for s in raw_scopes if isinstance(s, str)] if isinstance(raw_scopes, list) else []
    scope_set = {s for s in scopes}

    # C. Broad high-risk write scopes (M74A). Counts only the curated set —
    #    generic write scopes do not contribute.
    high_risk_writes = sorted(scope_set & _HIGH_RISK_WRITE_SCOPES)
    high_risk_write_count = len(high_risk_writes)
    if high_risk_write_count >= _BROAD_WRITE_MIN:
        severity = "high" if high_risk_write_count >= _BROAD_WRITE_HIGH else "medium"
        out.append(
            FindingCandidate(
                provider="shopify",
                rule_key=_RULE_APP_BROAD_WRITE_SCOPES,
                finding_key=make_finding_key(_RULE_APP_BROAD_WRITE_SCOPES, record_id),
                severity=severity,
                title="Shopify app has broad high-risk write scopes",
                description=(
                    f"The Shopify app/access token is granted "
                    f"{high_risk_write_count} high-risk write scopes "
                    f"({', '.join(high_risk_writes)}). Broad write permissions "
                    f"widen the configuration surface and may affect store "
                    f"operations if misused. This is evidence for review and "
                    f"does not confirm fraud, compromise, unauthorized access, "
                    f"or data exposure."
                ),
                evidence={
                    "rule": _RULE_APP_BROAD_WRITE_SCOPES,
                    "high_risk_write_scope_count": high_risk_write_count,
                    "high_risk_write_scopes": ",".join(high_risk_writes),
                },
                remediation={
                    "summary": "Reduce the app's grant to least privilege.",
                    "steps": [
                        "Review which write scopes the integration actually needs.",
                        "Re-grant the app with the smaller required scope set.",
                    ],
                },
                record_id=record_id,
            )
        )

    # D. Customer-data scope (M74A). Fires only on the specific
    #    ``read_customers`` / ``write_customers`` permission handles.
    has_read_customers = "read_customers" in scope_set
    has_write_customers = "write_customers" in scope_set
    if has_read_customers or has_write_customers:
        granted = [s for s, present in (
            ("read_customers", has_read_customers),
            ("write_customers", has_write_customers),
        ) if present]
        out.append(
            FindingCandidate(
                provider="shopify",
                rule_key=_RULE_APP_CUSTOMER_DATA_SCOPE,
                finding_key=make_finding_key(_RULE_APP_CUSTOMER_DATA_SCOPE, record_id),
                severity="high",
                title="Shopify app has customer-data access scopes",
                description=(
                    f"The Shopify app/access token is granted "
                    f"{', '.join(granted)} — scopes that grant access to "
                    f"customer records. Confirm this access is intentional and "
                    f"that the receiving system is trusted. This is evidence "
                    f"for review and does not confirm fraud, compromise, "
                    f"unauthorized access, or data exposure."
                ),
                evidence={
                    "rule": _RULE_APP_CUSTOMER_DATA_SCOPE,
                    "scopes": ",".join(granted),
                },
                remediation={
                    "summary": "Confirm customer-data access is intended.",
                    "steps": [
                        "Verify the integration needs customer-data access.",
                        "If not needed, remove read_customers / write_customers from the app's grant.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Domain posture ───────────────────────────────────────────────────────────


def _eval_domain(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    # Only the primary domain is evaluated. Non-primary domains may be staged
    # / legacy and a missing SSL cert there is not necessarily a current risk.
    if record.get("primary") is not True:
        return out
    record_id = get_str(record, "record_id") or None
    host = get_str(record, "host") or "the primary domain"

    # E. Primary domain SSL missing (M74A). Only an explicit False fires.
    if record.get("ssl_enabled") is False:
        out.append(
            FindingCandidate(
                provider="shopify",
                rule_key=_RULE_DOMAIN_SSL_MISSING,
                finding_key=make_finding_key(_RULE_DOMAIN_SSL_MISSING, record_id),
                severity="high",
                title="Shopify primary domain does not have SSL enabled",
                description=(
                    f"The Shopify primary domain ({host}) does not have SSL "
                    f"enabled, so requests may be served over plain HTTP. This "
                    f"may affect store/security operations. This is evidence "
                    f"for review and does not confirm fraud, compromise, "
                    f"unauthorized access, or data exposure."
                ),
                evidence={
                    "rule": _RULE_DOMAIN_SSL_MISSING,
                    "host": host,
                    "primary": True,
                    "ssl_enabled": False,
                },
                remediation={
                    "summary": "Enable SSL on the primary domain.",
                    "steps": [
                        "In the Shopify admin, enable SSL/HTTPS for the primary domain.",
                        "Verify the storefront serves https:// after the change.",
                    ],
                },
                record_id=record_id,
            )
        )

    # F. Primary domain unverified (M74A). Only an explicit False fires.
    if record.get("verified") is False:
        out.append(
            FindingCandidate(
                provider="shopify",
                rule_key=_RULE_DOMAIN_UNVERIFIED,
                finding_key=make_finding_key(_RULE_DOMAIN_UNVERIFIED, record_id),
                severity="medium",
                title="Shopify primary domain is unverified",
                description=(
                    f"The Shopify primary domain ({host}) is unverified. An "
                    f"unverified primary domain may affect store operations "
                    f"and may require review. This is evidence for review and "
                    f"does not confirm fraud, compromise, unauthorized "
                    f"access, or data exposure."
                ),
                evidence={
                    "rule": _RULE_DOMAIN_UNVERIFIED,
                    "host": host,
                    "primary": True,
                    "verified": False,
                },
                remediation={
                    "summary": "Verify the primary domain in the Shopify admin.",
                    "steps": [
                        "Confirm domain ownership in the Shopify admin.",
                        "Re-check verification status after DNS updates propagate.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Store policy posture ──────────────────────────────────────────────────────


def _eval_store_policy(record: dict[str, Any]) -> list[FindingCandidate]:
    # G. Standard policy missing (M74A). Only an explicit ``present=False``
    #    fires; partially-recorded policies (no ``present`` key) are ignored.
    if record.get("present") is not False:
        return []
    record_id = get_str(record, "record_id") or None
    policy_type = get_str(record, "policy_type") or "a store policy"
    return [
        FindingCandidate(
            provider="shopify",
            rule_key=_RULE_POLICY_MISSING,
            finding_key=make_finding_key(_RULE_POLICY_MISSING, record_id),
            severity="low",
            title=f"Shopify '{policy_type}' policy is missing",
            description=(
                f"The Shopify '{policy_type}' policy is not present. A missing "
                f"standard policy may affect store operations and customer "
                f"trust. This is evidence for review and does not confirm "
                f"fraud, compromise, unauthorized access, or data exposure."
            ),
            evidence={
                "rule": _RULE_POLICY_MISSING,
                "policy_type": policy_type,
                "present": False,
            },
            remediation={
                "summary": f"Add the {policy_type} policy in the Shopify admin.",
                "steps": [
                    f"In the Shopify admin, draft and publish the {policy_type} policy.",
                    "Confirm the policy is visible on the storefront.",
                ],
            },
            record_id=record_id,
        )
    ]
