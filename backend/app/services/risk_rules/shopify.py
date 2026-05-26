"""Shopify risk classification rules — M57.5.

Entry point: ``classify_shopify_change(change)``

Risk levels
-----------
critical  — (none currently; reserved for future payment-disruption signals)
high      — Webhook added/removed/endpoint domain changed, non-HTTPS webhook,
            payments disabled, storefront disabled, sensitive scope added.
medium    — Webhook path changed, plan downgrade, currency changed, store
            policy body changed, store policy removed, password protection
            disabled, checkout API disabled, payment agreement required.
low       — Password protection enabled (strengthening), policy added,
            cosmetic/locale/timezone changes.

Directionality
--------------
Every classification distinguishes:
  * new_value → False / None / removed  — weakening or loss of capability
  * new_value → True / added            — strengthening or new capability

Data minimisation
-----------------
Webhook URLs are NEVER included in risk reasons — only domain and topic.
Shop domain is included in context but access token is NEVER referenced.
"""

from __future__ import annotations

from app.models.change import Change


def _get(obj: object, field: str) -> object:
    """Safely retrieve a field from a Change object or dict."""
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


# ── shopify_shop_metadata ─────────────────────────────────────────────────────

def _classify_shop_metadata_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return (
            "low",
            "Shopify shop metadata record was added or removed during sync.",
        )

    # Storefront password protection — directional
    if fp == "password_enabled":
        if new_v is False or new_v == "false":
            return (
                "medium",
                "Shopify storefront password protection was disabled. "
                "The store is now publicly accessible without a password.",
            )
        return (
            "low",
            "Shopify storefront password protection was enabled. "
            "Visitors must now enter a password to access the storefront.",
        )

    # Plan name change — could be upgrade or downgrade
    if fp in ("plan_name", "plan_display_name"):
        return (
            "medium",
            "Shopify subscription plan changed. "
            "Verify this change was intentional — plan downgrades may remove features.",
        )

    # Payment eligibility — high impact if lost
    if fp == "eligible_for_payments":
        if new_v is False or new_v == "false":
            return (
                "high",
                "This Shopify store is no longer eligible for payments. "
                "Customers cannot complete purchases until this is resolved.",
            )
        return (
            "medium",
            "Shopify store payment eligibility was restored.",
        )

    # Checkout API support
    if fp == "checkout_api_supported":
        if new_v is False or new_v == "false":
            return (
                "medium",
                "Shopify Checkout API support was disabled. "
                "Custom checkout integrations may stop functioning.",
            )
        return (
            "low",
            "Shopify Checkout API support was enabled.",
        )

    # Storefront presence
    if fp == "has_storefront":
        if new_v is False or new_v == "false":
            return (
                "high",
                "The Shopify storefront was disabled. "
                "The store is no longer publicly visible.",
            )
        return (
            "low",
            "Shopify storefront was enabled.",
        )

    # Extra payments agreement required
    if fp == "requires_extra_payments_agreement":
        if new_v is True or new_v == "true":
            return (
                "medium",
                "Shopify now requires an extra payments provider agreement. "
                "Payment processing may be suspended until the agreement is accepted.",
            )
        return (
            "low",
            "Shopify extra payments provider agreement requirement was cleared.",
        )

    # Currency change — operationally significant
    if fp == "currency":
        return (
            "medium",
            "Shopify store currency changed. "
            "Verify this change is intentional — it affects pricing and payouts.",
        )

    # Timezone / locale / country — low impact
    if fp in ("timezone", "iana_timezone"):
        return (
            "low",
            "Shopify store timezone changed.",
        )
    if fp in ("primary_locale",):
        return (
            "low",
            "Shopify store primary locale changed.",
        )
    if fp == "country_code":
        return (
            "low",
            "Shopify store country code changed.",
        )

    # Tax settings
    if fp in ("taxes_included", "tax_shipping"):
        return (
            "low",
            "Shopify tax configuration changed.",
        )

    # Shop name
    if fp == "shop_name":
        return (
            "low",
            "Shopify shop display name changed.",
        )

    return (
        "low",
        f"Shopify shop metadata field '{fp}' changed.",
    )


# ── shopify_webhook_subscription ─────────────────────────────────────────────

# Critical webhook topics whose removal / change is especially high-risk.
_CRITICAL_TOPICS = frozenset({
    "app/uninstalled",
    "shop/redact",
    "customers/redact",
    "customers/data_request",
    "orders/create",
    "orders/cancelled",
    "orders/fulfilled",
    "checkouts/create",
    "checkouts/update",
})


def _classify_webhook_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")
    pm = _get(change, "provider_metadata") or {}
    if isinstance(pm, dict):
        topic = pm.get("topic") or ""
    else:
        topic = ""

    # Structural: webhook added
    if ct == "added":
        return (
            "high",
            "A new Shopify webhook subscription was added. "
            f"Topic: {topic or 'unknown'}. "
            "Verify the endpoint is legitimate and the topic is expected.",
        )

    # Structural: webhook removed
    if ct == "removed":
        if topic in _CRITICAL_TOPICS:
            return (
                "high",
                f"A Shopify webhook for a critical topic ({topic}) was removed. "
                "Event delivery to the registered endpoint has stopped.",
            )
        return (
            "medium",
            f"A Shopify webhook subscription was removed (topic: {topic or 'unknown'}). "
            "Event delivery to the registered endpoint has stopped.",
        )

    # HTTPS enforcement — always high when downgraded
    if fp == "is_https":
        if new_v is False or new_v == "false":
            return (
                "high",
                "A Shopify webhook endpoint was changed to use plain HTTP (not HTTPS). "
                "Event payloads will be transmitted unencrypted.",
            )
        return (
            "low",
            "A Shopify webhook endpoint was upgraded to HTTPS.",
        )

    # Endpoint domain change — events now delivered to a different server
    if fp == "endpoint_domain":
        return (
            "high",
            "A Shopify webhook endpoint domain changed. "
            "Events are now being delivered to a different server. "
            "Verify this change is intentional.",
        )

    # Endpoint scheme change
    if fp == "endpoint_scheme":
        if str(new_v).lower() in ("http", ""):
            return (
                "high",
                "A Shopify webhook endpoint scheme was downgraded from HTTPS to HTTP. "
                "Event payloads will be transmitted unencrypted.",
            )
        return (
            "low",
            "A Shopify webhook endpoint scheme changed to HTTPS.",
        )

    # Path hash / length change — same domain, different path
    if fp in ("endpoint_path_hash", "endpoint_path_length"):
        return (
            "medium",
            "A Shopify webhook endpoint path changed (same domain). "
            "Verify the receiving application has been updated.",
        )

    # Topic change — the event type being monitored changed
    if fp == "topic":
        return (
            "medium",
            "A Shopify webhook topic (event type) changed. "
            "The subscription now captures different events.",
        )

    # API version / format — low impact configuration details
    if fp == "api_version":
        return (
            "low",
            "Shopify webhook API version changed.",
        )
    if fp == "format":
        return (
            "low",
            "Shopify webhook payload format changed.",
        )

    return (
        "low",
        f"Shopify webhook subscription field '{fp}' changed.",
    )


# ── shopify_store_policy ──────────────────────────────────────────────────────

def _classify_store_policy_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")
    pm = _get(change, "provider_metadata") or {}
    if isinstance(pm, dict):
        policy_type = pm.get("policy_type") or ""
    else:
        policy_type = ""

    # Structural: policy added
    if ct == "added":
        return (
            "low",
            f"A Shopify store policy was added: {policy_type or 'unknown type'}.",
        )

    # Structural: policy removed
    if ct == "removed":
        return (
            "medium",
            f"A Shopify store policy record was removed: {policy_type or 'unknown type'}. "
            "Verify this policy is still configured in the Shopify admin.",
        )

    # Policy presence flag
    if fp == "present":
        if new_v is False or new_v == "false":
            return (
                "medium",
                f"A Shopify store policy was cleared or removed: {policy_type or 'unknown type'}. "
                "Legal compliance may be affected.",
            )
        return (
            "low",
            f"A Shopify store policy was created: {policy_type or 'unknown type'}.",
        )

    # Body hash change — policy text changed (hash-only; raw text never stored)
    if fp == "body_hash":
        label = policy_type or "unknown type"
        if "privacy" in label.lower():
            return (
                "medium",
                f"Shopify privacy policy content changed (body hash differs). "
                "Review the updated policy for compliance.",
            )
        return (
            "medium",
            f"Shopify store policy content changed: {label} (body hash differs). "
            "Review the updated policy.",
        )

    # Body length changed alongside hash — same risk as hash change
    if fp == "body_length":
        return (
            "low",
            f"Shopify store policy length changed: {policy_type or 'unknown type'}.",
        )

    return (
        "low",
        f"Shopify store policy field '{fp}' changed.",
    )


# ── Main dispatcher ───────────────────────────────────────────────────────────

# ── shopify_app_scope_summary ──────────────────────────────────────────────────


def _classify_app_scope_summary_change(change: Change) -> tuple[str, str]:
    """Risk rules for ``shopify_app_scope_summary`` records — M57.9.

    Priority chain (first match wins):
    1. removed → high
    2. added   → low
    3. sensitive_scope_count increased → high
    4. write_scope_count increased → high
    5. customer/order/payment scope newly present → high
    6. scope_count increased (other) → medium
    7. scope_count decreased → medium
    8. scope_hash / scope_names changed → medium
    9. other → low
    """
    change_type = (_get(change, "change_type") or "").lower()
    field_path = _get(change, "field_path") or ""
    prev_value = _get(change, "prev_value")
    new_value  = _get(change, "new_value")

    if change_type == "removed":
        return (
            "high",
            "The Shopify app access scope record was removed. "
            "Scope drift can no longer be detected for this integration.",
        )

    if change_type == "added":
        return (
            "low",
            "Shopify app access scopes were recorded for the first time.",
        )

    # sensitive_scope_count increased
    if field_path == "sensitive_scope_count":
        try:
            old_n = int(prev_value or 0)
            new_n = int(new_value or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n > old_n:
            return (
                "high",
                f"The number of sensitive Shopify scopes (orders, customers, "
                f"payments) increased from {old_n} to {new_n}. "
                "Review newly granted scopes and rotate credentials if unexpected.",
            )

    # write_scope_count increased
    if field_path == "write_scope_count":
        try:
            old_n = int(prev_value or 0)
            new_n = int(new_value or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n > old_n:
            return (
                "high",
                f"Write-access Shopify scopes increased from {old_n} to {new_n}. "
                "The app can now modify more store data — confirm this is intended.",
            )

    # Customer/order/payment scope newly present
    if field_path in ("customer_scope_present", "order_scope_present", "payment_scope_present"):
        if new_value is True and prev_value is not True:
            scope_label = field_path.replace("_scope_present", "")
            return (
                "high",
                f"The Shopify app may now access {scope_label} data "
                f"(scope category newly granted). "
                "Verify this permission is required and rotate credentials if unexpected.",
            )

    # scope_count increased
    if field_path == "scope_count":
        try:
            old_n = int(prev_value or 0)
            new_n = int(new_value or 0)
        except (ValueError, TypeError):
            old_n, new_n = 0, 0
        if new_n > old_n:
            return (
                "medium",
                f"Shopify app scope count increased from {old_n} to {new_n}. "
                "Review the scope_names field to identify newly granted permissions.",
            )
        if new_n < old_n:
            return (
                "medium",
                f"Shopify app scope count decreased from {old_n} to {new_n}. "
                "Some permissions may have been revoked.",
            )

    # scope_hash or scope_names changed
    if field_path in ("scope_hash", "scope_names"):
        return (
            "medium",
            "The set of Shopify app access scopes changed. "
            "Review scope_names to identify added or removed permissions.",
        )

    return (
        "low",
        f"Shopify app scope summary field '{field_path}' changed.",
    )


def classify_shopify_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for a Shopify change.

    Dispatches on ``provider_metadata["record_type"]``:
      * ``shopify_shop_metadata``       → shop settings rules
      * ``shopify_webhook_subscription`` → webhook rules
      * ``shopify_store_policy``         → store policy rules
      * ``shopify_app_scope_summary``    → app scope rules (M57.9)

    Args:
        change: A ``Change`` ORM instance (or a plain dict, for testing).

    Returns:
        ``(risk_level, risk_reason)`` where risk_level is one of
        ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
    """
    pm = _get(change, "provider_metadata") or {}
    if isinstance(pm, dict):
        record_type = (pm.get("record_type") or "").lower()
    else:
        record_type = ""

    if record_type == "shopify_shop_metadata":
        return _classify_shop_metadata_change(change)
    if record_type == "shopify_webhook_subscription":
        return _classify_webhook_change(change)
    if record_type == "shopify_store_policy":
        return _classify_store_policy_change(change)
    if record_type == "shopify_app_scope_summary":
        return _classify_app_scope_summary_change(change)

    # Fallback for unknown shopify_ subtypes
    return (
        "low",
        f"Shopify configuration changed (record type: {record_type or 'unknown'}).",
    )
