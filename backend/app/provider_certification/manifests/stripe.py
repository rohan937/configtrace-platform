"""Stripe certification manifest (message 4 of N).

Generic discovery is fully sufficient for Stripe — no adapter needed.
Credential is a single ``stripe_api_key`` field (already prefixed).
Reconnect is wired through the shared generic dispatcher (not a named
``reconnect_credentials_stripe`` function) — the same "original-era"
pattern seen for GitHub/Cloudflare.

Only 6 of the 17 schema-declared record-type constants are actually
wired into the connector (confirmed by grep: the other 11 — prices,
products, coupons, promotion codes, tax settings, radar rules,
restricted API keys, external accounts, checkout/dunning/subscription-
invoice settings — never appear anywhere in ``stripe.py``, not even the
classifier). Interestingly the classifier module DOES have dispatch
entries for all 17 (aspirational/future-proofed code), but with no
connector wiring those 11 are dead on both sides — genuinely
unimplemented, not a discovery bug. The manifest declares only the 6
real ones.
"""

from __future__ import annotations

from app.provider_certification.models import (
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ProviderCertificationManifest,
)
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "stripe_account_settings",
    "stripe_billing_portal_config",
    "stripe_payment_link",
    "stripe_payment_method_configuration",
    "stripe_payment_method_domain",
    "stripe_webhook_endpoint",
)

_FINDING_RULE_IDS = (
    "stripe_account_capability_incomplete",
    "stripe_payment_link_promo_codes_enabled",
    "stripe_payment_link_tax_disabled",
    "stripe_portal_login_enabled",
    "stripe_portal_subscription_cancel_enabled",
    "stripe_webhook_broad_events",
    "stripe_webhook_disabled",
    "stripe_webhook_http",
)

STRIPE_MANIFEST = ProviderCertificationManifest(
    provider_id="stripe",
    display_name="Stripe",
    category="payments_commerce",
    maturity="complete",
    expected_public=True,
    expected_connectable=True,
    expected_live=True,
    credential_fields=("stripe_api_key",),
    sensitive_credential_fields=("stripe_api_key",),
    authentication_model="api_key",
    expected_record_types=_EXPECTED_RECORD_TYPES,
    security_finding_rule_ids=_FINDING_RULE_IDS,
    supported_capabilities=(
        "security_findings",
        "activity_ingestion",
        "activity_signals",
        "risk_activity_correlations",
        "demo_case_reporting",
    ),
    unsupported_capabilities=(),
    completeness_scopes=(),
    false_removal_scopes=(),
    expected_frontend_form="StripeIntegrationForm.tsx",
    expected_reconnect=True,
    prohibited_dependencies=(),
    known_limitations=(
        "No payment transaction ingestion, no charge/event history, no "
        "invoice content, and no customer/card/payment-method data — "
        "only account/product-configuration metadata (webhook endpoints, "
        "payment links, billing-portal config, account settings) is "
        "collected.",
        "No webhook PAYLOAD ingestion — only the webhook ENDPOINT "
        "configuration (URL, enabled events, status) is collected, never "
        "delivered event bodies.",
        "11 of the 17 schema-declared record-type constants (prices, "
        "products, coupons, promotion codes, tax settings, radar rules, "
        "restricted API keys, external accounts, checkout/dunning/"
        "subscription-invoice settings) are declared in "
        "stripe_schema.py but never wired into the connector — genuinely "
        "unimplemented, confirmed by grep, not a discovery gap.",
        "No false-removal suppression function exists for Stripe yet "
        "(diff_service has no _stripe_removal_suppressed) — "
        "completeness_scopes/false_removal_scopes are honestly declared "
        "empty rather than claiming protection that doesn't exist.",
    ),
    evidence_test_files=(
        "tests/test_milestone73a_stripe_security_provider_foundation.py",
        "tests/test_stripe_change_classification_qa.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="stripe",
            test_file="tests/test_milestone73a_stripe_security_provider_foundation.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=15,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="stripe",
            test_file="tests/test_stripe_change_classification_qa.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=10,
            quality="direct",
        ),
    ),
)

register_manifest(STRIPE_MANIFEST)
