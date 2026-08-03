"""Shopify certification manifest (message 6 of N).

Generic discovery is fully sufficient for Shopify — no adapter needed.
Shopify is registered in the capability matrix as maturity='complete'.
"""

from __future__ import annotations

from app.provider_certification.models import (
    CapabilityEvidenceDeclaration,
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ProviderCertificationManifest,
)
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "shopify_app_scope_summary",
    "shopify_domain",
    "shopify_shop_metadata",
    "shopify_store_policy",
    "shopify_webhook_subscription",
)

_FINDING_RULE_IDS = (
    "shopify_app_broad_write_scopes",
    "shopify_app_customer_data_scope",
    "shopify_domain_ssl_missing",
    "shopify_domain_unverified",
    "shopify_policy_missing",
    "shopify_webhook_high_risk_topic",
    "shopify_webhook_http",
)

SHOPIFY_MANIFEST = ProviderCertificationManifest(
    provider_id="shopify",
    display_name="Shopify",
    category="ecommerce",
    maturity="complete",
    expected_public=True,
    expected_connectable=True,
    expected_live=True,
    credential_fields=("shopify_access_token", "shopify_shop_domain"),
    sensitive_credential_fields=("shopify_access_token",),
    authentication_model="access_token",
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
    expected_frontend_form="ShopifyIntegrationForm.tsx",
    expected_reconnect=True,
    prohibited_dependencies=(),
    known_limitations=(
        "Customer PII, order data, payment data, and financial records are NEVER fetched, stored, or logged — several Shopify Admin API endpoints are explicitly FORBIDDEN and never called by this connector.",
        "Raw policy text is never stored — only policy presence/posture.",
        "The shopify_access_token is never logged (not even partially) and never returned to the frontend.",
    ),
    evidence_test_files=(
        "tests/test_shopify_risk_audit.py",
        "tests/test_shopify_risk_audit.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="shopify",
            test_file="tests/test_shopify_risk_audit.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=67,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="shopify",
            test_file="tests/test_shopify_risk_audit.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=67,
            quality="direct",
        ),
    ),
    capability_evidence=(
        CapabilityEvidenceDeclaration(
            capability="security_findings",
            supporting_record_types=(),
            supporting_finding_rule_ids=_FINDING_RULE_IDS,
            evidence_tests=("tests/test_shopify_risk_audit.py",),
            limitation_note="Customer PII, order data, payment data, and financial records are NEVER ingested — only shop/app/webhook/policy configuration metadata.",
        ),
    ),
)

register_manifest(SHOPIFY_MANIFEST)
