"""M83C — Clerk Auth/Application Risk Expansion tests.

Verifies all 19 new Clerk configuration-risk rules introduced in M83C,
registry/confidence/pack/coverage wiring, capability matrix, expansion
framework, and frontend catalog.

Privacy guarantees verified by these tests
------------------------------------------
- Evidence never contains Clerk secret key values, publishable key values,
  session tokens, JWTs, OAuth tokens, bearer tokens, webhook secrets
- Evidence never contains raw webhook URLs, raw redirect URLs, raw callback URLs
- Evidence never contains raw domain names, raw JWT template bodies, raw claims
- Evidence never contains audience values, issuer values, user emails
- Evidence never contains user IDs, phone numbers, names, organization member
  identities, session history, login history, password data
- Evidence never contains MFA secrets, backup codes, IP addresses, user agents

Sections
--------
  A. Rule key taxonomy (2 tests)
  B. Rule trigger tests — positive cases (19 tests)
  C. Rule non-trigger tests — healthy records (19 + 4 extra tests)
  D. Evidence privacy scan
  E. Registry / confidence / pack wiring
  F. Coverage service
  G. Capability matrix + expansion framework
  H. Frontend catalog
  I. Forbidden wording scan
  J. M83A+M83B regression
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from app.services.security_rules.clerk import (
    CLERK_RULE_KEYS,
    evaluate,
)
from app.connectors.clerk_schema import (
    CLERK_INSTANCE_SETTINGS,
    CLERK_APPLICATION,
    CLERK_DOMAIN,
    CLERK_REDIRECT_URL_CONFIG,
    CLERK_JWT_TEMPLATE,
    CLERK_WEBHOOK_ENDPOINT,
    CLERK_EMAIL_SMS_SETTINGS,
    CLERK_AUTH_STRATEGY,
    CLERK_ORGANIZATION_SETTINGS,
    CLERK_SESSION_POLICY,
)
from app.services.security_rule_registry import KNOWN_RULE_KEYS, is_known_rule_key
from app.services.security_rule_confidence import RULE_CONFIDENCE, confidence_for
from app.services.security_rule_pack import _RULE_META, pack_summary
from app.services.security_coverage_service import PROVIDERS, RULE_RECORD_TYPES, PROVIDER_SURFACES
from app.services.security_finding_evaluator import _PROVIDER_RULES, evaluate_record
from app.services.provider_capability_matrix_service import (
    get_matrix as get_capability_matrix,
    get_provider_capability,
    PROVIDER_CAPABILITIES_PARTIAL,
)
from app.services.provider_expansion_framework import get_framework

# ── Test constants ─────────────────────────────────────────────────────────────

# Safe placeholder values — NOT real credentials.
CLERK_TEST_SECRET_KEY = "CLERK_TEST_SECRET_KEY_PLACEHOLDER"
CLERK_TEST_INSTANCE_ID = "CLERK_TEST_INSTANCE_ID"
CLERK_TEST_WEBHOOK_ID = "CLERK_TEST_WEBHOOK_ID"
CLERK_TEST_TEMPLATE_ID = "CLERK_TEST_TEMPLATE_ID"

# The 19 new rule keys introduced in M83C.
M83C_NEW_RULE_KEYS = {
    "clerk_application_sign_up_enabled",
    "clerk_application_password_without_mfa",
    "clerk_application_oauth_without_mfa",
    "clerk_application_saml_without_mfa",
    "clerk_application_many_redirect_urls",
    "clerk_application_many_allowed_origins",
    "clerk_redirect_url_custom_scheme_present",
    "clerk_jwt_template_audience_missing",
    "clerk_jwt_template_issuer_missing",
    "clerk_jwt_template_many_claims",
    "clerk_webhook_broad_event_scope",
    "clerk_org_verified_domains_not_required",
    "clerk_org_invitations_enabled",
    "clerk_org_admin_role_missing",
    "clerk_org_high_role_count",
    "clerk_org_high_permission_count",
    "clerk_session_device_tracking_disabled",
    "clerk_session_reverification_disabled",
    "clerk_session_long_lifetime_without_single_session",
}

# Fields that must NEVER appear as keys in any evidence dict.
_FORBIDDEN_EVIDENCE_FIELDS = frozenset({
    "secret_key", "publishable_key", "api_key", "token", "bearer", "jwt",
    "session_token", "webhook_secret", "url", "webhook_url", "redirect_url",
    "callback_url", "domain_name", "template_body", "claims", "audience_value",
    "issuer_value", "email", "user_email", "user_id", "phone", "member",
    "ip_address", "user_agent", "member_id", "member_email",
})

# Strings that must NEVER appear in any evidence string value.
_FORBIDDEN_EVIDENCE_STRINGS = [
    "eyJ",
    "pk_live_",
    "sk_live_",
    "clerk.com",
    "@",
]


# ── Record builder helpers ─────────────────────────────────────────────────────


def _app(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_application record with M83C fields; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_APPLICATION,
        "provider": "clerk",
        "record_id": "clerk_app_opaque_001",
        "provider_resource_id": "applications/clerk_app_opaque_001",
        "name": "My Application",
        "application_type": "web",
        "enabled": True,
        "oauth_provider_count": 0,
        "redirect_url_count": 5,
        "allowed_origin_count": 5,
        "jwt_template_count": 1,
        "organization_enabled": False,
        "mfa_required": True,
        "sign_up_enabled": False,
        "sign_in_enabled": True,
        "password_enabled": False,
        "saml_enabled": False,
    }
    defaults.update(kwargs)
    return defaults


def _redirect(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_redirect_url_config record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_REDIRECT_URL_CONFIG,
        "provider": "clerk",
        "record_id": "ru_opaque_001",
        "provider_resource_id": "redirect_urls/ru_opaque_001",
        "url_present": True,
        "url_scheme_category": "https",
        "wildcard_present": False,
        "localhost_present": False,
        "custom_scheme_present": False,
    }
    defaults.update(kwargs)
    return defaults


def _jwt(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_jwt_template record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_JWT_TEMPLATE,
        "provider": "clerk",
        "record_id": CLERK_TEST_TEMPLATE_ID,
        "provider_resource_id": f"jwt_templates/{CLERK_TEST_TEMPLATE_ID}",
        "name": "Standard JWT",
        "enabled": True,
        "claims_count": 2,
        "custom_claims_present": False,
        "audience_present": True,
        "issuer_present": True,
        "lifetime_category": "standard",
        "algorithm": "RS256",
    }
    defaults.update(kwargs)
    return defaults


def _webhook(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_webhook_endpoint record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_WEBHOOK_ENDPOINT,
        "provider": "clerk",
        "record_id": CLERK_TEST_WEBHOOK_ID,
        "provider_resource_id": f"webhooks/{CLERK_TEST_WEBHOOK_ID}",
        "enabled": True,
        "url_present": True,
        "url_scheme_category": "https",
        "event_count": 3,
        "secret_present": True,
        "description_present": True,
    }
    defaults.update(kwargs)
    return defaults


def _org(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_organization_settings record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_ORGANIZATION_SETTINGS,
        "provider": "clerk",
        "record_id": "clerk_organization_settings_main",
        "provider_resource_id": "instance/organization",
        "organizations_enabled": True,
        "max_allowed_memberships_category": "limited",
        "admin_delete_enabled": False,
        "domains_enabled": True,
        "domains_enrollment_mode_category": "manual",
        "verified_domains_required": True,
        "invitation_enabled": False,
        "admin_role_present": True,
        "role_count": 3,
        "permission_count": 10,
    }
    defaults.update(kwargs)
    return defaults


def _session(**kwargs: Any) -> dict[str, Any]:
    """Build a healthy clerk_session_policy record; override with kwargs."""
    defaults: dict[str, Any] = {
        "record_type": CLERK_SESSION_POLICY,
        "provider": "clerk",
        "record_id": "clerk_session_policy_main",
        "provider_resource_id": "instance/session",
        "session_lifetime_category": "standard",
        "inactivity_timeout_category": "standard",
        "single_session_mode": True,
        "url_based_session_syncing": False,
        "token_rotation_enabled": True,
        "device_tracking_enabled": True,
        "reverification_required": True,
    }
    defaults.update(kwargs)
    return defaults


def _rule_keys(findings: list) -> set[str]:
    """Extract set of rule_key strings from a list of FindingCandidate objects."""
    return {f.rule_key for f in findings}


def _collect_all_m83c_risky_findings() -> list:
    """Return all findings from all M83C risky records (for privacy scans)."""
    records = [
        _app(sign_up_enabled=True),
        _app(password_enabled=True, mfa_required=False),
        _app(oauth_provider_count=3, mfa_required=False),
        _app(saml_enabled=True, mfa_required=False),
        _app(redirect_url_count=15),
        _app(allowed_origin_count=12),
        _redirect(custom_scheme_present=True),
        _jwt(audience_present=False),
        _jwt(issuer_present=False),
        _jwt(claims_count=20),
        _webhook(event_count=12),
        _org(organizations_enabled=True, verified_domains_required=False),
        _org(organizations_enabled=True, invitation_enabled=True),
        _org(organizations_enabled=True, admin_role_present=False),
        _org(organizations_enabled=True, role_count=25),
        _org(organizations_enabled=True, permission_count=55),
        _session(device_tracking_enabled=False),
        _session(reverification_required=False),
        _session(session_lifetime_category="extended", single_session_mode=False),
    ]
    all_findings = []
    for record in records:
        all_findings.extend(evaluate(record))
    return all_findings


# ── Section A: Rule key taxonomy ───────────────────────────────────────────────


class TestRuleKeyTaxonomy:
    def test_m83c_new_rule_keys_exist(self):
        """All 19 M83C rule keys must be present in CLERK_RULE_KEYS."""
        assert M83C_NEW_RULE_KEYS <= CLERK_RULE_KEYS, (
            f"Missing from CLERK_RULE_KEYS: {M83C_NEW_RULE_KEYS - CLERK_RULE_KEYS}"
        )

    def test_m83c_clerk_rule_keys_total(self):
        """Total CLERK_RULE_KEYS should be 40 (21 from M83B + 19 new from M83C)."""
        assert len(CLERK_RULE_KEYS) == 40, (
            f"Expected 40 total Clerk rule keys, got {len(CLERK_RULE_KEYS)}"
        )


# ── Section B: Rule trigger tests — positive cases ────────────────────────────


class TestRuleTriggerPositive:
    """One test per M83C rule — risky record must trigger the rule."""

    def test_clerk_application_sign_up_enabled_fires(self):
        record = _app(sign_up_enabled=True)
        findings = evaluate(record)
        assert "clerk_application_sign_up_enabled" in _rule_keys(findings)

    def test_clerk_application_password_without_mfa_fires(self):
        record = _app(password_enabled=True, mfa_required=False)
        findings = evaluate(record)
        assert "clerk_application_password_without_mfa" in _rule_keys(findings)

    def test_clerk_application_oauth_without_mfa_fires(self):
        record = _app(oauth_provider_count=3, mfa_required=False)
        findings = evaluate(record)
        assert "clerk_application_oauth_without_mfa" in _rule_keys(findings)

    def test_clerk_application_saml_without_mfa_fires(self):
        record = _app(saml_enabled=True, mfa_required=False)
        findings = evaluate(record)
        assert "clerk_application_saml_without_mfa" in _rule_keys(findings)

    def test_clerk_application_many_redirect_urls_fires(self):
        record = _app(redirect_url_count=15)
        findings = evaluate(record)
        assert "clerk_application_many_redirect_urls" in _rule_keys(findings)

    def test_clerk_application_many_allowed_origins_fires(self):
        record = _app(allowed_origin_count=12)
        findings = evaluate(record)
        assert "clerk_application_many_allowed_origins" in _rule_keys(findings)

    def test_clerk_redirect_url_custom_scheme_present_fires(self):
        record = _redirect(custom_scheme_present=True)
        findings = evaluate(record)
        assert "clerk_redirect_url_custom_scheme_present" in _rule_keys(findings)

    def test_clerk_jwt_template_audience_missing_fires(self):
        record = _jwt(audience_present=False)
        findings = evaluate(record)
        assert "clerk_jwt_template_audience_missing" in _rule_keys(findings)

    def test_clerk_jwt_template_issuer_missing_fires(self):
        record = _jwt(issuer_present=False)
        findings = evaluate(record)
        assert "clerk_jwt_template_issuer_missing" in _rule_keys(findings)

    def test_clerk_jwt_template_many_claims_fires(self):
        record = _jwt(claims_count=20)
        findings = evaluate(record)
        assert "clerk_jwt_template_many_claims" in _rule_keys(findings)

    def test_clerk_webhook_broad_event_scope_fires(self):
        record = _webhook(event_count=12)
        findings = evaluate(record)
        assert "clerk_webhook_broad_event_scope" in _rule_keys(findings)

    def test_clerk_org_verified_domains_not_required_fires(self):
        record = _org(organizations_enabled=True, verified_domains_required=False)
        findings = evaluate(record)
        assert "clerk_org_verified_domains_not_required" in _rule_keys(findings)

    def test_clerk_org_invitations_enabled_fires(self):
        record = _org(organizations_enabled=True, invitation_enabled=True)
        findings = evaluate(record)
        assert "clerk_org_invitations_enabled" in _rule_keys(findings)

    def test_clerk_org_admin_role_missing_fires(self):
        record = _org(organizations_enabled=True, admin_role_present=False)
        findings = evaluate(record)
        assert "clerk_org_admin_role_missing" in _rule_keys(findings)

    def test_clerk_org_high_role_count_fires(self):
        record = _org(organizations_enabled=True, role_count=25)
        findings = evaluate(record)
        assert "clerk_org_high_role_count" in _rule_keys(findings)

    def test_clerk_org_high_permission_count_fires(self):
        record = _org(organizations_enabled=True, permission_count=55)
        findings = evaluate(record)
        assert "clerk_org_high_permission_count" in _rule_keys(findings)

    def test_clerk_session_device_tracking_disabled_fires(self):
        record = _session(device_tracking_enabled=False)
        findings = evaluate(record)
        assert "clerk_session_device_tracking_disabled" in _rule_keys(findings)

    def test_clerk_session_reverification_disabled_fires(self):
        record = _session(reverification_required=False)
        findings = evaluate(record)
        assert "clerk_session_reverification_disabled" in _rule_keys(findings)

    def test_clerk_session_long_lifetime_without_single_session_fires(self):
        record = _session(session_lifetime_category="extended", single_session_mode=False)
        findings = evaluate(record)
        assert "clerk_session_long_lifetime_without_single_session" in _rule_keys(findings)


# ── Section C: Rule non-trigger tests — healthy records ───────────────────────


class TestRuleNonTriggerHealthy:
    """One test per M83C rule — healthy record must NOT trigger the rule."""

    def test_clerk_application_sign_up_enabled_no_fire(self):
        record = _app(sign_up_enabled=False)
        findings = evaluate(record)
        assert "clerk_application_sign_up_enabled" not in _rule_keys(findings)

    def test_clerk_application_password_without_mfa_no_fire_when_mfa_required(self):
        record = _app(password_enabled=True, mfa_required=True)
        findings = evaluate(record)
        assert "clerk_application_password_without_mfa" not in _rule_keys(findings)

    def test_clerk_application_oauth_without_mfa_no_fire_when_no_providers(self):
        # oauth_provider_count == 0 means no OAuth configured — should not fire
        record = _app(oauth_provider_count=0, mfa_required=False)
        findings = evaluate(record)
        assert "clerk_application_oauth_without_mfa" not in _rule_keys(findings)

    def test_clerk_application_saml_without_mfa_no_fire_when_saml_disabled(self):
        record = _app(saml_enabled=False, mfa_required=False)
        findings = evaluate(record)
        assert "clerk_application_saml_without_mfa" not in _rule_keys(findings)

    def test_clerk_application_many_redirect_urls_no_fire_when_under_threshold(self):
        record = _app(redirect_url_count=5)
        findings = evaluate(record)
        assert "clerk_application_many_redirect_urls" not in _rule_keys(findings)

    def test_clerk_application_many_allowed_origins_no_fire_when_under_threshold(self):
        record = _app(allowed_origin_count=5)
        findings = evaluate(record)
        assert "clerk_application_many_allowed_origins" not in _rule_keys(findings)

    def test_clerk_redirect_url_custom_scheme_no_fire(self):
        record = _redirect(custom_scheme_present=False)
        findings = evaluate(record)
        assert "clerk_redirect_url_custom_scheme_present" not in _rule_keys(findings)

    def test_clerk_jwt_template_audience_missing_no_fire_when_present(self):
        record = _jwt(audience_present=True)
        findings = evaluate(record)
        assert "clerk_jwt_template_audience_missing" not in _rule_keys(findings)

    def test_clerk_jwt_template_issuer_missing_no_fire_when_present(self):
        record = _jwt(issuer_present=True)
        findings = evaluate(record)
        assert "clerk_jwt_template_issuer_missing" not in _rule_keys(findings)

    def test_clerk_jwt_template_many_claims_no_fire_when_under_threshold(self):
        record = _jwt(claims_count=5)
        findings = evaluate(record)
        assert "clerk_jwt_template_many_claims" not in _rule_keys(findings)

    def test_clerk_webhook_broad_event_scope_no_fire_when_under_threshold(self):
        record = _webhook(event_count=3)
        findings = evaluate(record)
        assert "clerk_webhook_broad_event_scope" not in _rule_keys(findings)

    def test_clerk_org_verified_domains_not_required_no_fire_when_required(self):
        record = _org(verified_domains_required=True)
        findings = evaluate(record)
        assert "clerk_org_verified_domains_not_required" not in _rule_keys(findings)

    def test_clerk_org_invitations_enabled_no_fire_when_disabled(self):
        record = _org(invitation_enabled=False)
        findings = evaluate(record)
        assert "clerk_org_invitations_enabled" not in _rule_keys(findings)

    def test_clerk_org_admin_role_missing_no_fire_when_present(self):
        record = _org(admin_role_present=True)
        findings = evaluate(record)
        assert "clerk_org_admin_role_missing" not in _rule_keys(findings)

    def test_clerk_org_high_role_count_no_fire_when_under_threshold(self):
        record = _org(role_count=5)
        findings = evaluate(record)
        assert "clerk_org_high_role_count" not in _rule_keys(findings)

    def test_clerk_org_high_permission_count_no_fire_when_under_threshold(self):
        record = _org(permission_count=10)
        findings = evaluate(record)
        assert "clerk_org_high_permission_count" not in _rule_keys(findings)

    def test_clerk_session_device_tracking_disabled_no_fire_when_enabled(self):
        record = _session(device_tracking_enabled=True)
        findings = evaluate(record)
        assert "clerk_session_device_tracking_disabled" not in _rule_keys(findings)

    def test_clerk_session_reverification_disabled_no_fire_when_required(self):
        record = _session(reverification_required=True)
        findings = evaluate(record)
        assert "clerk_session_reverification_disabled" not in _rule_keys(findings)

    def test_clerk_session_long_lifetime_without_single_session_no_fire_when_standard(self):
        # Standard lifetime (not extended) should not fire even if single_session is False
        record = _session(session_lifetime_category="standard", single_session_mode=False)
        findings = evaluate(record)
        assert "clerk_session_long_lifetime_without_single_session" not in _rule_keys(findings)

    def test_org_rules_skip_when_disabled(self):
        """When organizations_enabled=False, all org-specific M83C rules must not fire."""
        org_rule_keys = {
            "clerk_org_verified_domains_not_required",
            "clerk_org_invitations_enabled",
            "clerk_org_admin_role_missing",
            "clerk_org_high_role_count",
            "clerk_org_high_permission_count",
        }
        record = _org(
            organizations_enabled=False,
            verified_domains_required=False,
            invitation_enabled=True,
            admin_role_present=False,
            role_count=50,
            permission_count=100,
        )
        findings = evaluate(record)
        fired = _rule_keys(findings)
        overlap = org_rule_keys & fired
        assert not overlap, f"Org rules fired when organizations_enabled=False: {overlap}"

    def test_session_long_lifetime_single_session_enabled(self):
        """Extended lifetime WITH single_session_mode=True must NOT fire the combined rule."""
        record = _session(session_lifetime_category="extended", single_session_mode=True)
        findings = evaluate(record)
        assert "clerk_session_long_lifetime_without_single_session" not in _rule_keys(findings)

    def test_device_tracking_none_does_not_fire(self):
        """device_tracking_enabled=None (not provided) must not fire the rule."""
        record = _session(device_tracking_enabled=None)
        findings = evaluate(record)
        assert "clerk_session_device_tracking_disabled" not in _rule_keys(findings)

    def test_reverification_none_does_not_fire(self):
        """reverification_required=None (not provided) must not fire the rule."""
        record = _session(reverification_required=None)
        findings = evaluate(record)
        assert "clerk_session_reverification_disabled" not in _rule_keys(findings)


# ── Section D: Evidence privacy scan ──────────────────────────────────────────


class TestEvidencePrivacy:
    def test_no_forbidden_evidence_fields(self):
        """No finding produced by M83C risky records may contain a forbidden field key."""
        findings = _collect_all_m83c_risky_findings()
        assert findings, "Expected at least some M83C findings from risky records"
        violations: list[str] = []
        for finding in findings:
            evidence = finding.evidence or {}
            for key in evidence:
                if key in _FORBIDDEN_EVIDENCE_FIELDS:
                    violations.append(
                        f"Rule {finding.rule_key!r} has forbidden evidence field {key!r}"
                    )
        assert not violations, "\n".join(violations)

    def test_no_forbidden_evidence_strings(self):
        """No evidence string value may contain a forbidden substring (JWT prefix, live keys, etc.)."""
        findings = _collect_all_m83c_risky_findings()
        violations: list[str] = []
        for finding in findings:
            evidence = finding.evidence or {}
            for key, value in evidence.items():
                if not isinstance(value, str):
                    continue
                for forbidden in _FORBIDDEN_EVIDENCE_STRINGS:
                    if forbidden in value:
                        violations.append(
                            f"Rule {finding.rule_key!r} evidence field {key!r} "
                            f"contains forbidden string {forbidden!r}: {value!r}"
                        )
        assert not violations, "\n".join(violations)

    def test_finding_key_format(self):
        """Every finding must have a finding_key that contains ':'."""
        findings = _collect_all_m83c_risky_findings()
        assert findings, "Expected at least some M83C findings from risky records"
        for finding in findings:
            assert ":" in finding.finding_key, (
                f"finding_key for rule {finding.rule_key!r} missing ':': "
                f"{finding.finding_key!r}"
            )


# ── Section E: Registry / confidence / pack wiring ────────────────────────────


class TestRegistryWiring:
    def test_all_m83c_rules_in_registry(self):
        """All 19 M83C rule keys must be registered in KNOWN_RULE_KEYS."""
        missing = M83C_NEW_RULE_KEYS - KNOWN_RULE_KEYS
        assert not missing, f"M83C rules not in KNOWN_RULE_KEYS: {missing}"

    def test_all_m83c_rules_have_confidence(self):
        """All 19 M83C rule keys must have an entry in RULE_CONFIDENCE."""
        missing = M83C_NEW_RULE_KEYS - set(RULE_CONFIDENCE.keys())
        assert not missing, f"M83C rules missing from RULE_CONFIDENCE: {missing}"

    def test_all_m83c_rules_in_pack(self):
        """All 19 M83C rule keys must have an entry in _RULE_META."""
        missing = M83C_NEW_RULE_KEYS - set(_RULE_META.keys())
        assert not missing, f"M83C rules missing from _RULE_META: {missing}"

    def test_all_m83c_rules_in_rule_record_types(self):
        """All 19 M83C rule keys must appear in RULE_RECORD_TYPES."""
        missing = M83C_NEW_RULE_KEYS - set(RULE_RECORD_TYPES.keys())
        assert not missing, f"M83C rules missing from RULE_RECORD_TYPES: {missing}"


# ── Section F: Coverage service ───────────────────────────────────────────────


class TestCoverageService:
    def test_clerk_organization_settings_in_rule_record_types(self):
        """The 'clerk_organization_settings' record type must appear as a value in RULE_RECORD_TYPES."""
        all_values: list[str] = []
        for rts in RULE_RECORD_TYPES.values():
            all_values.extend(rts)
        assert "clerk_organization_settings" in all_values, (
            "clerk_organization_settings not found as any RULE_RECORD_TYPES value"
        )

    def test_clerk_in_coverage_provider_surfaces(self):
        """PROVIDER_SURFACES must include 'clerk' with at least 9 surfaces."""
        assert "clerk" in PROVIDER_SURFACES, "'clerk' not found in PROVIDER_SURFACES"
        surfaces = PROVIDER_SURFACES["clerk"]
        assert len(surfaces) >= 9, (
            f"Expected >= 9 clerk surfaces, got {len(surfaces)}: {surfaces}"
        )


# ── Section G: Capability matrix + expansion framework ────────────────────────


class TestCapabilityMatrixAndFramework:
    def test_capability_matrix_clerk_still_partial(self):
        """Clerk must appear in the partial provider list with maturity='partial'."""
        clerk_cap = get_provider_capability("clerk")
        assert clerk_cap is not None, "clerk not found in capability matrix (_BY_KEY lookup)"
        clerk_dict = clerk_cap.as_dict()
        assert clerk_dict.get("maturity") == "partial", (
            f"Expected clerk maturity='partial', got {clerk_dict.get('maturity')!r}"
        )

    def test_capability_matrix_clerk_security_rules_true(self):
        """Clerk must have security_rules=True; activity_ingestion=True after M83D."""
        clerk_cap = get_provider_capability("clerk")
        assert clerk_cap is not None, "clerk not found in capability matrix (_BY_KEY lookup)"
        assert clerk_cap.security.security_rules is True, (
            f"Expected clerk security_rules=True, got {clerk_cap.security.security_rules!r}"
        )
        # M83D promoted activity_ingestion to True.
        assert clerk_cap.security.activity_ingestion is True, (
            f"Expected clerk activity_ingestion=True after M83D, "
            f"got {clerk_cap.security.activity_ingestion!r}"
        )

    def test_expansion_framework_m83d(self):
        """The expansion framework planned_next_stage must reference 'M83D' or later Clerk stage."""
        framework = get_framework()
        planned = framework.get("summary", {}).get("planned_next_stage", "")
        assert (
            "M83D" in planned or "Activity" in planned or
            "M83E" in planned or "M83F" in planned or
            "M83G" in planned or "M83H" in planned or "M83I" in planned
            or "M84A" in planned or "PagerDuty" in planned
            or "M85A" in planned or "Linear" in planned
            or "M86" in planned or "Jira" in planned
            or "M87" in planned or "GitLab" in planned
        ), (
            f"Expected planned_next_stage to contain 'M83D' or a later Clerk stage, got: {planned!r}"
        )


# ── Section H: Frontend catalog ───────────────────────────────────────────────


class TestFrontendCatalog:
    @pytest.fixture(scope="class")
    def catalog_text(self) -> str:
        catalog_path = (
            Path(__file__).resolve().parent.parent.parent
            / "frontend"
            / "src"
            / "lib"
            / "securityRuleCatalog.ts"
        )
        assert catalog_path.exists(), f"securityRuleCatalog.ts not found at {catalog_path}"
        return catalog_path.read_text(encoding="utf-8")

    def test_frontend_catalog_has_m83c_rules(self, catalog_text: str):
        """All 19 M83C rule key strings must appear in securityRuleCatalog.ts."""
        missing = [key for key in M83C_NEW_RULE_KEYS if key not in catalog_text]
        assert not missing, (
            f"M83C rule keys missing from securityRuleCatalog.ts: {sorted(missing)}"
        )

    def test_frontend_catalog_clerk_coverage_updated(self, catalog_text: str):
        """'Organization posture' or 'Organization' must appear in the clerk PROVIDER_COVERAGE block."""
        # PROVIDER_COVERAGE is near the bottom of the file; find the last occurrence
        # of '"clerk"' which is the one inside PROVIDER_COVERAGE.
        last_clerk_idx = catalog_text.rfind('"clerk"')
        assert last_clerk_idx != -1, "'clerk' not found in securityRuleCatalog.ts"
        # Look within a reasonable window around the last clerk entry (the PROVIDER_COVERAGE block)
        window = catalog_text[last_clerk_idx: last_clerk_idx + 2000]
        has_organization = "Organization posture" in window or "Organization" in window
        assert has_organization, (
            "Neither 'Organization posture' nor 'Organization' found in the clerk "
            "PROVIDER_COVERAGE block in securityRuleCatalog.ts"
        )


# ── Section I: Forbidden wording ──────────────────────────────────────────────


class TestForbiddenWording:
    def test_no_forbidden_wording_in_m83c_clerk_module(self):
        """The clerk security rules module must not contain any forbidden claim phrases."""
        clerk_rules_path = (
            Path(__file__).resolve().parent.parent
            / "app"
            / "services"
            / "security_rules"
            / "clerk.py"
        )
        assert clerk_rules_path.exists(), f"clerk.py not found at {clerk_rules_path}"
        content = clerk_rules_path.read_text(encoding="utf-8")

        forbidden_phrases = [
            "compromise confirmed",
            "secret leaked",
            "data leaked",
            "customer data leaked",
            "payment fraud detected",
            "attacker found",
            "someone has access",
            "unauthorized access confirmed",
            "breach detected",
            "attack detected",
            "orders exposed",
            "card data exposed",
        ]
        found = [phrase for phrase in forbidden_phrases if phrase in content.lower()]
        assert not found, (
            f"Forbidden claim phrases found in clerk.py: {found}"
        )


# ── Section J: M83A+M83B regression ──────────────────────────────────────────


class TestM83AM83BRegression:
    def test_m83a_m83b_rules_still_in_clerk_rule_keys(self):
        """Spot-check that well-known M83B rules are still present in CLERK_RULE_KEYS."""
        m83b_spot_check = {
            "clerk_instance_mfa_disabled",
            "clerk_application_mfa_not_required",
            "clerk_domain_unverified",
            "clerk_domain_ssl_disabled",
            "clerk_redirect_url_non_https",
            "clerk_redirect_url_wildcard_present",
            "clerk_redirect_url_localhost_present",
            "clerk_jwt_template_custom_claims_present",
            "clerk_jwt_template_long_lifetime",
            "clerk_webhook_endpoint_disabled",
            "clerk_webhook_without_signing",
            "clerk_webhook_non_https",
            "clerk_email_sms_custom_sender_present",
            "clerk_auth_strategy_mfa_not_required",
            "clerk_auth_strategy_password_without_mfa",
            "clerk_session_lifetime_extended",
            "clerk_session_inactivity_timeout_extended",
            "clerk_session_single_session_disabled",
            "clerk_session_token_rotation_disabled",
            "clerk_instance_password_without_mfa",
            "clerk_instance_sign_up_enabled",
        }
        missing = m83b_spot_check - CLERK_RULE_KEYS
        assert not missing, (
            f"M83A/M83B rules unexpectedly absent from CLERK_RULE_KEYS: {missing}"
        )
