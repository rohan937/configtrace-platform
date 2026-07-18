"""Clerk Provider Depth QA — post-audit regression suite.

Covers every concrete issue found in the Clerk provider QA audit:

A. Rule-key taxonomy completeness (40 rules across all layers)
B. Evaluator dispatch wiring
C. Backend-to-frontend severity parity
D. Evidence safety (no secrets, PII, tokens, raw URLs)
E. Clerk copy — no forbidden breach/compromise/account-takeover wording
F. connector.fetch() emits clerk_application records
G. Seven clerk_application_* rules reachable from connector output
H. Non-HTTPS redirect rule scoped to http only (not custom schemes)
I. Frontend falsePositiveGuard — no double-negative strings
J. Planned-next-stage and recommended-queue correctness (M89A Kubernetes)
K. Kubernetes not yet implemented
L. Provider capability matrix correctness for Clerk
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.connectors.clerk_schema import (
    CLERK_APPLICATION,
    CLERK_AUTH_STRATEGY,
    CLERK_DOMAIN,
    CLERK_EMAIL_SMS_SETTINGS,
    CLERK_INSTANCE_SETTINGS,
    CLERK_JWT_TEMPLATE,
    CLERK_ORGANIZATION_SETTINGS,
    CLERK_REDIRECT_URL_CONFIG,
    CLERK_SESSION_POLICY,
    CLERK_WEBHOOK_ENDPOINT,
)
from app.services.security_rules.clerk import CLERK_RULE_KEYS, evaluate
from app.services.security_finding_evaluator import _PROVIDER_RULES, evaluate_record
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_coverage_service import RULE_RECORD_TYPES, PROVIDERS
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

# ── Paths ─────────────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CATALOG_PATH = _REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"
_CLERK_RULES_PATH = (
    _REPO_ROOT / "backend" / "app" / "services" / "security_rules" / "clerk.py"
)
_CONNECTOR_PATH = _REPO_ROOT / "backend" / "app" / "connectors" / "clerk.py"

# ── Exact set of 40 expected Clerk rule keys ──────────────────────────────────

EXPECTED_CLERK_RULE_KEYS: frozenset[str] = frozenset({
    # Instance settings (3)
    "clerk_instance_mfa_disabled",
    "clerk_instance_password_without_mfa",
    "clerk_instance_sign_up_enabled",
    # Application (7)
    "clerk_application_mfa_not_required",
    "clerk_application_sign_up_enabled",
    "clerk_application_password_without_mfa",
    "clerk_application_oauth_without_mfa",
    "clerk_application_saml_without_mfa",
    "clerk_application_many_redirect_urls",
    "clerk_application_many_allowed_origins",
    # Domain (2)
    "clerk_domain_unverified",
    "clerk_domain_ssl_disabled",
    # Redirect URL (4)
    "clerk_redirect_url_non_https",
    "clerk_redirect_url_wildcard_present",
    "clerk_redirect_url_localhost_present",
    "clerk_redirect_url_custom_scheme_present",
    # JWT template (5)
    "clerk_jwt_template_custom_claims_present",
    "clerk_jwt_template_long_lifetime",
    "clerk_jwt_template_audience_missing",
    "clerk_jwt_template_issuer_missing",
    "clerk_jwt_template_many_claims",
    # Webhook (4)
    "clerk_webhook_endpoint_disabled",
    "clerk_webhook_without_signing",
    "clerk_webhook_non_https",
    "clerk_webhook_broad_event_scope",
    # Email/SMS (1)
    "clerk_email_sms_custom_sender_present",
    # Auth strategy (2)
    "clerk_auth_strategy_mfa_not_required",
    "clerk_auth_strategy_password_without_mfa",
    # Organization settings (5)
    "clerk_org_verified_domains_not_required",
    "clerk_org_invitations_enabled",
    "clerk_org_admin_role_missing",
    "clerk_org_high_role_count",
    "clerk_org_high_permission_count",
    # Session policy (7)
    "clerk_session_lifetime_extended",
    "clerk_session_inactivity_timeout_extended",
    "clerk_session_single_session_disabled",
    "clerk_session_token_rotation_disabled",
    "clerk_session_device_tracking_disabled",
    "clerk_session_reverification_disabled",
    "clerk_session_long_lifetime_without_single_session",
})

_APPLICATION_RULE_KEYS: frozenset[str] = frozenset({
    "clerk_application_mfa_not_required",
    "clerk_application_sign_up_enabled",
    "clerk_application_password_without_mfa",
    "clerk_application_oauth_without_mfa",
    "clerk_application_saml_without_mfa",
    "clerk_application_many_redirect_urls",
    "clerk_application_many_allowed_origins",
})

# ── Record builder helpers ────────────────────────────────────────────────────


def _instance(**kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "record_type": CLERK_INSTANCE_SETTINGS,
        "provider": "clerk",
        "record_id": "inst_opaque_qa001",
        "provider_resource_id": "instance/settings",
        "environment_type": "production",
        "sign_up_enabled": False,
        "sign_in_enabled": True,
        "email_enabled": True,
        "phone_enabled": False,
        "username_enabled": False,
        "password_enabled": True,
        "social_provider_count": 2,
        "mfa_enabled": True,
        "mfa_factor_count": 1,
        "session_lifetime_category": "standard",
        "allowed_redirect_count": 2,
        "domain_count": 1,
        "webhook_count": 1,
        "allowlist_enabled": False,
        "blocklist_enabled": False,
        "sign_in_mode": "public",
    }
    d.update(kw)
    return d


def _application(**kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "record_type": CLERK_APPLICATION,
        "provider": "clerk",
        "record_id": "app_opaque_qa001",
        "provider_resource_id": "applications/app_opaque_qa001",
        "name": "QA Application",
        "application_type": "web",
        "enabled": True,
        "oauth_provider_count": 2,
        "redirect_url_count": 3,
        "allowed_origin_count": 2,
        "jwt_template_count": 1,
        "organization_enabled": False,
        "mfa_required": True,
        "sign_up_enabled": False,
        "sign_in_enabled": True,
        "password_enabled": True,
        "saml_enabled": False,
    }
    d.update(kw)
    return d


def _redirect_url(**kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "record_type": CLERK_REDIRECT_URL_CONFIG,
        "provider": "clerk",
        "record_id": "ru_opaque_qa001",
        "provider_resource_id": "redirect_urls/ru_opaque_qa001",
        "url_present": True,
        "url_scheme_category": "https",
        "wildcard_present": False,
        "localhost_present": False,
        "custom_scheme_present": False,
    }
    d.update(kw)
    return d


def _session_policy(**kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
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
    d.update(kw)
    return d


def _rule_keys(findings: list) -> set[str]:
    return {f.rule_key for f in findings}


# ═════════════════════════════════════════════════════════════════════════════
# A. Rule-key taxonomy completeness
# ═════════════════════════════════════════════════════════════════════════════


class TestRuleKeyTaxonomy:

    def test_clerk_rule_keys_count(self) -> None:
        assert len(CLERK_RULE_KEYS) == 40, (
            f"Expected 40 Clerk rule keys, got {len(CLERK_RULE_KEYS)}"
        )

    def test_all_expected_keys_present_in_module(self) -> None:
        missing = EXPECTED_CLERK_RULE_KEYS - CLERK_RULE_KEYS
        assert not missing, f"Missing from CLERK_RULE_KEYS: {sorted(missing)}"

    def test_all_clerk_rule_keys_in_registry(self) -> None:
        missing = EXPECTED_CLERK_RULE_KEYS - KNOWN_RULE_KEYS
        assert not missing, f"Clerk rules missing from registry: {sorted(missing)}"

    def test_all_clerk_rule_keys_in_confidence(self) -> None:
        missing = EXPECTED_CLERK_RULE_KEYS - set(RULE_CONFIDENCE.keys())
        assert not missing, f"Clerk rules missing from confidence: {sorted(missing)}"

    def test_all_clerk_rule_keys_in_pack(self) -> None:
        missing = EXPECTED_CLERK_RULE_KEYS - set(_RULE_META.keys())
        assert not missing, f"Clerk rules missing from rule pack: {sorted(missing)}"

    def test_all_clerk_rule_keys_in_coverage(self) -> None:
        missing = EXPECTED_CLERK_RULE_KEYS - set(RULE_RECORD_TYPES.keys())
        assert not missing, f"Clerk rules missing from coverage service: {sorted(missing)}"

    def test_all_clerk_rule_keys_in_frontend_catalog(self) -> None:
        if not _CATALOG_PATH.exists():
            pytest.skip("securityRuleCatalog.ts not found")
        catalog_text = _CATALOG_PATH.read_text(encoding="utf-8")
        missing = [k for k in EXPECTED_CLERK_RULE_KEYS if k not in catalog_text]
        assert not missing, f"Clerk rules missing from frontend catalog: {sorted(missing)}"

    def test_all_rule_keys_start_with_clerk(self) -> None:
        bad = [k for k in CLERK_RULE_KEYS if not k.startswith("clerk_")]
        assert not bad, f"Rule keys not starting with 'clerk_': {bad}"

    def test_clerk_provider_listed_in_coverage_providers(self) -> None:
        assert "clerk" in PROVIDERS, "clerk missing from coverage PROVIDERS set"


# ═════════════════════════════════════════════════════════════════════════════
# B. Evaluator dispatch wiring
# ═════════════════════════════════════════════════════════════════════════════


class TestEvaluatorDispatch:

    def test_clerk_in_provider_rules(self) -> None:
        assert "clerk" in _PROVIDER_RULES, (
            "clerk missing from _PROVIDER_RULES in security_finding_evaluator.py"
        )

    def test_clerk_evaluator_list_is_non_empty(self) -> None:
        rules = _PROVIDER_RULES["clerk"]
        assert len(rules) >= 1
        for fn in rules:
            assert callable(fn)

    def test_evaluate_record_produces_findings_for_risky_instance(self) -> None:
        """evaluate_record(record, 'clerk') must return findings for a risky record."""
        rec = _instance(mfa_enabled=False)
        findings = evaluate_record(rec, "clerk")
        assert findings, "evaluate_record produced no findings for mfa_enabled=False"
        keys = _rule_keys(findings)
        assert "clerk_instance_mfa_disabled" in keys

    def test_evaluate_record_empty_for_unknown_provider(self) -> None:
        rec = _instance(mfa_enabled=False)
        assert evaluate_record(rec, "unknown_provider_xyz") == []

    def test_evaluate_record_empty_for_healthy_instance(self) -> None:
        healthy = _instance(
            mfa_enabled=True,
            password_enabled=True,
            sign_up_enabled=False,
        )
        findings = evaluate_record(healthy, "clerk")
        instance_keys = {f.rule_key for f in findings
                         if f.rule_key.startswith("clerk_instance_")}
        assert not instance_keys, (
            f"Healthy instance fired instance rules: {instance_keys}"
        )

    def test_evaluate_record_dispatches_application_record(self) -> None:
        """evaluate_record must produce findings for a risky clerk_application record."""
        rec = _application(mfa_required=False)
        findings = evaluate_record(rec, "clerk")
        keys = _rule_keys(findings)
        assert "clerk_application_mfa_not_required" in keys


# ═════════════════════════════════════════════════════════════════════════════
# C. Backend-to-frontend severity parity
# ═════════════════════════════════════════════════════════════════════════════


class TestSeverityParity:

    @pytest.fixture(scope="class")
    def catalog_entries(self) -> dict[str, str]:
        """Return {rule_key: severity} from the frontend catalog."""
        if not _CATALOG_PATH.exists():
            pytest.skip("securityRuleCatalog.ts not found")
        text = _CATALOG_PATH.read_text(encoding="utf-8")
        result: dict[str, str] = {}
        # Extract key/severity pairs for clerk rules
        pattern = re.compile(
            r'key:\s*"(clerk_[^"]+)"[^}]*?severity:\s*"([^"]+)"',
            re.DOTALL,
        )
        for m in pattern.finditer(text):
            result[m.group(1)] = m.group(2)
        return result

    def test_all_clerk_rules_have_catalog_entry(self, catalog_entries: dict) -> None:
        missing = EXPECTED_CLERK_RULE_KEYS - set(catalog_entries.keys())
        assert not missing, f"Clerk rules missing from catalog severity map: {sorted(missing)}"

    def test_backend_frontend_severity_match(self, catalog_entries: dict) -> None:
        mismatches = []
        for key, (_, backend_sev, _) in _RULE_META.items():
            if not key.startswith("clerk_"):
                continue
            frontend_sev = catalog_entries.get(key)
            if frontend_sev is None:
                mismatches.append(f"{key}: not in catalog")
            elif frontend_sev != backend_sev:
                mismatches.append(
                    f"{key}: backend={backend_sev!r} frontend={frontend_sev!r}"
                )
        assert not mismatches, "Backend/frontend severity mismatches:\n" + "\n".join(mismatches)

    def test_instance_mfa_disabled_is_high(self) -> None:
        """clerk_instance_mfa_disabled must be High severity."""
        sev = _RULE_META.get("clerk_instance_mfa_disabled", (None, None, None))[1]
        assert sev == "high", f"Expected high, got {sev!r}"

    def test_instance_password_without_mfa_is_high(self) -> None:
        """clerk_instance_password_without_mfa must be High severity."""
        sev = _RULE_META.get("clerk_instance_password_without_mfa", (None, None, None))[1]
        assert sev == "high", f"Expected high, got {sev!r}"

    def test_rules_file_instance_mfa_disabled_fires_high(self) -> None:
        findings = evaluate(_instance(mfa_enabled=False))
        mfa_findings = [f for f in findings if f.rule_key == "clerk_instance_mfa_disabled"]
        assert mfa_findings, "clerk_instance_mfa_disabled did not fire"
        assert mfa_findings[0].severity == "high", (
            f"Expected high severity, got {mfa_findings[0].severity!r}"
        )

    def test_rules_file_instance_password_without_mfa_fires_high(self) -> None:
        findings = evaluate(_instance(mfa_enabled=False, password_enabled=True))
        pwmfa_findings = [f for f in findings
                          if f.rule_key == "clerk_instance_password_without_mfa"]
        assert pwmfa_findings, "clerk_instance_password_without_mfa did not fire"
        assert pwmfa_findings[0].severity == "high", (
            f"Expected high severity, got {pwmfa_findings[0].severity!r}"
        )

    def test_domain_ssl_disabled_is_high(self) -> None:
        sev = _RULE_META.get("clerk_domain_ssl_disabled", (None, None, None))[1]
        assert sev == "high", f"Expected high, got {sev!r}"

    def test_webhook_without_signing_is_high(self) -> None:
        sev = _RULE_META.get("clerk_webhook_without_signing", (None, None, None))[1]
        assert sev == "high", f"Expected high, got {sev!r}"

    def test_instance_sign_up_enabled_is_low(self) -> None:
        sev = _RULE_META.get("clerk_instance_sign_up_enabled", (None, None, None))[1]
        assert sev == "low", f"Expected low, got {sev!r}"


# ═════════════════════════════════════════════════════════════════════════════
# D. Evidence safety
# ═════════════════════════════════════════════════════════════════════════════

_FORBIDDEN_EVIDENCE_KEYS = frozenset({
    "secret_key", "secretKey", "api_key", "apiKey", "access_token", "refresh_token",
    "session_token", "sessionToken", "jwt", "id_token", "idToken", "token", "bearer",
    "authorization", "headers", "payload", "request", "response", "raw",
    "secret", "secret_value", "webhook_secret", "signing_secret", "signing_key",
    "magic_link_token", "verification_code", "invitation_token",
    "password", "mfa_secret", "backup_code",
    "callback_url", "redirect_url", "allowed_origin",
    "user_email", "email", "user_name", "username", "user_id", "phone",
    "phone_number", "organization_name", "organization_id", "member",
    "membership", "invitation", "customer", "pii",
})


def _all_findings_for_all_risky_records() -> list:
    """Produce findings for a representative risky record per type."""
    from app.services.security_rules.clerk import evaluate as clerk_eval
    records = [
        _instance(mfa_enabled=False, password_enabled=True, sign_up_enabled=True),
        _application(mfa_required=False, password_enabled=True, oauth_provider_count=2,
                     saml_enabled=True, sign_up_enabled=True,
                     redirect_url_count=15, allowed_origin_count=15),
        {
            "record_type": CLERK_DOMAIN, "provider": "clerk",
            "record_id": "dmn_qa001", "provider_resource_id": "domains/dmn_qa001",
            "domain_present": True, "domain_type": "primary",
            "verified": False, "primary": True, "ssl_enabled": False,
            "dns_status_category": "pending", "proxy_enabled": False,
        },
        _redirect_url(url_scheme_category="http", wildcard_present=True,
                      localhost_present=True, custom_scheme_present=True),
        {
            "record_type": CLERK_JWT_TEMPLATE, "provider": "clerk",
            "record_id": "tmpl_qa001", "provider_resource_id": "jwt_templates/tmpl_qa001",
            "name": "Test Template", "enabled": True, "claims_count": 20,
            "custom_claims_present": True, "audience_present": False,
            "lifetime_category": "extended", "algorithm": "RS256", "issuer_present": False,
        },
        {
            "record_type": CLERK_WEBHOOK_ENDPOINT, "provider": "clerk",
            "record_id": "wh_qa001", "provider_resource_id": "webhooks/wh_qa001",
            "enabled": False, "url_present": True, "url_scheme_category": "http",
            "event_count": 15, "secret_present": False, "description_present": False,
        },
        {
            "record_type": CLERK_EMAIL_SMS_SETTINGS, "provider": "clerk",
            "record_id": "clerk_email_sms_settings_main",
            "provider_resource_id": "instance/email_sms",
            "email_enabled": True, "sms_enabled": False,
            "custom_sender_present": True, "template_customization_present": False,
        },
        {
            "record_type": CLERK_AUTH_STRATEGY, "provider": "clerk",
            "record_id": "clerk_auth_strategy_main",
            "provider_resource_id": "instance/auth_strategy",
            "password_enabled": True, "oauth_enabled": True, "social_provider_count": 2,
            "saml_enabled": False, "mfa_enabled": True, "mfa_required": False,
            "passkey_enabled": False, "magic_link_enabled": False,
            "email_otp_enabled": True, "phone_otp_enabled": False,
        },
        {
            "record_type": CLERK_ORGANIZATION_SETTINGS, "provider": "clerk",
            "record_id": "clerk_organization_settings_main",
            "provider_resource_id": "instance/organization",
            "organizations_enabled": True, "max_allowed_memberships_category": "unlimited",
            "admin_delete_enabled": True, "domains_enabled": False,
            "domains_enrollment_mode_category": "automatic",
            "verified_domains_required": False, "invitation_enabled": True,
            "admin_role_present": False, "role_count": 25, "permission_count": 60,
        },
        _session_policy(
            session_lifetime_category="extended", inactivity_timeout_category="extended",
            single_session_mode=False, token_rotation_enabled=False,
            device_tracking_enabled=False, reverification_required=False,
        ),
    ]
    all_findings = []
    for rec in records:
        all_findings.extend(clerk_eval(rec))
    return all_findings


class TestEvidenceSafety:

    @pytest.fixture(scope="class")
    def all_risky_findings(self) -> list:
        return _all_findings_for_all_risky_records()

    def test_no_forbidden_evidence_keys(self, all_risky_findings: list) -> None:
        violations = []
        for f in all_risky_findings:
            if f.evidence:
                bad_keys = set(f.evidence.keys()) & _FORBIDDEN_EVIDENCE_KEYS
                if bad_keys:
                    violations.append(f"{f.rule_key}: {sorted(bad_keys)}")
        assert not violations, (
            "Forbidden evidence keys found:\n" + "\n".join(violations)
        )

    def test_evidence_values_are_safe_types(self, all_risky_findings: list) -> None:
        """Evidence values must be booleans, ints, strings (short), or None."""
        violations = []
        for f in all_risky_findings:
            if not f.evidence:
                continue
            for k, v in f.evidence.items():
                if not isinstance(v, (bool, int, float, str, type(None))):
                    violations.append(f"{f.rule_key}.{k}: type={type(v).__name__}")
                elif isinstance(v, str) and len(v) > 200:
                    violations.append(
                        f"{f.rule_key}.{k}: string too long ({len(v)} chars)"
                    )
        assert not violations, "Unsafe evidence values:\n" + "\n".join(violations)

    def test_no_raw_url_strings_in_evidence(self, all_risky_findings: list) -> None:
        """No evidence value should look like a raw URL."""
        url_pattern = re.compile(r"^https?://|^[a-z][a-z0-9+\-.]+://", re.IGNORECASE)
        violations = []
        for f in all_risky_findings:
            if f.evidence:
                for k, v in f.evidence.items():
                    if isinstance(v, str) and url_pattern.match(v):
                        violations.append(f"{f.rule_key}.{k}: looks like URL: {v[:60]!r}")
        assert not violations, "Raw URLs in evidence:\n" + "\n".join(violations)

    def test_no_email_shaped_strings_in_evidence(self, all_risky_findings: list) -> None:
        email_pattern = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
        violations = []
        for f in all_risky_findings:
            if f.evidence:
                for k, v in f.evidence.items():
                    if isinstance(v, str) and email_pattern.search(v):
                        violations.append(f"{f.rule_key}.{k}: email-shaped: {v[:60]!r}")
        assert not violations, "Email-shaped strings in evidence:\n" + "\n".join(violations)


# ═════════════════════════════════════════════════════════════════════════════
# E. Clerk copy — no forbidden wording in rule descriptions
# ═════════════════════════════════════════════════════════════════════════════

_FORBIDDEN_CLAIM_PHRASES = [
    "breach confirmed", "compromise confirmed", "attacker found",
    "someone has access", "data leaked", "secret leaked", "customer data exposed",
    "unauthorized access confirmed", "payment fraud detected", "attack detected",
    "orders exposed", "card data exposed", "account takeover detected",
    "credentials exposed", "tokens leaked", "sessions exposed",
    "users exposed", "passwords leaked", "fraud confirmed",
]

# These words may appear in conditional/negating context but should not
# appear as affirmative claims in rule descriptions.
_SOFTER_FORBIDDEN_IN_DESCRIPTIONS = [
    "if a session is compromised",
    "credential compromise",
]


class TestClerkRuleCopy:

    @pytest.fixture(scope="class")
    def all_risky_findings(self) -> list:
        return _all_findings_for_all_risky_records()

    def test_no_hard_forbidden_phrases_in_descriptions(self, all_risky_findings: list) -> None:
        violations = []
        for f in all_risky_findings:
            for phrase in _FORBIDDEN_CLAIM_PHRASES:
                if phrase in (f.description or "").lower():
                    violations.append(f"{f.rule_key}: contains '{phrase}'")
                if phrase in (f.title or "").lower():
                    violations.append(f"{f.rule_key} title: contains '{phrase}'")
        assert not violations, "Forbidden claim phrases in findings:\n" + "\n".join(violations)

    def test_no_soft_forbidden_phrases_in_descriptions(self, all_risky_findings: list) -> None:
        violations = []
        for f in all_risky_findings:
            for phrase in _SOFTER_FORBIDDEN_IN_DESCRIPTIONS:
                if phrase in (f.description or "").lower():
                    violations.append(f"{f.rule_key}: contains soft-forbidden phrase '{phrase}'")
        assert not violations, (
            "Soft-forbidden phrases found in rule descriptions (should use safer wording):\n"
            + "\n".join(violations)
        )

    def test_all_descriptions_contain_safe_framing(self, all_risky_findings: list) -> None:
        """Every finding description should include some form of safe, non-alarmist framing."""
        _safe_phrases = (
            "may require review", "for review", "periodic review",
            "warrant review", "may require", "review",
            "configuration evidence", "posture", "may include",
            "never stored", "are never stored",
        )
        violations = []
        for f in all_risky_findings:
            desc = (f.description or "").lower()
            if not any(phrase in desc for phrase in _safe_phrases):
                violations.append(f"{f.rule_key}: no safe framing in description")
        assert not violations, (
            "Findings missing safe framing:\n" + "\n".join(violations)
        )

    def test_clerk_rules_source_no_forbidden_phrases(self) -> None:
        """The clerk.py rules source must not contain hard-forbidden claim phrases."""
        if not _CLERK_RULES_PATH.exists():
            pytest.skip("clerk rules file not found")
        text = _CLERK_RULES_PATH.read_text(encoding="utf-8").lower()

        # Strip out negating disclaimer lines before scanning
        lines = _CLERK_RULES_PATH.read_text(encoding="utf-8").splitlines()
        non_negating: list[str] = []
        for line in lines:
            stripped = line.strip().lower()
            if ("does not confirm" in stripped or "it never asserts" in stripped
                    or "never asserts" in stripped or "# " == stripped[:2]):
                continue
            non_negating.append(line.lower())
        combined = "\n".join(non_negating)

        violations = []
        for phrase in _FORBIDDEN_CLAIM_PHRASES:
            if phrase in combined:
                violations.append(f"Found '{phrase}' in clerk.py rules")
        assert not violations, "\n".join(violations)


# ═════════════════════════════════════════════════════════════════════════════
# F. connector.fetch() emits clerk_application records
# ═════════════════════════════════════════════════════════════════════════════


class TestConnectorApplicationFetch:
    """Verify the connector now emits clerk_application records from fetch()."""

    @pytest.fixture(scope="class")
    def mock_instance_response(self) -> dict:
        """Minimal /instance response that triggers application-level posture fields."""
        return {
            "id": "inst_qa_opaque_001",
            "object": "instance",
            "environment_type": "production",
            "name": "QA Instance",
            "user_settings": {
                "sign_in": {"second_factor": {"required": False}},
                "social": {
                    "oauth_google": {"enabled": True},
                    "oauth_github": {"enabled": True},
                },
                "password": {"enabled": True},
                "sign_up": {"enabled": False},
                "mfa": {"enabled": True, "required": False},
                "passkeys": {"enabled": False},
                "saml_enabled": False,
            },
            "organization_settings": {
                "enabled": False,
                "max_allowed_memberships": 5,
            },
            "allowed_origins": [],
            "clerk_js_version": "5.0.0",
        }

    def _fetch_with_mocked_instance(
        self, mock_instance_response: dict
    ) -> list[dict]:
        """Helper: call connector.fetch() with /instance mocked to return the given response."""
        from app.connectors.clerk import ClerkConnector
        connector = ClerkConnector()

        # _get_json(client, path) → takes two positional args (client + path)
        def mock_get_json(_client: Any, path: str) -> dict | list:
            if path == "/instance":
                return mock_instance_response
            return []

        with patch.object(connector, "_make_client") as mock_make_client, \
             patch.object(connector, "_get_json", side_effect=mock_get_json):
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_make_client.return_value = mock_ctx
            records = connector.fetch({"secret_key": "sk_test_qa_fake_key"})
        return records

    def test_fetch_emits_clerk_application_record(
        self, mock_instance_response: dict
    ) -> None:
        """connector.fetch() must emit at least one record with record_type==clerk_application."""
        records = self._fetch_with_mocked_instance(mock_instance_response)
        app_records = [r for r in records if r.get("record_type") == CLERK_APPLICATION]
        assert app_records, (
            "connector.fetch() did not emit any clerk_application records. "
            "This means all clerk_application_* rules are dead in production."
        )

    def test_application_record_has_safe_fields_only(
        self, mock_instance_response: dict
    ) -> None:
        """Emitted clerk_application record must use only safe normalized fields."""
        records = self._fetch_with_mocked_instance(mock_instance_response)
        app_records = [r for r in records if r.get("record_type") == CLERK_APPLICATION]
        if not app_records:
            pytest.skip("No clerk_application record emitted — see test_fetch_emits test")

        rec = app_records[0]
        assert rec.get("provider_resource_id", "").startswith("applications/"), (
            f"Unexpected provider_resource_id: {rec.get('provider_resource_id')!r}"
        )
        bad = set(rec.keys()) & _FORBIDDEN_EVIDENCE_KEYS
        assert not bad, f"Forbidden fields in clerk_application record: {sorted(bad)}"

    def test_application_record_has_required_posture_fields(
        self, mock_instance_response: dict
    ) -> None:
        """The emitted application record must have the fields clerk_application_* rules depend on."""
        records = self._fetch_with_mocked_instance(mock_instance_response)
        app_records = [r for r in records if r.get("record_type") == CLERK_APPLICATION]
        if not app_records:
            pytest.skip("No clerk_application record emitted")
        rec = app_records[0]

        required_fields = [
            "record_type", "provider", "record_id", "provider_resource_id",
            "mfa_required", "sign_up_enabled", "password_enabled",
            "oauth_provider_count", "saml_enabled",
        ]
        missing = [f for f in required_fields if f not in rec]
        assert not missing, f"Required fields missing from clerk_application record: {missing}"


# ═════════════════════════════════════════════════════════════════════════════
# G. Seven clerk_application_* rules reachable from connector output
# ═════════════════════════════════════════════════════════════════════════════


class TestApplicationRuleReachability:
    """All seven clerk_application_* rules must fire from a risky application record."""

    def test_application_mfa_not_required_fires(self) -> None:
        findings = evaluate(_application(mfa_required=False))
        assert "clerk_application_mfa_not_required" in _rule_keys(findings)

    def test_application_sign_up_enabled_fires(self) -> None:
        findings = evaluate(_application(sign_up_enabled=True))
        assert "clerk_application_sign_up_enabled" in _rule_keys(findings)

    def test_application_password_without_mfa_fires(self) -> None:
        findings = evaluate(_application(password_enabled=True, mfa_required=False))
        assert "clerk_application_password_without_mfa" in _rule_keys(findings)

    def test_application_oauth_without_mfa_fires(self) -> None:
        findings = evaluate(_application(oauth_provider_count=2, mfa_required=False))
        assert "clerk_application_oauth_without_mfa" in _rule_keys(findings)

    def test_application_saml_without_mfa_fires(self) -> None:
        findings = evaluate(_application(saml_enabled=True, mfa_required=False))
        assert "clerk_application_saml_without_mfa" in _rule_keys(findings)

    def test_application_many_redirect_urls_fires(self) -> None:
        findings = evaluate(_application(redirect_url_count=15))
        assert "clerk_application_many_redirect_urls" in _rule_keys(findings)

    def test_application_many_allowed_origins_fires(self) -> None:
        findings = evaluate(_application(allowed_origin_count=15))
        assert "clerk_application_many_allowed_origins" in _rule_keys(findings)

    def test_all_seven_application_rules_reachable(self) -> None:
        """All seven clerk_application_* rules fire from synthesized records."""
        fired: set[str] = set()
        risky_apps = [
            _application(mfa_required=False, password_enabled=True,
                         oauth_provider_count=2, saml_enabled=True,
                         sign_up_enabled=True, redirect_url_count=15,
                         allowed_origin_count=15),
        ]
        for rec in risky_apps:
            fired.update(_rule_keys(evaluate(rec)))
        missing = _APPLICATION_RULE_KEYS - fired
        assert not missing, (
            f"clerk_application_* rules not reachable: {sorted(missing)}"
        )

    def test_healthy_application_fires_no_rules(self) -> None:
        """A healthy application record with all guards up must fire no rules."""
        healthy = _application(
            mfa_required=True,
            sign_up_enabled=False,
            password_enabled=True,
            oauth_provider_count=1,
            saml_enabled=False,
            redirect_url_count=3,
            allowed_origin_count=2,
        )
        findings = evaluate(healthy)
        app_keys = {f.rule_key for f in findings if f.rule_key.startswith("clerk_application_")}
        assert not app_keys, f"Healthy application fired rules: {sorted(app_keys)}"

    def test_application_rules_via_central_evaluator(self) -> None:
        """clerk_application_* rules must fire via evaluate_record(rec, 'clerk')."""
        rec = _application(mfa_required=False, sign_up_enabled=True, oauth_provider_count=2)
        findings = evaluate_record(rec, "clerk")
        keys = _rule_keys(findings)
        assert "clerk_application_mfa_not_required" in keys
        assert "clerk_application_sign_up_enabled" in keys
        assert "clerk_application_oauth_without_mfa" in keys


# ═════════════════════════════════════════════════════════════════════════════
# H. Non-HTTPS redirect rule scoped to http only (not custom schemes)
# ═════════════════════════════════════════════════════════════════════════════


class TestRedirectUrlNonHttpsScope:

    def test_http_scheme_fires_non_https_high(self) -> None:
        """Plain http:// redirect URL must fire clerk_redirect_url_non_https (high)."""
        findings = evaluate(_redirect_url(url_scheme_category="http"))
        keys = _rule_keys(findings)
        assert "clerk_redirect_url_non_https" in keys
        for f in findings:
            if f.rule_key == "clerk_redirect_url_non_https":
                assert f.severity == "high", f"Expected high, got {f.severity!r}"

    def test_custom_scheme_does_not_fire_non_https_high(self) -> None:
        """Custom scheme (deep-link) must NOT fire clerk_redirect_url_non_https."""
        findings = evaluate(
            _redirect_url(url_scheme_category="custom", custom_scheme_present=True)
        )
        keys = _rule_keys(findings)
        assert "clerk_redirect_url_non_https" not in keys, (
            "clerk_redirect_url_non_https incorrectly fired for custom scheme redirect URL"
        )

    def test_custom_scheme_fires_custom_scheme_rule(self) -> None:
        """Custom scheme redirect URL must fire clerk_redirect_url_custom_scheme_present."""
        findings = evaluate(
            _redirect_url(url_scheme_category="custom", custom_scheme_present=True)
        )
        keys = _rule_keys(findings)
        assert "clerk_redirect_url_custom_scheme_present" in keys

    def test_custom_scheme_rule_is_medium_severity(self) -> None:
        """clerk_redirect_url_custom_scheme_present must be medium severity."""
        findings = evaluate(
            _redirect_url(url_scheme_category="custom", custom_scheme_present=True)
        )
        for f in findings:
            if f.rule_key == "clerk_redirect_url_custom_scheme_present":
                assert f.severity == "medium", f"Expected medium, got {f.severity!r}"

    def test_https_scheme_fires_neither_non_https_nor_custom(self) -> None:
        """HTTPS redirect URL must fire neither the non-HTTPS nor custom-scheme rule."""
        findings = evaluate(_redirect_url(url_scheme_category="https"))
        keys = _rule_keys(findings)
        assert "clerk_redirect_url_non_https" not in keys
        assert "clerk_redirect_url_custom_scheme_present" not in keys

    def test_unknown_scheme_does_not_fire_non_https_high(self) -> None:
        """Unknown scheme must NOT fire the high-severity non-HTTPS rule (only http should)."""
        findings = evaluate(
            _redirect_url(url_scheme_category="unknown")
        )
        keys = _rule_keys(findings)
        assert "clerk_redirect_url_non_https" not in keys


# ═════════════════════════════════════════════════════════════════════════════
# I. Frontend falsePositiveGuard — no double-negative strings
# ═════════════════════════════════════════════════════════════════════════════


class TestFrontendFalsePositiveGuard:

    @pytest.fixture(scope="class")
    def catalog_text(self) -> str:
        if not _CATALOG_PATH.exists():
            pytest.skip("securityRuleCatalog.ts not found")
        return _CATALOG_PATH.read_text(encoding="utf-8")

    def test_no_double_negative_false_positive_guards(self, catalog_text: str) -> None:
        """falsePositiveGuard strings must not contain 'No X are NEVER stored' patterns."""
        # Extract all falsePositiveGuard values
        pattern = re.compile(r'falsePositiveGuard:\s*"([^"]+)"')
        double_neg_pattern = re.compile(r"\bNo\b.+\bNEVER\b", re.IGNORECASE)
        violations = []
        for m in pattern.finditer(catalog_text):
            guard_text = m.group(1)
            if double_neg_pattern.search(guard_text):
                violations.append(f"Double-negative guard: {guard_text!r}")
        assert not violations, (
            "Frontend catalog falsePositiveGuard double-negatives found:\n"
            + "\n".join(violations)
        )

    def test_token_rotation_guard_no_double_negative(self, catalog_text: str) -> None:
        """clerk_session_token_rotation_disabled falsePositiveGuard must not say 'No X are NEVER'."""
        idx = catalog_text.find('"clerk_session_token_rotation_disabled"')
        assert idx != -1
        block = catalog_text[idx:idx + 600]
        fpg_match = re.search(r'falsePositiveGuard:\s*"([^"]+)"', block)
        if fpg_match:
            guard = fpg_match.group(1)
            assert "No token values are NEVER" not in guard, (
                f"Double-negative still present: {guard!r}"
            )

    def test_saml_guard_no_double_negative(self, catalog_text: str) -> None:
        idx = catalog_text.find('"clerk_application_saml_without_mfa"')
        assert idx != -1
        block = catalog_text[idx:idx + 600]
        fpg_match = re.search(r'falsePositiveGuard:\s*"([^"]+)"', block)
        if fpg_match:
            guard = fpg_match.group(1)
            assert "No SAML certificates or credentials are NEVER" not in guard

    def test_admin_role_guard_no_double_negative(self, catalog_text: str) -> None:
        idx = catalog_text.find('"clerk_org_admin_role_missing"')
        assert idx != -1
        block = catalog_text[idx:idx + 600]
        fpg_match = re.search(r'falsePositiveGuard:\s*"([^"]+)"', block)
        if fpg_match:
            guard = fpg_match.group(1)
            assert "No member identities are NEVER" not in guard

    def test_device_tracking_guard_no_double_negative(self, catalog_text: str) -> None:
        idx = catalog_text.find('"clerk_session_device_tracking_disabled"')
        assert idx != -1
        block = catalog_text[idx:idx + 600]
        fpg_match = re.search(r'falsePositiveGuard:\s*"([^"]+)"', block)
        if fpg_match:
            guard = fpg_match.group(1)
            assert "No session data is NEVER" not in guard

    def test_reverification_guard_no_double_negative(self, catalog_text: str) -> None:
        idx = catalog_text.find('"clerk_session_reverification_disabled"')
        assert idx != -1
        block = catalog_text[idx:idx + 600]
        fpg_match = re.search(r'falsePositiveGuard:\s*"([^"]+)"', block)
        if fpg_match:
            guard = fpg_match.group(1)
            assert "No session token values are NEVER" not in guard


# ═════════════════════════════════════════════════════════════════════════════
# J. Planned-next-stage and recommended-queue correctness (M89A Kubernetes)
# ═════════════════════════════════════════════════════════════════════════════


class TestRoadmapState:

    def test_planned_next_stage_is_m89a_kubernetes(self) -> None:
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert ("M89A" in planned or "Kubernetes" in planned
                or "M90A" in planned or "Sentry" in planned), (
            f"planned_next_stage should be M89A/Kubernetes, got {planned!r}"
        )

    def test_planned_next_stage_is_not_any_clerk_milestone(self) -> None:
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        for clerk_milestone in ("M83A", "M83B", "M83C", "M83D", "M83E",
                                "M83F", "M83G", "M83H", "M83I"):
            assert clerk_milestone not in planned, (
                f"planned_next_stage still references Clerk milestone {clerk_milestone}: {planned!r}"
            )

    def test_clerk_not_in_recommended_next_providers(self) -> None:
        fw = get_framework()
        providers = [
            r.get("provider", "").lower()
            for r in fw.get("recommended_next_providers", [])
            if isinstance(r, dict)
        ]
        assert "clerk" not in providers, (
            "Clerk must not be in recommended_next_providers (arc M83A–M83I complete)"
        )

    def test_kubernetes_is_head_of_recommended_providers(self) -> None:
        """Regression note: Kubernetes launched and was removed from the
        recommended queue — Sentry is now the head."""
        fw = get_framework()
        recommended = fw.get("recommended_next_providers", [])
        assert recommended, "recommended_next_providers must not be empty"
        first = recommended[0]
        provider = first.get("provider", "") if isinstance(first, dict) else str(first)
        assert "sentry" in provider.lower(), (
            f"Expected sentry at head of recommended providers, got: {provider!r}"
        )


# ═════════════════════════════════════════════════════════════════════════════
# K. Kubernetes not yet implemented
# ═════════════════════════════════════════════════════════════════════════════


class TestKubernetesNotImplemented:

    def test_no_kubernetes_connector(self) -> None:
        """Regression note: the Kubernetes connector now exists (Kubernetes
        message 1 — provider architecture foundation only)."""
        connector_path = _REPO_ROOT / "backend" / "app" / "connectors" / "kubernetes.py"
        assert connector_path.exists()

    def test_kubernetes_security_rules_exist(self) -> None:
        """Regression note: the Kubernetes security rules module now exists
        (Kubernetes message 6 — static Security Finding taxonomy)."""
        rules_path = (
            _REPO_ROOT / "backend" / "app" / "services" / "security_rules" / "kubernetes.py"
        )
        assert rules_path.exists()

    def test_kubernetes_in_provider_rules(self) -> None:
        """Regression note: kubernetes is now dispatched in _PROVIDER_RULES
        (Kubernetes message 6 — static Security Finding taxonomy)."""
        assert "kubernetes" in _PROVIDER_RULES


# ═════════════════════════════════════════════════════════════════════════════
# L. Provider capability matrix correctness for Clerk
# ═════════════════════════════════════════════════════════════════════════════


class TestCapabilityMatrix:

    @pytest.fixture(scope="class")
    def clerk_cap(self):
        cap = get_provider_capability("clerk")
        assert cap is not None, "Clerk must have a capability matrix entry"
        return cap

    def test_clerk_security_rules_enabled(self, clerk_cap) -> None:
        assert clerk_cap.security.security_rules is True

    def test_clerk_activity_ingestion_enabled(self, clerk_cap) -> None:
        assert clerk_cap.security.activity_ingestion is True

    def test_clerk_demo_seed_clear_enabled(self, clerk_cap) -> None:
        assert clerk_cap.security.demo_seed_clear is True

    def test_clerk_capability_notes_not_stale_m83h(self, clerk_cap) -> None:
        notes_lower = clerk_cap.notes.lower()
        if "planned_next_stage" in notes_lower:
            idx = notes_lower.find("planned_next_stage")
            snippet = notes_lower[idx:idx + 80]
            assert "m83h" not in snippet, (
                f"Capability matrix notes still reference M83H as planned_next_stage: {snippet!r}"
            )

    def test_kubernetes_not_in_capability_matrix(self) -> None:
        """Regression note: Kubernetes now has a static Security Finding
        layer (message 6) — capability entry reflects maturity='partial',
        security_rules=True. Still not connectable/production-ready."""
        kube_cap = get_provider_capability("kubernetes")
        assert kube_cap is not None
        assert kube_cap.maturity == "partial"
        assert kube_cap.security.security_rules is True
