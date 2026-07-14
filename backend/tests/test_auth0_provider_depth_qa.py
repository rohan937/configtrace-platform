"""Auth0 provider depth QA.

Durable, mostly-static guardrails that pin the full Auth0 rule taxonomy
across every registration surface, validate the privacy / claim-discipline
invariants for the Auth0 provider, and — most importantly — assert the
central-evaluator wiring that makes Auth0 rules actually fire during snapshot
evaluation (the P0 fix this file regression-guards).

  TestAuth0RuleRegistration        — all 37 Auth0 rule keys present in the
                                     module export, registry, confidence map,
                                     rule pack, and coverage service.
  TestAuth0FrontendCatalogParity   — all 37 keys appear in the TypeScript
                                     securityRuleCatalog.ts with matching
                                     severities and provider.
  TestAuth0EvidenceSafety          — fired-rule evidence carries no secret /
                                     token / PII / raw-URL keys.
  TestAuth0CopySafety              — rule copy carries no forbidden
                                     (breach-style) wording.
  TestAuth0EvaluatorDispatch       — "auth0" is wired into the central
                                     evaluator and produces findings through it.
  TestAuth0ExpansionFramework      — expansion framework points at M89A
                                     Kubernetes.
  TestAuth0ProviderCapabilityMatrix — Auth0 is implemented (partial) with
                                     security_rules=True; Kubernetes is not yet
                                     implemented and has no connector file.

Pure unit tests: the registry / catalog / copy / severity / dispatch checks
read Python dicts and the TypeScript catalog as text and require no database
connection.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import Any

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend" / "app"
FRONTEND = REPO_ROOT / "frontend" / "src"

AUTH0_RULES_FILE = BACKEND / "services" / "security_rules" / "auth0.py"
FE_RULE_CATALOG = FRONTEND / "lib" / "securityRuleCatalog.ts"

CANONICAL_PROVIDER = "auth0"

# ── Canonical Auth0 rule set (the 39 shipped rules) ───────────────────────────

AUTH0_RULE_KEYS = [
    # Tenant settings (M81B)
    "auth0_tenant_session_lifetime_extended",
    "auth0_tenant_idle_session_lifetime_extended",
    "auth0_tenant_dynamic_client_registration_enabled",
    # Application core (M81B)
    "auth0_application_no_callbacks",
    "auth0_application_many_callbacks",
    "auth0_application_many_allowed_origins",
    "auth0_application_oidc_non_conformant",
    "auth0_application_weak_jwt_algorithm",
    "auth0_refresh_token_rotation_disabled",
    "auth0_refresh_token_lifetime_extended",
    # Connection (M81B)
    "auth0_connection_no_enabled_clients",
    "auth0_connection_weak_password_policy",
    # Resource server (M81B)
    "auth0_resource_server_offline_access_enabled",
    "auth0_resource_server_token_lifetime_extended",
    "auth0_resource_server_rbac_disabled",
    # Rule (M81B)
    "auth0_rule_disabled",
    "auth0_rule_large_script",
    # Action (M81B)
    "auth0_action_not_deployed",
    "auth0_action_secrets_present",
    # MFA factor (M81B)
    "auth0_mfa_factor_disabled",
    # Custom domain (M81B)
    "auth0_custom_domain_not_ready",
    "auth0_custom_domain_weak_tls_policy",
    # Application — grant type posture (M81C)
    "auth0_application_password_grant_enabled",
    "auth0_application_implicit_grant_enabled",
    "auth0_application_public_client_credentials_enabled",
    "auth0_application_refresh_grant_without_rotation",
    "auth0_application_many_grant_types",
    "auth0_application_device_code_grant_enabled",
    # Application — wildcard posture (M81C)
    "auth0_application_wildcard_callback",
    "auth0_application_wildcard_allowed_origin",
    "auth0_application_wildcard_logout_url",
    # Application — localhost posture (M81C)
    "auth0_application_localhost_callback",
    "auth0_application_localhost_origin",
    # Application — HTTPS posture (M81C)
    "auth0_application_callback_missing_https",
    "auth0_application_origin_missing_https",
    # Application — public client / token endpoint posture (M81C)
    "auth0_public_client_refresh_tokens_enabled",
    "auth0_application_token_endpoint_auth_none",
    # Classification-QA pass: Change-only coverage gaps closed
    "auth0_connection_mfa_disabled",
    "auth0_resource_server_weak_signing_algorithm",
]

ALL_AUTH0_RULE_KEYS: frozenset[str] = frozenset(AUTH0_RULE_KEYS)

# Forbidden claim wording — never in Auth0 rule code or user-facing copy
# (except inside an explicit negating disclaimer or a denylist constant).
FORBIDDEN_PHRASES = [
    "breach confirmed",
    "compromise confirmed",
    "attacker found",
    "someone has access",
    "data leaked",
    "secret leaked",
    "customer data exposed",
    "unauthorized access confirmed",
    "account takeover detected",
    "credentials exposed",
    "tokens leaked",
    "users exposed",
    "passwords leaked",
]

# Evidence dicts must never carry secret-bearing / PII-bearing / raw-URL keys.
FORBIDDEN_EVIDENCE_KEYS = [
    "client_secret",
    "token",
    "jwt",
    "password",
    "user_email",
    "callback_url",
    "secret",
    "management_api_token",
    "access_token",
    "refresh_token",
    "id_token",
    "authorization",
    "signing_key",
    "private_key",
    "user_id",
    "email",
    "ip_address",
    "domain_name",
    "script_content",
    "raw_payload",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rule_key(f: Any) -> str:
    return f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")


def _evidence(f: Any) -> dict:
    ev = f.evidence if hasattr(f, "evidence") else f.get("evidence", {})
    return ev if isinstance(ev, dict) else {}


def _title(f: Any) -> str:
    return (f.title if hasattr(f, "title") else f.get("title", "")) or ""


def _description(f: Any) -> str:
    return (f.description if hasattr(f, "description") else f.get("description", "")) or ""


def _auth0_eval(record: dict) -> list[Any]:
    from app.services.security_rules.auth0 import evaluate
    return evaluate(record)


# ── Representative risky records (field names mirror auth0_schema / M81B-C) ────

def _all_auth0_findings() -> list[Any]:
    """Fire a broad set of Auth0 rules across representative risky records.

    Field names mirror the canonical connector-normalizer schema consumed by
    ``security_rules.auth0.evaluate`` (as exercised by the M81B/M81C tests).
    """
    from app.connectors.auth0_schema import (
        AUTH0_ACTION,
        AUTH0_APPLICATION,
        AUTH0_CONNECTION,
        AUTH0_CUSTOM_DOMAIN,
        AUTH0_MFA_FACTOR,
        AUTH0_RESOURCE_SERVER,
        AUTH0_RULE,
        AUTH0_TENANT_SETTINGS,
    )

    records: list[dict] = [
        # Tenant: extended session + idle + dynamic client registration.
        {
            "record_type": AUTH0_TENANT_SETTINGS,
            "record_id": "auth0_tenant_settings_main",
            "session_lifetime_category": "extended",
            "idle_session_lifetime_category": "extended",
            "flag_enable_dynamic_client_registration": True,
        },
        # Application: weak JWT, OIDC non-conformant, no callbacks, password +
        # implicit + device-code grants, wildcards, localhost, HTTP, token
        # endpoint none, refresh grant without rotation, broad grant surface,
        # many callbacks/origins.
        {
            "record_type": AUTH0_APPLICATION,
            "record_id": "AUTH0_DEPTH_CLIENT_ID",
            "client_id": "AUTH0_DEPTH_CLIENT_ID",
            "name": "Depth Application",
            "app_type": "spa",
            "callbacks_count": 12,
            "allowed_origins_count": 8,
            "web_origins_count": 8,
            "jwt_alg": "HS256",
            "oidc_conformant": False,
            "token_endpoint_auth_method": "none",
            "refresh_token_rotation_enabled": False,
            "refresh_token_lifetime_category": "extended",
            "grant_types_summary": "authorization_code, refresh_token, password",
            "grant_types_count": 6,
            "grant_password_enabled": True,
            "grant_implicit_enabled": True,
            "grant_client_credentials_enabled": True,
            "grant_refresh_token_enabled": True,
            "grant_device_code_enabled": True,
            "wildcard_callback_present": True,
            "wildcard_allowed_origin_present": True,
            "wildcard_logout_url_present": True,
            "localhost_callback_present": True,
            "localhost_origin_present": True,
            "callbacks_missing_https": True,
            "allowed_origins_missing_https": True,
        },
        # Connection: weak password policy + no enabled clients.
        {
            "record_type": AUTH0_CONNECTION,
            "record_id": "AUTH0_DEPTH_CONNECTION_ID",
            "connection_id": "AUTH0_DEPTH_CONNECTION_ID",
            "name": "Depth Connection",
            "strategy": "auth0",
            "enabled_clients_count": 0,
            "password_policy_category": "low",
        },
        # Resource server: offline access + extended token + RBAC disabled.
        {
            "record_type": AUTH0_RESOURCE_SERVER,
            "record_id": "AUTH0_DEPTH_RS_ID",
            "resource_server_id": "AUTH0_DEPTH_RS_ID",
            "name": "Depth API",
            "allow_offline_access": True,
            "token_lifetime_category": "extended",
            "rbac_enabled": False,
        },
        # Rule: disabled with script + long script.
        {
            "record_type": AUTH0_RULE,
            "record_id": "AUTH0_DEPTH_RULE_ID",
            "rule_id": "AUTH0_DEPTH_RULE_ID",
            "name": "Depth Rule",
            "enabled": False,
            "script_present": True,
            "script_length_category": "long",
            "stage": "login_success",
        },
        # Action: not deployed + secrets present.
        {
            "record_type": AUTH0_ACTION,
            "record_id": "AUTH0_DEPTH_ACTION_ID",
            "action_id": "AUTH0_DEPTH_ACTION_ID",
            "name": "Depth Action",
            "status": "built",
            "trigger_id": "post-login",
            "deployed_version_present": False,
            "secrets_count": 2,
        },
        # MFA factor: strong factor disabled.
        {
            "record_type": AUTH0_MFA_FACTOR,
            "record_id": "auth0_mfa_factor_otp",
            "factor_name": "otp",
            "enabled": False,
            "provider_category": "totp",
        },
        # Custom domain: not ready + weak (compatible) TLS.
        {
            "record_type": AUTH0_CUSTOM_DOMAIN,
            "record_id": "AUTH0_DEPTH_CUSTOM_DOMAIN_ID",
            "custom_domain_id": "AUTH0_DEPTH_CUSTOM_DOMAIN_ID",
            "status": "pending_verification",
            "type": "auth0_managed_certs",
            "primary": True,
            "tls_policy_category": "compatible",
        },
    ]
    out: list[Any] = []
    for r in records:
        out.extend(_auth0_eval(r))
    return out


# ── TestAuth0RuleRegistration ─────────────────────────────────────────────────

class TestAuth0RuleRegistration:
    def test_rule_key_count_is_thirty_nine(self) -> None:
        assert len(ALL_AUTH0_RULE_KEYS) == 39

    def test_module_export_matches_canonical_set(self) -> None:
        from app.services.security_rules.auth0 import AUTH0_RULE_KEYS as MOD_KEYS
        assert set(MOD_KEYS) == ALL_AUTH0_RULE_KEYS

    def test_all_keys_in_registry(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for key in ALL_AUTH0_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS, f"{key!r} missing from KNOWN_RULE_KEYS"

    def test_all_keys_in_confidence(self) -> None:
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for key in ALL_AUTH0_RULE_KEYS:
            assert key in RULE_CONFIDENCE, f"{key!r} missing from RULE_CONFIDENCE"

    def test_all_keys_in_rule_pack(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_AUTH0_RULE_KEYS:
            assert key in _RULE_META, f"{key!r} missing from _RULE_META"
            provider, _sev, _cat = _RULE_META[key]
            assert provider == CANONICAL_PROVIDER, (
                f"{key!r} wrong provider: {provider!r}"
            )

    def test_all_keys_in_coverage(self) -> None:
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in ALL_AUTH0_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, f"{key!r} missing from RULE_RECORD_TYPES"
            assert RULE_RECORD_TYPES[key], f"{key!r} has empty record-type tuple"

    def test_registry_has_no_unexpected_auth0_keys(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        reg = {k for k in KNOWN_RULE_KEYS if k.startswith("auth0_")}
        extra = reg - ALL_AUTH0_RULE_KEYS
        assert not extra, f"unexpected auth0 keys in registry: {sorted(extra)}"


# ── TestAuth0FrontendCatalogParity ────────────────────────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
class TestAuth0FrontendCatalogParity:
    def _catalog_text(self) -> str:
        return FE_RULE_CATALOG.read_text(encoding="utf-8")

    def test_all_keys_present_in_catalog(self) -> None:
        text = self._catalog_text()
        missing = [k for k in ALL_AUTH0_RULE_KEYS if f'key: "{k}"' not in text]
        assert not missing, (
            f"Auth0 rule keys missing from frontend catalog: {missing}"
        )

    def test_catalog_keys_match_via_regex(self) -> None:
        text = self._catalog_text()
        found = set(re.findall(r'key:\s*"(auth0_[a-z0-9_]+)"', text))
        missing = ALL_AUTH0_RULE_KEYS - found
        assert not missing, (
            f"Regex did not find Auth0 keys in catalog: {sorted(missing)}"
        )

    def test_catalog_has_no_unexpected_auth0_keys(self) -> None:
        text = self._catalog_text()
        found = set(re.findall(r'key:\s*"(auth0_[a-z0-9_]+)"', text))
        extra = found - ALL_AUTH0_RULE_KEYS
        assert not extra, (
            f"Unexpected auth0 keys in frontend catalog: {sorted(extra)}"
        )

    def test_catalog_severity_matches_backend_pack(self) -> None:
        text = self._catalog_text()
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_AUTH0_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            assert idx != -1, f"Auth0 rule {key!r} not found in frontend catalog"
            block = text[idx:idx + 900]
            _provider, expected_sev, _cat = _RULE_META[key]
            assert f'severity: "{expected_sev}"' in block, (
                f"Frontend severity for {key!r} does not match backend "
                f"({expected_sev!r})"
            )

    def test_catalog_provider_is_canonical(self) -> None:
        text = self._catalog_text()
        for key in ALL_AUTH0_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            block = text[idx:idx + 900]
            assert 'provider: "auth0"' in block, (
                f"Frontend catalog entry for {key!r} must use provider 'auth0'"
            )


# ── TestAuth0EvidenceSafety ───────────────────────────────────────────────────

class TestAuth0EvidenceSafety:
    def test_representative_records_fire_many_rules(self) -> None:
        fired = {_rule_key(f) for f in _all_auth0_findings()}
        # The representative set is broad; assert it exercises the bulk of the
        # taxonomy so the evidence-safety check below is meaningful.
        assert len(fired) >= 25, (
            f"expected representative records to fire >= 25 distinct rules; "
            f"got {len(fired)}: {sorted(fired)}"
        )

    def test_evidence_has_no_forbidden_keys(self) -> None:
        findings = _all_auth0_findings()
        assert findings, "expected at least one finding across representative records"
        for f in findings:
            ev_keys = {k.lower() for k in _evidence(f)}
            for forbidden in FORBIDDEN_EVIDENCE_KEYS:
                assert forbidden not in ev_keys, (
                    f"Forbidden evidence key {forbidden!r} in finding "
                    f"{_rule_key(f)!r}: {sorted(ev_keys)}"
                )

    def test_evidence_is_flat_safe_scalars(self) -> None:
        # Auth0 evidence is metadata-only: scalars or lists of scalars; no
        # nested dicts or lists-of-dicts.
        def _is_safe_scalar(x: Any) -> bool:
            return isinstance(x, (str, int, float, bool, type(None)))

        for f in _all_auth0_findings():
            for k, v in _evidence(f).items():
                if _is_safe_scalar(v):
                    continue
                assert isinstance(v, list), (
                    f"Non-scalar evidence value in {_rule_key(f)!r} key {k!r}: "
                    f"{type(v).__name__}"
                )
                for item in v:
                    assert _is_safe_scalar(item), (
                        f"Unsafe list item in {_rule_key(f)!r} key {k!r}: "
                        f"{type(item).__name__}"
                    )


# ── TestAuth0CopySafety ───────────────────────────────────────────────────────

class TestAuth0CopySafety:
    def test_no_forbidden_wording_in_rules_module(self) -> None:
        from app.services.security_rules import auth0 as a0_rules
        src = inspect.getsource(a0_rules).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in src, (
                f"forbidden phrase {phrase!r} present in security_rules.auth0"
            )

    def test_no_forbidden_wording_in_finding_copy(self) -> None:
        for f in _all_auth0_findings():
            blob = f"{_title(f)}\n{_description(f)}".lower()
            for phrase in FORBIDDEN_PHRASES:
                assert phrase not in blob, (
                    f"Finding {_rule_key(f)!r} copy contains forbidden phrase "
                    f"{phrase!r}"
                )


# ── TestAuth0EvaluatorDispatch ────────────────────────────────────────────────

class TestAuth0EvaluatorDispatch:
    def test_auth0_in_provider_rules(self) -> None:
        """P0 regression guard: Auth0 must be wired into the central evaluator."""
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert "auth0" in _PROVIDER_RULES, (
            "auth0 missing from security_finding_evaluator._PROVIDER_RULES"
        )
        assert _PROVIDER_RULES["auth0"], "auth0 dispatch list is empty"

    def test_central_evaluator_produces_tenant_dcr_finding(self) -> None:
        from app.connectors.auth0_schema import AUTH0_TENANT_SETTINGS
        from app.services.security_finding_evaluator import evaluate_record
        rec = {
            "record_type": AUTH0_TENANT_SETTINGS,
            "record_id": "auth0_tenant_settings_main",
            "session_lifetime_category": "standard",
            "idle_session_lifetime_category": "standard",
            "flag_enable_dynamic_client_registration": True,
        }
        candidates = evaluate_record(rec, "auth0")
        assert candidates, "central evaluator produced no Auth0 findings"
        keys = {c.rule_key for c in candidates}
        assert "auth0_tenant_dynamic_client_registration_enabled" in keys, (
            f"expected dynamic client registration finding via central dispatch; "
            f"got {keys}"
        )

    def test_central_evaluator_produces_weak_jwt_finding(self) -> None:
        from app.connectors.auth0_schema import AUTH0_APPLICATION
        from app.services.security_finding_evaluator import evaluate_record
        rec = {
            "record_type": AUTH0_APPLICATION,
            "record_id": "AUTH0_DISPATCH_CLIENT_ID",
            "client_id": "AUTH0_DISPATCH_CLIENT_ID",
            "name": "Dispatch Application",
            "app_type": "regular_web",
            "jwt_alg": "HS256",
        }
        candidates = evaluate_record(rec, "auth0")
        assert candidates, "central evaluator produced no Auth0 findings"
        keys = {c.rule_key for c in candidates}
        assert "auth0_application_weak_jwt_algorithm" in keys, (
            f"expected weak JWT algorithm finding via central dispatch; got {keys}"
        )

    def test_central_evaluator_produces_weak_password_policy_finding(self) -> None:
        from app.connectors.auth0_schema import AUTH0_CONNECTION
        from app.services.security_finding_evaluator import evaluate_record
        rec = {
            "record_type": AUTH0_CONNECTION,
            "record_id": "AUTH0_DISPATCH_CONNECTION_ID",
            "connection_id": "AUTH0_DISPATCH_CONNECTION_ID",
            "name": "Dispatch Connection",
            "strategy": "auth0",
            "enabled_clients_count": 3,
            "password_policy_category": "none",
        }
        candidates = evaluate_record(rec, "auth0")
        assert candidates, "central evaluator produced no Auth0 findings"
        keys = {c.rule_key for c in candidates}
        assert "auth0_connection_weak_password_policy" in keys, (
            f"expected weak password policy finding via central dispatch; got {keys}"
        )


# ── TestAuth0ExpansionFramework ───────────────────────────────────────────────

class TestAuth0ExpansionFramework:
    def test_planned_next_stage_points_at_kubernetes(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        stage = get_framework()["summary"]["planned_next_stage"]
        assert stage.startswith("M89A") or "Kubernetes" in stage, (
            f"planned_next_stage should reference M89A Kubernetes, got {stage!r}"
        )

    def test_auth0_not_in_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        providers = [r["provider"] for r in fw["recommended_next_providers"]]
        assert CANONICAL_PROVIDER not in providers, (
            "Auth0 has launched and must not be in the recommended queue"
        )


# ── TestAuth0ProviderCapabilityMatrix ─────────────────────────────────────────

class TestAuth0ProviderCapabilityMatrix:
    def test_auth0_present_with_expected_capabilities(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability(CANONICAL_PROVIDER)
        assert cap is not None, "Auth0 missing from provider capability matrix"
        assert cap.provider == CANONICAL_PROVIDER
        assert cap.security.security_rules is True
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True
        assert cap.maturity == "partial"

    def test_auth0_capability_count_matches_rule_set(self) -> None:
        """The Auth0 rule pack must expose exactly the 37 canonical rules."""
        from app.services.security_rule_pack import _RULE_META
        auth0_keys = {k for k, v in _RULE_META.items() if v[0] == CANONICAL_PROVIDER}
        assert auth0_keys == ALL_AUTH0_RULE_KEYS, (
            f"Auth0 rule-pack key set drift. Missing: "
            f"{ALL_AUTH0_RULE_KEYS - auth0_keys}; Extra: "
            f"{auth0_keys - ALL_AUTH0_RULE_KEYS}"
        )

    def test_kubernetes_is_not_yet_implemented(self) -> None:
        """Guard against accidental introduction of a Kubernetes provider."""
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        assert get_provider_capability("kubernetes") is None, (
            "Kubernetes must not be implemented yet — it is still in the "
            "recommended-next queue"
        )

    def test_kubernetes_connector_does_not_exist(self) -> None:
        """The Kubernetes provider connector module must not exist yet."""
        k8s_connector = BACKEND / "connectors" / "kubernetes.py"
        assert not k8s_connector.exists(), (
            "Kubernetes connector should not exist yet (provider not implemented)"
        )
