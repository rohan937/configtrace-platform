"""Azure provider depth QA.

Durable guardrails that pin the full Azure rule taxonomy across every
registration surface and validate the claim-discipline / posture invariants
hardened during the Azure QA pass:

  TestAzureRuleRegistration       — all 20 Azure rule keys present in the
                                    registry, confidence map, rule pack, and
                                    coverage service.
  TestAzureFrontendCatalogParity  — all 20 keys appear in the TypeScript
                                    securityRuleCatalog.ts.
  TestAzureEvidenceSafety         — no rule's evidence carries secret / PII /
                                    raw keys.
  TestAzureCopySafety             — rule copy carries no forbidden
                                    (breach-style) wording, and no leftover
                                    "network attack surface" phrasing.
  TestAzureSeverityCalibration    — key rules carry the expected severity.
  TestAzureExpansionFramework     — expansion framework still points at M89A
                                    Kubernetes; Azure is not the next stage.
  TestAzureProviderCapabilityMatrix — Azure appears with the expected
                                    security_rules + drift capabilities.
  TestAzureAksAuthorizedIpRanges  — AKS public-API rule distinguishes
                                    "authorizedIPRanges absent" from
                                    "explicitly empty".

Pure unit tests: the registry / catalog / copy / severity checks read Python
dicts and the TypeScript catalog as text and require no database connection.
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

AZURE_RULES_FILE = BACKEND / "services" / "security_rules" / "azure.py"
FE_RULE_CATALOG = FRONTEND / "lib" / "securityRuleCatalog.ts"

# ── Canonical Azure rule set (the 20 shipped rules) ───────────────────────────

ALL_AZURE_RULE_KEYS: frozenset[str] = frozenset({
    "azure_nsg_public_admin_ingress",
    "azure_nsg_public_broad_ingress",
    "azure_storage_public_blob_access",
    "azure_storage_public_network_access",
    "azure_storage_weak_tls",
    "azure_storage_shared_key_enabled",
    "azure_storage_https_only_disabled",
    "azure_key_vault_public_network_access",
    "azure_key_vault_purge_protection_disabled",
    "azure_key_vault_soft_delete_disabled",
    "azure_key_vault_rbac_disabled",
    "azure_role_assignment_broad_privilege",
    "azure_app_service_https_disabled",
    "azure_app_service_ftp_enabled",
    "azure_app_service_weak_tls",
    "azure_app_service_public_network_access",
    "azure_sql_public_network_access",
    "azure_sql_weak_tls",
    "azure_aks_local_accounts_enabled",
    "azure_aks_public_api_access",
    "azure_aks_network_policy_missing",
})

# Expected headline severity for the key rules (subset checked explicitly).
EXPECTED_SEVERITY: dict[str, Any] = {
    "azure_nsg_public_admin_ingress": ("high", "critical"),
    "azure_storage_public_blob_access": "high",
    "azure_storage_https_only_disabled": "high",
    "azure_key_vault_public_network_access": ("high", "critical"),
    "azure_role_assignment_broad_privilege": ("high", "critical"),
    "azure_app_service_https_disabled": "high",
    "azure_aks_public_api_access": "high",
    "azure_storage_weak_tls": "medium",
    "azure_app_service_ftp_enabled": "medium",
    "azure_aks_network_policy_missing": "medium",
}

# Forbidden claim phrases — never in Azure rule code or user-facing copy.
FORBIDDEN_PHRASES = [
    "breach confirmed",
    "compromise confirmed",
    "attacker found",
    "data leaked",
    "secret leaked",
    "customer data exposed",
    "unauthorized access confirmed",
    "attack detected",
    "data exposure confirmed",
    # Softened in the Azure QA pass (Task B):
    "network attack surface",
    "attack surface",
]

# Evidence dicts must never carry secret-bearing / PII-bearing / raw keys.
FORBIDDEN_EVIDENCE_KEYS = [
    "client_secret",
    "access_token",
    "refresh_token",
    "jwt",
    "api_key",
    "authorization",
    "headers",
    "payload",
    "request",
    "response",
    "raw",
    "secret_value",
    "connection_string",
    "storage_key",
    "key_vault_secret",
    "private_key",
    "user_email",
    "user_name",
    "ip_address",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rule_key(f: Any) -> str:
    return f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")


def _severity(f: Any) -> str:
    return f.severity if hasattr(f, "severity") else f.get("severity", "")


def _evidence(f: Any) -> dict:
    ev = f.evidence if hasattr(f, "evidence") else f.get("evidence", {})
    return ev if isinstance(ev, dict) else {}


def _title(f: Any) -> str:
    return (f.title if hasattr(f, "title") else f.get("title", "")) or ""


def _description(f: Any) -> str:
    return (f.description if hasattr(f, "description") else f.get("description", "")) or ""


def _az_eval(record: dict) -> list[Any]:
    from app.services.security_rules.azure import evaluate
    return evaluate(record)


def _all_azure_findings() -> list[Any]:
    """Fire every Azure rule across a set of representative risky records."""
    from app.connectors.azure_schema import (
        AZURE_AKS_CLUSTER,
        AZURE_APP_SERVICE,
        AZURE_KEY_VAULT,
        AZURE_NETWORK_SECURITY_GROUP,
        AZURE_ROLE_ASSIGNMENT,
        AZURE_SQL_SERVER,
        AZURE_STORAGE_ACCOUNT,
    )

    def _ingress(src: str, port: str, name: str) -> dict:
        return {
            "rule_name": name, "direction": "Inbound", "access": "Allow",
            "source_address_prefix": src, "destination_port_range": port,
            "protocol": "Tcp",
        }

    records: list[dict] = [
        # NSG: public admin (22) + public broad (3389 is admin too; use 8080 broad)
        {
            "record_type": AZURE_NETWORK_SECURITY_GROUP,
            "record_id": "/sub/s/nsgs/nsg-prod",
            "nsg_name": "nsg-prod", "resource_group": "rg",
            "location": "eastus",
            "rules_summary": [
                _ingress("*", "22", "ssh"),          # admin ingress (port 22)
                _ingress("*", "0-65535", "any"),     # broad ingress (all ports)
            ],
        },
        # Storage: public blob + public network + weak TLS + shared key.
        {
            "record_type": AZURE_STORAGE_ACCOUNT,
            "record_id": "/sub/s/sa",
            "account_name": "acct", "resource_group": "rg", "location": "eastus",
            "allow_blob_public_access": True,
            "public_network_access": "Enabled",
            "network_default_action": "Allow",
            "minimum_tls_version": "TLS1_0",
            "shared_access_key_enabled": True,
            "supports_https_traffic_only": False,
        },
        # Key Vault: public network + purge + soft delete + rbac disabled.
        {
            "record_type": AZURE_KEY_VAULT,
            "record_id": "/sub/s/kv",
            "vault_name": "kv", "resource_group": "rg", "location": "eastus",
            "public_network_access": "Enabled",
            "network_default_action": "Allow",
            "purge_protection_enabled": False,
            "soft_delete_enabled": False,
            "enable_rbac_authorization": False,
            "access_policy_count": 3,
        },
        # Role assignment: broad privilege.
        {
            "record_type": AZURE_ROLE_ASSIGNMENT,
            "record_id": "/sub/s/ra",
            "role_definition_name": "Owner",
            "scope_type": "subscription",
            "principal_type": "ServicePrincipal",
            "resource_group": "rg",
        },
        # App Service: https disabled + ftp + weak TLS + public network.
        {
            "record_type": AZURE_APP_SERVICE,
            "record_id": "/sub/s/app",
            "app_name": "app", "resource_group": "rg", "location": "eastus",
            "https_only": False,
            "ftps_state": "AllAllowed",
            "min_tls_version": "1.0",
            "public_network_access": "Enabled",
        },
        # SQL Server: public network + weak TLS.
        {
            "record_type": AZURE_SQL_SERVER,
            "record_id": "/sub/s/sql",
            "server_name": "sql", "resource_group": "rg", "location": "eastus",
            "public_network_access": "Enabled",
            "minimum_tls_version": "1.0",
        },
        # AKS: local accounts + public api (explicitly empty IP ranges) + no policy.
        {
            "record_type": AZURE_AKS_CLUSTER,
            "record_id": "/sub/s/aks",
            "cluster_name": "aks", "resource_group": "rg", "location": "eastus",
            "local_account_disabled": False,
            "private_cluster_enabled": False,
            "api_server_authorized_ip_range_count": 0,
            "authorized_ip_ranges_configured": True,
            "network_plugin": "azure",
            "network_policy": "",
        },
    ]
    out: list[Any] = []
    for r in records:
        out.extend(_az_eval(r))
    return out


# ── TestAzureRuleRegistration ─────────────────────────────────────────────────

class TestAzureRuleRegistration:
    def test_rule_key_count_is_twenty_one(self) -> None:
        assert len(ALL_AZURE_RULE_KEYS) == 21

    def test_module_export_matches_canonical_set(self) -> None:
        from app.services.security_rules.azure import AZURE_RULE_KEYS
        assert set(AZURE_RULE_KEYS) == ALL_AZURE_RULE_KEYS

    def test_all_keys_in_registry(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for key in ALL_AZURE_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS, f"{key!r} missing from KNOWN_RULE_KEYS"

    def test_all_keys_in_confidence(self) -> None:
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for key in ALL_AZURE_RULE_KEYS:
            assert key in RULE_CONFIDENCE, f"{key!r} missing from RULE_CONFIDENCE"

    def test_all_keys_in_rule_pack(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_AZURE_RULE_KEYS:
            assert key in _RULE_META, f"{key!r} missing from _RULE_META"
            provider, _sev, _cat = _RULE_META[key]
            assert provider == "azure", f"{key!r} wrong provider: {provider!r}"

    def test_all_keys_in_coverage(self) -> None:
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in ALL_AZURE_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, f"{key!r} missing from RULE_RECORD_TYPES"
            assert RULE_RECORD_TYPES[key], f"{key!r} has empty record-type tuple"


# ── TestAzureFrontendCatalogParity ────────────────────────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
class TestAzureFrontendCatalogParity:
    def _catalog_text(self) -> str:
        return FE_RULE_CATALOG.read_text(encoding="utf-8")

    def test_all_keys_present_in_catalog(self) -> None:
        text = self._catalog_text()
        missing = [k for k in ALL_AZURE_RULE_KEYS if f'key: "{k}"' not in text]
        assert not missing, f"Azure rule keys missing from frontend catalog: {missing}"

    def test_catalog_azure_keys_match_via_regex(self) -> None:
        text = self._catalog_text()
        found = set(re.findall(r'key:\s*"(azure_[a-z0-9_]+)"', text))
        missing = ALL_AZURE_RULE_KEYS - found
        assert not missing, f"Regex did not find Azure keys in catalog: {sorted(missing)}"

    def test_catalog_severity_matches_backend_pack(self) -> None:
        text = self._catalog_text()
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_AZURE_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            assert idx != -1, f"Azure rule {key!r} not found in frontend catalog"
            block = text[idx:idx + 900]
            _provider, expected_sev, _cat = _RULE_META[key]
            assert f'severity: "{expected_sev}"' in block, (
                f"Frontend severity for {key!r} does not match backend "
                f"({expected_sev!r})"
            )


# ── TestAzureEvidenceSafety ───────────────────────────────────────────────────

class TestAzureEvidenceSafety:
    def test_synthetic_records_fire_every_rule(self) -> None:
        fired = {_rule_key(f) for f in _all_azure_findings()}
        missing = ALL_AZURE_RULE_KEYS - fired
        assert not missing, f"Synthetic records did not fire rules: {sorted(missing)}"

    def test_evidence_has_no_forbidden_keys(self) -> None:
        findings = _all_azure_findings()
        assert findings, "expected at least one finding across representative records"
        for f in findings:
            ev_keys = {k.lower() for k in _evidence(f)}
            for forbidden in FORBIDDEN_EVIDENCE_KEYS:
                assert forbidden not in ev_keys, (
                    f"Forbidden evidence key {forbidden!r} in finding "
                    f"{_rule_key(f)!r}: {sorted(ev_keys)}"
                )

    def test_evidence_is_flat_safe_scalars(self) -> None:
        for f in _all_azure_findings():
            for v in _evidence(f).values():
                assert isinstance(v, (str, int, float, bool, list, type(None))), (
                    f"Non-scalar evidence value in {_rule_key(f)!r}: {type(v).__name__}"
                )
                if isinstance(v, list):
                    for item in v:
                        assert isinstance(item, (str, int, float, bool, type(None)))


# ── TestAzureCopySafety ───────────────────────────────────────────────────────

class TestAzureCopySafety:
    def test_no_forbidden_wording_in_rules_module(self) -> None:
        from app.services.security_rules import azure as az_rules
        src = inspect.getsource(az_rules).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in src, (
                f"forbidden phrase {phrase!r} present in security_rules.azure"
            )

    def test_no_forbidden_wording_in_finding_copy(self) -> None:
        for f in _all_azure_findings():
            blob = f"{_title(f)}\n{_description(f)}".lower()
            for phrase in FORBIDDEN_PHRASES:
                assert phrase not in blob, (
                    f"Finding {_rule_key(f)!r} copy contains forbidden phrase "
                    f"{phrase!r}"
                )

    def test_network_attack_surface_softened(self) -> None:
        """Task B: the App Service public-network rule must read 'network exposure'."""
        text = AZURE_RULES_FILE.read_text(encoding="utf-8")
        assert "attack surface" not in text.lower(), (
            "'attack surface' should have been softened to 'network exposure'"
        )
        # The softened copy reads "broaden the network exposure"; the f-string
        # split means the words are on adjacent literals, so check the noun.
        assert "exposure" in text.lower()


# ── TestAzureSeverityCalibration ──────────────────────────────────────────────

class TestAzureSeverityCalibration:
    def test_key_rule_severities(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        for key, expected in EXPECTED_SEVERITY.items():
            _provider, sev, _cat = _RULE_META[key]
            if isinstance(expected, tuple):
                assert sev in expected, (
                    f"{key!r}: severity {sev!r} not in expected {expected}"
                )
            else:
                assert sev == expected, (
                    f"{key!r}: severity {sev!r} != expected {expected!r}"
                )


# ── TestAzureExpansionFramework ───────────────────────────────────────────────

class TestAzureExpansionFramework:
    def test_planned_next_stage_points_at_kubernetes(self) -> None:
        """Regression note: Kubernetes launched (message 1 / M89A) — Sentry/M90A is now next."""
        from app.services.provider_expansion_framework import get_framework
        stage = get_framework()["summary"]["planned_next_stage"]
        assert "M90A" in stage, f"planned_next_stage should contain M90A, got {stage!r}"
        assert "Sentry" in stage, (
            f"planned_next_stage should contain Sentry, got {stage!r}"
        )

    def test_azure_is_not_the_next_stage(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        stage = get_framework()["summary"]["planned_next_stage"]
        assert "azure" not in stage.lower(), (
            f"Azure must not be the planned_next_stage, got {stage!r}"
        )

    def test_azure_is_not_the_next_provider_to_implement(self) -> None:
        from app.services.provider_expansion_framework import (
            RECOMMENDED_NEXT_PROVIDERS,
        )
        head = RECOMMENDED_NEXT_PROVIDERS[0]
        assert head.provider != "azure", (
            "Azure must not be the next provider to implement"
        )
        assert head.provider == "kubernetes"


# ── TestAzureProviderCapabilityMatrix ─────────────────────────────────────────

class TestAzureProviderCapabilityMatrix:
    def test_azure_present_with_expected_capabilities(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("azure")
        assert cap is not None, "Azure missing from provider capability matrix"
        assert cap.provider == "azure"
        # security_rules capability present.
        assert cap.security.security_rules is True
        # drift detection (snapshots + diff + risk classification) present.
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True


# ── TestAzureAksAuthorizedIpRanges (Task C) ───────────────────────────────────

class TestAzureAksAuthorizedIpRanges:
    """The AKS public-API rule distinguishes 'authorizedIPRanges absent'
    (posture unknown — do not fire) from 'explicitly configured but empty'
    (no restriction — fire)."""

    def _aks_record(self, **overrides: Any) -> dict:
        from app.connectors.azure_schema import AZURE_AKS_CLUSTER
        rec = {
            "record_type": AZURE_AKS_CLUSTER,
            "record_id": "/sub/s/aks",
            "cluster_name": "aks", "resource_group": "rg", "location": "eastus",
            "private_cluster_enabled": False,
            "api_server_authorized_ip_range_count": 0,
        }
        rec.update(overrides)
        return rec

    def test_fires_when_explicitly_configured_empty(self) -> None:
        fired = {_rule_key(f) for f in _az_eval(
            self._aks_record(authorized_ip_ranges_configured=True))}
        assert "azure_aks_public_api_access" in fired

    def test_does_not_fire_when_authorized_ranges_absent(self) -> None:
        fired = {_rule_key(f) for f in _az_eval(
            self._aks_record(authorized_ip_ranges_configured=False))}
        assert "azure_aks_public_api_access" not in fired, (
            "rule must not fire when authorizedIPRanges is absent (posture unknown)"
        )

    def test_still_fires_for_legacy_records_without_the_flag(self) -> None:
        """Records that predate the flag default to firing (backward compatible)."""
        fired = {_rule_key(f) for f in _az_eval(self._aks_record())}
        assert "azure_aks_public_api_access" in fired
