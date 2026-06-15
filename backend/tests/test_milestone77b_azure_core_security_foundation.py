"""M77B: Azure core security foundation — test suite.

Covers:
  * Evaluator dispatch on every Azure record_type
  * Each of the 10 rules firing on appropriate normalized records
  * Negative cases — normal web ingress, private prefixes, missing fields
  * Evidence safety — no secrets / tokens / connection strings / principal-emails
  * Claim discipline — no overclaim wording
  * Registry / confidence / pack / coverage / catalog parity
  * provider_capability_matrix shows azure security_rules=True (partial)
  * provider_expansion_framework next_stage points to M77C
  * Frontend catalog has all 10 keys
  * M77A regression — record_type values still canonical
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.connectors.azure_schema import (
    AZURE_KEY_VAULT,
    AZURE_NETWORK_SECURITY_GROUP,
    AZURE_RESOURCE_GROUP,
    AZURE_STORAGE_ACCOUNT,
    AZURE_SUBSCRIPTION,
)
from app.services.provider_capability_matrix_service import (
    get_provider_capability,
)
from app.services.provider_expansion_framework import get_framework
from app.services.security_coverage_service import (
    PROVIDERS as COVERAGE_PROVIDERS,
)
from app.services.security_coverage_service import (
    PROVIDER_SURFACES,
    RULE_RECORD_TYPES,
)
from app.services.security_finding_evaluator import _PROVIDER_RULES
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META, pack_summary
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules import azure as azure_rules
from app.services.security_rules.azure import AZURE_RULE_KEYS, evaluate

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"

# Strings that must NEVER appear in evidence (case-insensitive substring match).
# Targets the actual shapes a leak would take — raw key material, connection
# strings, SAS tokens, PEM blocks, principal/object IDs, auth headers.
# Deliberately omits bare words like "authorization" / "token" / "secret" so
# benign Azure field names (e.g. enable_rbac_authorization) don't false-positive.
_FORBIDDEN_EVIDENCE_SUBSTRINGS = (
    "password",
    "passwd",
    "bearer ",
    "authorization:",
    "connectionstring",
    "connection_string",
    "accountkey=",
    "?sv=",  # SAS query
    "principal_id",
    "object_id",
    "tenant_id",
    "client_id",
    "private_key",
    "begin rsa",
    "begin certificate",
    "begin private",
)

# Claim-discipline forbidden phrases (must NOT appear in any rule description).
_FORBIDDEN_CLAIMS = (
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
)


def _nsg(rules: list[dict], **extra) -> dict:
    return {
        "record_type": AZURE_NETWORK_SECURITY_GROUP,
        "record_id": extra.pop("record_id", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-prod"),
        "nsg_name": extra.pop("nsg_name", "nsg-prod"),
        "resource_group": "rg",
        "location": "eastus",
        "rules_summary": rules,
        **extra,
    }


def _storage(**fields) -> dict:
    base = {
        "record_type": AZURE_STORAGE_ACCOUNT,
        "record_id": fields.pop("record_id", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct"),
        "account_name": fields.pop("account_name", "acct"),
        "resource_group": "rg",
        "location": "eastus",
    }
    base.update(fields)
    return base


def _kv(**fields) -> dict:
    base = {
        "record_type": AZURE_KEY_VAULT,
        "record_id": fields.pop("record_id", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-prod"),
        "vault_name": fields.pop("vault_name", "kv-prod"),
        "resource_group": "rg",
        "location": "eastus",
    }
    base.update(fields)
    return base


def _ingress_rule(
    *,
    name: str = "allow-x",
    direction: str = "Inbound",
    access: str = "Allow",
    src: str = "*",
    dest_port: str = "22",
    protocol: str = "Tcp",
) -> dict:
    return {
        "rule_name": name,
        "direction": direction,
        "access": access,
        "source_address_prefix": src,
        "destination_port_range": dest_port,
        "protocol": protocol,
    }


def _assert_evidence_safe(ev: dict, where: str) -> None:
    text = json.dumps(ev, sort_keys=True).lower()
    for bad in _FORBIDDEN_EVIDENCE_SUBSTRINGS:
        assert bad.lower() not in text, f"forbidden substring {bad!r} in evidence for {where}: {ev}"


# ──────────────────────────────────────────────────────────────────────────────
# Dispatcher
# ──────────────────────────────────────────────────────────────────────────────


class TestEvaluatorDispatch:
    def test_evaluator_dispatches_nsg(self):
        findings = evaluate(_nsg([_ingress_rule(src="10.0.0.0/24", dest_port="22")]))
        # Private source — must not fire admin rule
        assert findings == []

    def test_evaluator_returns_empty_on_subscription(self):
        record = {
            "record_type": AZURE_SUBSCRIPTION,
            "record_id": "/subscriptions/s",
            "subscription_id": "s",
            "subscription_name": "Prod",
        }
        assert evaluate(record) == []

    def test_evaluator_returns_empty_on_resource_group(self):
        record = {
            "record_type": AZURE_RESOURCE_GROUP,
            "record_id": "/subscriptions/s/resourceGroups/rg",
            "resource_group_name": "rg",
            "location": "eastus",
        }
        assert evaluate(record) == []

    def test_evaluator_returns_empty_on_unknown_provider(self):
        assert evaluate({"record_type": "github_repo"}) == []

    def test_evaluator_handles_non_dict_record(self):
        assert evaluate(None) == []  # type: ignore[arg-type]
        assert evaluate("foo") == []  # type: ignore[arg-type]
        assert evaluate(42) == []  # type: ignore[arg-type]

    def test_evaluator_registered_in_provider_rules(self):
        assert "azure" in _PROVIDER_RULES
        assert azure_rules.evaluate in _PROVIDER_RULES["azure"]


# ──────────────────────────────────────────────────────────────────────────────
# NSG rules
# ──────────────────────────────────────────────────────────────────────────────


class TestNSGAdminIngress:
    def test_public_ssh_fires_high(self):
        findings = evaluate(_nsg([_ingress_rule(src="*", dest_port="22")]))
        keys = {f.rule_key for f in findings}
        assert "azure_nsg_public_admin_ingress" in keys
        admin = next(f for f in findings if f.rule_key == "azure_nsg_public_admin_ingress")
        assert admin.severity == "high"
        assert admin.evidence["admin_port"] == 22

    def test_public_rdp_fires_critical(self):
        findings = evaluate(_nsg([_ingress_rule(src="0.0.0.0/0", dest_port="3389")]))
        admin = next(f for f in findings if f.rule_key == "azure_nsg_public_admin_ingress")
        assert admin.severity == "critical"
        assert admin.evidence["admin_port"] == 3389

    @pytest.mark.parametrize("port", [1433, 3306, 5432, 6379, 9200, 27017, 5985, 5986])
    def test_public_db_cache_admin_ports_fire_critical(self, port: int):
        findings = evaluate(_nsg([_ingress_rule(src="Internet", dest_port=str(port))]))
        admin = next(f for f in findings if f.rule_key == "azure_nsg_public_admin_ingress")
        assert admin.severity == "critical"
        assert admin.evidence["admin_port"] == port

    def test_critical_admin_port_beats_ssh_in_same_nsg(self):
        # RDP and SSH on same NSG — admin finding should be critical (RDP wins).
        findings = evaluate(
            _nsg(
                [
                    _ingress_rule(src="*", dest_port="22", name="allow-ssh"),
                    _ingress_rule(src="*", dest_port="3389", name="allow-rdp"),
                ]
            )
        )
        admin = [f for f in findings if f.rule_key == "azure_nsg_public_admin_ingress"]
        assert len(admin) == 1  # grouped per NSG
        assert admin[0].severity == "critical"

    def test_normal_web_ingress_does_not_fire_admin(self):
        for port in ("80", "443"):
            findings = evaluate(_nsg([_ingress_rule(src="*", dest_port=port)]))
            assert all(
                f.rule_key != "azure_nsg_public_admin_ingress" for f in findings
            ), f"web port {port} should not trigger admin"

    def test_private_source_does_not_fire(self):
        findings = evaluate(_nsg([_ingress_rule(src="10.0.0.0/24", dest_port="22")]))
        assert findings == []

    def test_outbound_rule_does_not_fire(self):
        findings = evaluate(
            _nsg([_ingress_rule(src="*", dest_port="22", direction="Outbound")])
        )
        assert findings == []

    def test_deny_rule_does_not_fire(self):
        findings = evaluate(
            _nsg([_ingress_rule(src="*", dest_port="22", access="Deny")])
        )
        assert findings == []


class TestNSGBroadIngress:
    @pytest.mark.parametrize("dest_port", ["*", "Any", "0-65535", "1-65535"])
    def test_broad_public_ports_fire_critical(self, dest_port: str):
        findings = evaluate(_nsg([_ingress_rule(src="*", dest_port=dest_port)]))
        broad = [f for f in findings if f.rule_key == "azure_nsg_public_broad_ingress"]
        assert len(broad) == 1
        assert broad[0].severity == "critical"
        assert broad[0].evidence["public_source"] is True

    def test_broad_and_admin_can_both_fire(self):
        findings = evaluate(
            _nsg(
                [
                    _ingress_rule(src="*", dest_port="*", name="broad"),
                    _ingress_rule(src="*", dest_port="3389", name="rdp"),
                ]
            )
        )
        rule_keys = {f.rule_key for f in findings}
        assert "azure_nsg_public_broad_ingress" in rule_keys
        assert "azure_nsg_public_admin_ingress" in rule_keys


# ──────────────────────────────────────────────────────────────────────────────
# Storage Account rules
# ──────────────────────────────────────────────────────────────────────────────


class TestStorageAccountRules:
    def test_public_blob_access_fires_high(self):
        findings = evaluate(_storage(allow_blob_public_access=True))
        match = [f for f in findings if f.rule_key == "azure_storage_public_blob_access"]
        assert len(match) == 1
        assert match[0].severity == "high"
        assert match[0].evidence["allow_blob_public_access"] is True

    def test_public_blob_access_false_does_not_fire(self):
        findings = evaluate(_storage(allow_blob_public_access=False))
        assert all(
            f.rule_key != "azure_storage_public_blob_access" for f in findings
        )

    def test_public_network_access_enabled_medium(self):
        findings = evaluate(
            _storage(public_network_access="Enabled", network_default_action="Deny")
        )
        match = next(
            f for f in findings if f.rule_key == "azure_storage_public_network_access"
        )
        assert match.severity == "medium"

    def test_public_network_access_enabled_default_allow_high(self):
        findings = evaluate(
            _storage(public_network_access="Enabled", network_default_action="Allow")
        )
        match = next(
            f for f in findings if f.rule_key == "azure_storage_public_network_access"
        )
        assert match.severity == "high"

    def test_public_network_access_disabled_does_not_fire(self):
        findings = evaluate(_storage(public_network_access="Disabled"))
        assert all(
            f.rule_key != "azure_storage_public_network_access" for f in findings
        )

    @pytest.mark.parametrize("tls", ["TLS1_0", "TLS1_1"])
    def test_weak_tls_fires(self, tls: str):
        findings = evaluate(_storage(minimum_tls_version=tls))
        match = next(f for f in findings if f.rule_key == "azure_storage_weak_tls")
        assert match.severity == "medium"
        assert match.evidence["minimum_tls_version"] == tls

    @pytest.mark.parametrize("tls", ["TLS1_2", "TLS1_3", ""])
    def test_strong_or_missing_tls_does_not_fire(self, tls: str):
        findings = evaluate(_storage(minimum_tls_version=tls))
        assert all(f.rule_key != "azure_storage_weak_tls" for f in findings)

    def test_shared_key_enabled_fires(self):
        findings = evaluate(_storage(shared_access_key_enabled=True))
        match = next(
            f for f in findings if f.rule_key == "azure_storage_shared_key_enabled"
        )
        assert match.severity == "medium"

    def test_shared_key_disabled_does_not_fire(self):
        findings = evaluate(_storage(shared_access_key_enabled=False))
        assert all(
            f.rule_key != "azure_storage_shared_key_enabled" for f in findings
        )


# ──────────────────────────────────────────────────────────────────────────────
# Key Vault rules
# ──────────────────────────────────────────────────────────────────────────────


class TestKeyVaultRules:
    def test_public_network_access_enabled_medium(self):
        findings = evaluate(
            _kv(public_network_access="Enabled", network_default_action="Deny")
        )
        match = next(
            f for f in findings if f.rule_key == "azure_key_vault_public_network_access"
        )
        assert match.severity == "medium"

    def test_public_network_access_default_allow_high(self):
        findings = evaluate(
            _kv(public_network_access="Enabled", network_default_action="Allow")
        )
        match = next(
            f for f in findings if f.rule_key == "azure_key_vault_public_network_access"
        )
        assert match.severity == "high"

    def test_purge_protection_disabled_with_soft_delete_on_medium(self):
        findings = evaluate(
            _kv(purge_protection_enabled=False, soft_delete_enabled=True)
        )
        match = next(
            f for f in findings if f.rule_key == "azure_key_vault_purge_protection_disabled"
        )
        assert match.severity == "medium"

    def test_purge_protection_disabled_with_soft_delete_off_high(self):
        findings = evaluate(
            _kv(purge_protection_enabled=False, soft_delete_enabled=False)
        )
        match = next(
            f for f in findings if f.rule_key == "azure_key_vault_purge_protection_disabled"
        )
        assert match.severity == "high"

    def test_soft_delete_disabled_fires(self):
        findings = evaluate(
            _kv(soft_delete_enabled=False, purge_protection_enabled=True)
        )
        match = next(
            f for f in findings if f.rule_key == "azure_key_vault_soft_delete_disabled"
        )
        assert match.severity == "medium"

    def test_rbac_disabled_with_access_policies_fires(self):
        findings = evaluate(
            _kv(enable_rbac_authorization=False, access_policy_count=3)
        )
        match = next(
            f for f in findings if f.rule_key == "azure_key_vault_rbac_disabled"
        )
        assert match.severity == "medium"
        assert match.evidence["access_policy_count"] == 3

    def test_rbac_disabled_without_access_policies_does_not_fire(self):
        findings = evaluate(
            _kv(enable_rbac_authorization=False, access_policy_count=0)
        )
        assert all(
            f.rule_key != "azure_key_vault_rbac_disabled" for f in findings
        )

    def test_rbac_enabled_does_not_fire_rbac_rule(self):
        findings = evaluate(
            _kv(enable_rbac_authorization=True, access_policy_count=5)
        )
        assert all(
            f.rule_key != "azure_key_vault_rbac_disabled" for f in findings
        )


# ──────────────────────────────────────────────────────────────────────────────
# Evidence safety + claim discipline
# ──────────────────────────────────────────────────────────────────────────────


class TestEvidenceSafety:
    def test_all_nsg_findings_have_safe_evidence(self):
        findings = evaluate(
            _nsg(
                [
                    _ingress_rule(src="*", dest_port="*", name="any-any"),
                    _ingress_rule(src="*", dest_port="3389", name="rdp"),
                ]
            )
        )
        assert findings
        for f in findings:
            _assert_evidence_safe(f.evidence, f.rule_key)

    def test_all_storage_findings_have_safe_evidence(self):
        findings = evaluate(
            _storage(
                allow_blob_public_access=True,
                public_network_access="Enabled",
                network_default_action="Allow",
                minimum_tls_version="TLS1_0",
                shared_access_key_enabled=True,
            )
        )
        assert len(findings) == 4
        for f in findings:
            _assert_evidence_safe(f.evidence, f.rule_key)

    def test_all_key_vault_findings_have_safe_evidence(self):
        findings = evaluate(
            _kv(
                public_network_access="Enabled",
                network_default_action="Allow",
                purge_protection_enabled=False,
                soft_delete_enabled=False,
                enable_rbac_authorization=False,
                access_policy_count=4,
            )
        )
        assert len(findings) == 4
        for f in findings:
            _assert_evidence_safe(f.evidence, f.rule_key)

    def test_evidence_never_contains_record_payload_fields(self):
        # Even if the connector accidentally surfaces a "secret" payload, the
        # rule MUST only include the allowlisted evidence keys (no leak-through).
        leaky_record = _storage(
            allow_blob_public_access=True,
            account_key="SUPERSECRET",  # contraband — must NOT appear in evidence
            connection_string="DefaultEndpointsProtocol=https;AccountName=x;AccountKey=SECRET=",
        )
        findings = evaluate(leaky_record)
        for f in findings:
            text = json.dumps(f.evidence).lower()
            assert "supersecret" not in text
            assert "accountkey" not in text
            assert "secret=" not in text
            assert "connection_string" not in f.evidence
            assert "account_key" not in f.evidence


class TestClaimDiscipline:
    def test_no_overclaim_phrases_in_any_rule_description(self):
        all_findings = []
        all_findings.extend(
            evaluate(
                _nsg(
                    [
                        _ingress_rule(src="*", dest_port="*", name="any"),
                        _ingress_rule(src="*", dest_port="3389", name="rdp"),
                    ]
                )
            )
        )
        all_findings.extend(
            evaluate(
                _storage(
                    allow_blob_public_access=True,
                    public_network_access="Enabled",
                    network_default_action="Allow",
                    minimum_tls_version="TLS1_0",
                    shared_access_key_enabled=True,
                )
            )
        )
        all_findings.extend(
            evaluate(
                _kv(
                    public_network_access="Enabled",
                    network_default_action="Allow",
                    purge_protection_enabled=False,
                    soft_delete_enabled=False,
                    enable_rbac_authorization=False,
                    access_policy_count=4,
                )
            )
        )
        assert len(all_findings) == 10  # all 10 azure rules fire
        for f in all_findings:
            text = f.description.lower()
            for bad in _FORBIDDEN_CLAIMS:
                assert bad not in text, (
                    f"forbidden claim {bad!r} in {f.rule_key} description: {f.description}"
                )
            # Must include the standard disclaimer.
            assert "does not confirm compromise" in text, (
                f"{f.rule_key} missing claim disclaimer"
            )

    def test_descriptions_use_hedged_language(self):
        f = evaluate(
            _nsg([_ingress_rule(src="*", dest_port="3389", name="rdp")])
        )[0]
        # "may" hedge required somewhere in description
        assert " may " in f.description.lower()


# ──────────────────────────────────────────────────────────────────────────────
# Registry / confidence / pack / coverage / catalog parity
# ──────────────────────────────────────────────────────────────────────────────


class TestRuleKeyParity:
    EXPECTED = {
        "azure_nsg_public_admin_ingress",
        "azure_nsg_public_broad_ingress",
        "azure_storage_public_blob_access",
        "azure_storage_public_network_access",
        "azure_storage_weak_tls",
        "azure_storage_shared_key_enabled",
        "azure_key_vault_public_network_access",
        "azure_key_vault_purge_protection_disabled",
        "azure_key_vault_soft_delete_disabled",
        "azure_key_vault_rbac_disabled",
    }

    def test_rule_module_exposes_all_keys(self):
        """Flipped in M77C: AZURE_RULE_KEYS now contains 20 keys (10 M77C added)."""
        assert self.EXPECTED.issubset(AZURE_RULE_KEYS), (
            f"M77B keys missing from AZURE_RULE_KEYS: {self.EXPECTED - AZURE_RULE_KEYS}"
        )

    def test_registry_contains_all_azure_keys(self):
        missing = self.EXPECTED - set(KNOWN_RULE_KEYS)
        assert missing == set(), f"missing in KNOWN_RULE_KEYS: {missing}"

    def test_confidence_has_entries_for_all_azure_keys(self):
        missing = self.EXPECTED - set(RULE_CONFIDENCE)
        assert missing == set(), f"missing in RULE_CONFIDENCE: {missing}"

    def test_pack_meta_has_entries_for_all_azure_keys(self):
        missing = self.EXPECTED - set(_RULE_META)
        assert missing == set(), f"missing in _RULE_META: {missing}"
        # Provider must be 'azure' for each
        for k in self.EXPECTED:
            provider, _sev, _cat = _RULE_META[k]
            assert provider == "azure", f"{k} pack provider != azure"

    def test_pack_summary_includes_azure(self):
        summary = pack_summary()
        keys = {r["rule_key"] for r in summary["rules"]}
        assert self.EXPECTED.issubset(keys)
        assert "azure" in summary["providers"]

    def test_coverage_has_entries_for_all_azure_keys(self):
        missing = self.EXPECTED - set(RULE_RECORD_TYPES)
        assert missing == set(), f"missing in RULE_RECORD_TYPES: {missing}"
        # NSG rules → azure_network_security_group
        for k in (
            "azure_nsg_public_admin_ingress",
            "azure_nsg_public_broad_ingress",
        ):
            assert RULE_RECORD_TYPES[k] == ("azure_network_security_group",)
        # Storage rules → azure_storage_account
        for k in (
            "azure_storage_public_blob_access",
            "azure_storage_public_network_access",
            "azure_storage_weak_tls",
            "azure_storage_shared_key_enabled",
        ):
            assert RULE_RECORD_TYPES[k] == ("azure_storage_account",)
        # Key Vault rules → azure_key_vault
        for k in (
            "azure_key_vault_public_network_access",
            "azure_key_vault_purge_protection_disabled",
            "azure_key_vault_soft_delete_disabled",
            "azure_key_vault_rbac_disabled",
        ):
            assert RULE_RECORD_TYPES[k] == ("azure_key_vault",)

    def test_azure_in_coverage_providers_and_surfaces(self):
        """Flipped in M77C: PROVIDER_SURFACES["azure"] now includes 7 surfaces."""
        assert "azure" in COVERAGE_PROVIDERS
        # M77B surfaces must still be present; M77C surfaces are additive
        for surface in ("Network security groups", "Storage accounts", "Key Vaults"):
            assert surface in PROVIDER_SURFACES["azure"]


# ──────────────────────────────────────────────────────────────────────────────
# Capability matrix + expansion framework
# ──────────────────────────────────────────────────────────────────────────────


class TestProviderCapabilityMatrix:
    def test_azure_security_rules_marked_true(self):
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.security.security_rules is True
        # Drift risk classification flipped on with M77B as well
        assert cap.drift.drift_risk_classification is True
        # Maturity remains partial until M77C+
        assert cap.maturity == "partial"

    def test_azure_unfinished_security_surfaces_still_false(self):
        """Flipped in M77D/E/F: activity_ingestion + signals + correlations all True now."""
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.security.activity_ingestion is True   # flipped in M77D
        assert cap.security.activity_signals is True     # flipped in M77E
        assert cap.security.risk_activity_correlations is True  # flipped in M77F
        assert cap.security.demo_seed_clear is False


class TestProviderExpansionFramework:
    def test_planned_next_stage_points_to_m77c(self):
        """Flipped in M77F: planned_next_stage now points to M77G."""
        framework = get_framework()
        stage = framework["summary"]["planned_next_stage"]
        assert "M77G" in stage, (
            f"planned_next_stage should reference M77D after M77C, got: {stage!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Frontend catalog presence
# ──────────────────────────────────────────────────────────────────────────────


class TestFrontendCatalog:
    def test_all_azure_keys_present_in_catalog(self):
        if not FRONTEND_CATALOG.exists():
            pytest.skip("frontend/src not mounted in this environment")
        text = FRONTEND_CATALOG.read_text()
        for key in TestRuleKeyParity.EXPECTED:
            assert f'key: "{key}"' in text, (
                f"frontend catalog missing rule key {key}"
            )

    def test_azure_marked_metadata_only(self):
        if not FRONTEND_CATALOG.exists():
            pytest.skip("frontend/src not mounted in this environment")
        text = FRONTEND_CATALOG.read_text()
        # Find each azure block and ensure metadataOnly: true
        for key in TestRuleKeyParity.EXPECTED:
            m = re.search(
                rf'key: "{re.escape(key)}".*?\}},',
                text,
                flags=re.DOTALL,
            )
            assert m is not None, f"catalog block for {key} not found"
            block = m.group(0)
            assert "provider: \"azure\"" in block
            assert "metadataOnly: true" in block, (
                f"{key} catalog entry not marked metadataOnly:true"
            )


# ──────────────────────────────────────────────────────────────────────────────
# M77A canonical record_type regression
# ──────────────────────────────────────────────────────────────────────────────


class TestM77ACanonicalRecordTypes:
    def test_constants_are_lowercase_snake(self):
        assert AZURE_SUBSCRIPTION == "azure_subscription"
        assert AZURE_RESOURCE_GROUP == "azure_resource_group"
        assert AZURE_NETWORK_SECURITY_GROUP == "azure_network_security_group"
        assert AZURE_STORAGE_ACCOUNT == "azure_storage_account"
        assert AZURE_KEY_VAULT == "azure_key_vault"
