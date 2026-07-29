"""Microsoft Entra ID security-rule registry parity tests (Entra message 6
of 8).

Asserts exact Entra rule-key parity across every metadata layer: security
rule module, evaluator dispatch, registry, confidence, pack, coverage
record-type mapping, and frontend catalog. Also checks severity/category
consistency, duplicate-key detection, and Finding-vs-Change severity
parity for representative rules.

Entra remains internally-registered but NOT publicly connectable until
message 8 — this file explicitly asserts "entra" is absent from
security_coverage_service.PROVIDERS / PROVIDER_SURFACES (which drive the
live connected-integration coverage UI), while still requiring full
RULE_RECORD_TYPES mapping parity so the groundwork is ready (mirroring
Okta's identical pre-launch pattern at its own message 6).
"""

from __future__ import annotations

import re
from pathlib import Path

from app.services import security_coverage_service, security_rule_pack
from app.services.security_finding_evaluator import _PROVIDER_RULES
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules import entra as entra_rules

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FRONTEND_CATALOG = _REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"


def _module_rule_keys() -> set[str]:
    src = Path(entra_rules.__file__).read_text()
    consts = dict(re.findall(r'(_RULE_\w+)\s*=\s*"(entra_[a-z_0-9]+)"', src))
    return set(consts.values())


def _registry_entra_keys() -> set[str]:
    return {k for k in KNOWN_RULE_KEYS if k.startswith("entra_")}


def _confidence_entra_keys() -> set[str]:
    return {k for k in RULE_CONFIDENCE if k.startswith("entra_")}


def _pack_entra_keys() -> set[str]:
    return {k for k in security_rule_pack._RULE_META if k.startswith("entra_")}


def _coverage_entra_keys() -> set[str]:
    return {k for k in security_coverage_service.RULE_RECORD_TYPES if k.startswith("entra_")}


def _frontend_entra_keys() -> set[str]:
    text = _FRONTEND_CATALOG.read_text()
    return set(re.findall(r'key:\s*"(entra_[a-z_0-9]+)"', text))


class TestModuleDispatchReachable:
    def test_evaluate_is_callable(self):
        assert callable(entra_rules.evaluate)

    def test_entra_dispatched_in_evaluator(self):
        assert "entra" in _PROVIDER_RULES
        assert entra_rules.evaluate in _PROVIDER_RULES["entra"]

    def test_module_has_at_least_forty_five_rule_keys(self):
        keys = _module_rule_keys()
        assert len(keys) >= 45, f"only {len(keys)} entra rule keys found"

    def test_no_duplicate_rule_key_constants(self):
        src = Path(entra_rules.__file__).read_text()
        consts = re.findall(r'(_RULE_\w+)\s*=\s*"(entra_[a-z_0-9]+)"', src)
        keys = [k for _const, k in consts]
        assert len(keys) == len(set(keys)), "duplicate entra_* rule key value found"


class TestRegistryParity:
    def test_module_keys_subset_of_registry(self):
        missing = _module_rule_keys() - _registry_entra_keys()
        assert not missing, f"rule keys missing from security_rule_registry: {sorted(missing)}"

    def test_registry_has_no_extra_entra_keys(self):
        extra = _registry_entra_keys() - _module_rule_keys()
        assert not extra, f"registry has entra_* keys with no matching rule: {sorted(extra)}"


class TestConfidenceParity:
    def test_every_registered_entra_rule_has_confidence(self):
        missing = _registry_entra_keys() - _confidence_entra_keys()
        assert not missing, f"missing confidence entries: {sorted(missing)}"

    def test_no_extra_confidence_entries(self):
        extra = _confidence_entra_keys() - _registry_entra_keys()
        assert not extra, f"confidence has orphaned entra_* keys: {sorted(extra)}"

    def test_confidence_values_are_high_or_medium(self):
        from app.services.security_rule_confidence import HIGH, MEDIUM
        for key in _confidence_entra_keys():
            confidence, _guard = RULE_CONFIDENCE[key]
            assert confidence in (HIGH, MEDIUM), f"{key} has non-high/medium confidence {confidence!r}"

    def test_every_confidence_entry_has_a_guard_reason(self):
        for key in _confidence_entra_keys():
            _confidence, guard = RULE_CONFIDENCE[key]
            assert isinstance(guard, str) and guard, f"{key} has an empty false_positive_guard"


class TestPackParity:
    def test_every_registered_entra_rule_in_pack(self):
        missing = _registry_entra_keys() - _pack_entra_keys()
        assert not missing, f"missing pack entries: {sorted(missing)}"

    def test_no_extra_pack_entries(self):
        extra = _pack_entra_keys() - _registry_entra_keys()
        assert not extra, f"pack has orphaned entra_* keys: {sorted(extra)}"

    def test_pack_provider_is_entra_for_all_entries(self):
        for key in _pack_entra_keys():
            provider, _severity, _category = security_rule_pack._RULE_META[key]
            assert provider == "entra"

    def test_pack_severity_values_are_valid(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for key in _pack_entra_keys():
            _provider, severity, _category = security_rule_pack._RULE_META[key]
            assert severity in valid, f"{key} has invalid severity {severity!r}"

    def test_pack_manifest_self_check_passes(self):
        assert set(security_rule_pack._RULE_META) == set(KNOWN_RULE_KEYS)

    def test_pack_summary_includes_entra(self):
        summary = security_rule_pack.pack_summary()
        assert "entra" in summary["providers"]
        entra_rules_in_summary = [r for r in summary["rules"] if r["provider"] == "entra"]
        assert len(entra_rules_in_summary) == len(_pack_entra_keys())

    def test_pack_categories_cover_expected_buckets(self):
        categories = {c for k in _pack_entra_keys() for _p, _s, c in [security_rule_pack._RULE_META[k]]}
        expected = {
            "Privileged identities & directory roles",
            "Privileged service principals",
            "Consent & OAuth grants",
            "Conditional Access & MFA",
            "Authentication methods",
            "Applications & credentials",
            "Identity lifecycle",
            "Groups & app assignment posture",
        }
        assert expected.issubset(categories), f"missing categories: {expected - categories}"


class TestCoverageParity:
    def test_entra_in_connectable_providers_list(self):
        # Message 8: Entra is now publicly connectable — must appear in the
        # live connected-integration coverage surface.
        assert "entra" in security_coverage_service.PROVIDERS

    def test_entra_in_provider_surfaces(self):
        assert "entra" in security_coverage_service.PROVIDER_SURFACES

    def test_every_registered_entra_rule_has_record_types(self):
        missing = _registry_entra_keys() - _coverage_entra_keys()
        assert not missing, f"missing coverage RULE_RECORD_TYPES entries: {sorted(missing)}"

    def test_no_extra_coverage_entries(self):
        extra = _coverage_entra_keys() - _registry_entra_keys()
        assert not extra, f"coverage has orphaned entra_* keys: {sorted(extra)}"

    def test_provider_of_resolves_correctly(self):
        for key in _registry_entra_keys():
            assert security_coverage_service._provider_of(key) == "entra"

    def test_expected_record_types_non_empty(self):
        expected = security_coverage_service._expected_record_types("entra")
        assert len(expected) > 0


class TestFrontendParity:
    def test_frontend_catalog_file_exists(self):
        assert _FRONTEND_CATALOG.exists()

    def test_every_registered_entra_rule_in_frontend_catalog(self):
        missing = _registry_entra_keys() - _frontend_entra_keys()
        assert not missing, f"missing frontend catalog entries: {sorted(missing)}"

    def test_no_frontend_only_entra_rules(self):
        extra = _frontend_entra_keys() - _registry_entra_keys()
        assert not extra, f"frontend catalog has entra_* keys with no backend rule: {sorted(extra)}"

    def test_frontend_entries_have_provider_entra(self):
        text = _FRONTEND_CATALOG.read_text()
        for m in re.finditer(r'key:\s*"(entra_[a-z_0-9]+)"', text):
            window = text[m.start(): m.start() + 400]
            assert 'provider: "entra"' in window, f"{m.group(1)} missing provider field nearby"

    def test_frontend_severity_matches_backend_pack(self):
        text = _FRONTEND_CATALOG.read_text()
        for key in _frontend_entra_keys():
            block_match = re.search(r'key:\s*"' + re.escape(key) + r'".*?falsePositiveGuard:', text, re.DOTALL)
            assert block_match, f"could not isolate frontend block for {key}"
            block = block_match.group(0)
            fe_severity = re.search(r'severity:\s*"(\w+)"', block).group(1)
            _provider, backend_severity, _category = security_rule_pack._RULE_META[key]
            assert fe_severity == backend_severity, f"{key}: frontend severity {fe_severity!r} != backend {backend_severity!r}"


class TestFullCrossLayerParity:
    def test_all_layers_have_identical_entra_key_sets(self):
        layers = {
            "module": _module_rule_keys(),
            "registry": _registry_entra_keys(),
            "confidence": _confidence_entra_keys(),
            "pack": _pack_entra_keys(),
            "coverage": _coverage_entra_keys(),
            "frontend": _frontend_entra_keys(),
        }
        reference = layers["registry"]
        for name, keys in layers.items():
            assert keys == reference, (
                f"{name} layer diverges from registry — "
                f"missing={sorted(reference - keys)} extra={sorted(keys - reference)}"
            )

    def test_expected_rule_count_is_45(self):
        # Pinned count — update deliberately if the taxonomy changes; a
        # silent drift here should fail loudly rather than pass unnoticed.
        assert len(_registry_entra_keys()) == 45


class TestFindingVsChangeSeverityParity:
    """bad-state Change severity >= static Finding severity, for
    representative high-value rules (message-6 prevention of obvious
    mismatches — message 7 does exhaustive QA)."""

    _RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def _finding_severity(self, rule_key: str) -> str:
        _provider, severity, _category = security_rule_pack._RULE_META[rule_key]
        return severity

    def test_global_admin_assigned_change_at_least_as_severe(self):
        from app.services.risk_rules.entra import classify_entra_change
        change = {
            "change_type": "added",
            "field_path": None,
            "prev_value": None,
            "new_value": None,
            "provider_metadata": {
                "record_type": "entra_directory_role_assignment",
                "role_template_id": "62e90394-69f5-4237-9190-012177145e10",
                "privilege_tier": "critical",
                "role_name": "Global Administrator",
            },
        }
        change_severity, _reason = classify_entra_change(change)
        finding_severity = self._finding_severity("entra_global_admin_assigned")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_privileged_role_administrator_change_at_least_as_severe(self):
        from app.services.risk_rules.entra import classify_entra_change
        change = {
            "change_type": "added",
            "field_path": None,
            "prev_value": None,
            "new_value": None,
            "provider_metadata": {
                "record_type": "entra_directory_role_assignment",
                "role_template_id": "e8611ab8-c189-46e8-94e1-60213ab1f814",
                "privilege_tier": "critical",
                "role_name": "Privileged Role Administrator",
            },
        }
        change_severity, _reason = classify_entra_change(change)
        finding_severity = self._finding_severity("entra_privileged_role_administrator_assigned")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_high_tier_admin_change_at_least_as_severe(self):
        from app.services.risk_rules.entra import classify_entra_change
        change = {
            "change_type": "added",
            "field_path": None,
            "prev_value": None,
            "new_value": None,
            "provider_metadata": {
                "record_type": "entra_directory_role_assignment",
                "role_template_id": None,
                "privilege_tier": "high",
                "role_name": "Application Administrator",
            },
        }
        change_severity, _reason = classify_entra_change(change)
        finding_severity = self._finding_severity("entra_high_tier_admin_assigned")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_group_grants_global_admin_change_at_least_as_severe(self):
        from app.services.risk_rules.entra import classify_entra_change
        change = {
            "change_type": "added",
            "field_path": None,
            "prev_value": None,
            "new_value": None,
            "provider_metadata": {"record_type": "entra_privileged_group", "highest_privilege_tier": "critical"},
        }
        change_severity, _reason = classify_entra_change(change)
        finding_severity = self._finding_severity("entra_group_has_global_admin")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_guest_global_admin_change_at_least_as_severe(self):
        from app.services.risk_rules.entra import classify_entra_change
        change = {
            "change_type": "modified",
            "field_path": "has_global_admin",
            "prev_value": False,
            "new_value": True,
            "provider_metadata": {"record_type": "entra_privileged_identity", "highest_privilege_tier": "critical"},
        }
        change_severity, _reason = classify_entra_change(change)
        finding_severity = self._finding_severity("entra_guest_global_admin")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_critical_sp_permission_change_at_least_as_severe(self):
        from app.services.risk_rules.entra import classify_entra_change
        change = {
            "change_type": "added",
            "field_path": None,
            "prev_value": None,
            "new_value": None,
            "provider_metadata": {
                "record_type": "entra_service_principal_app_role_assignment",
                "app_role_risk_category": "high_risk",
                "app_role_privilege_tier": "critical",
            },
        }
        change_severity, _reason = classify_entra_change(change)
        finding_severity = self._finding_severity("entra_service_principal_can_manage_directory_roles")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_tenant_wide_high_risk_consent_change_at_least_as_severe(self):
        from app.services.risk_rules.entra import classify_entra_change
        change = {
            "change_type": "added",
            "field_path": None,
            "prev_value": None,
            "new_value": None,
            "provider_metadata": {
                "record_type": "entra_oauth2_permission_grant",
                "consent_type_category": "AllPrincipals",
                "high_risk_scope_present": True,
            },
        }
        change_severity, _reason = classify_entra_change(change)
        finding_severity = self._finding_severity("entra_tenant_wide_high_risk_delegated_consent")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_no_mfa_ca_policy_change_at_least_as_severe(self):
        from app.services.risk_rules.entra import classify_entra_change
        change = {
            "change_type": "modified",
            "field_path": "mfa_requirement_category",
            "prev_value": "required",
            "new_value": "not_required",
            "provider_metadata": {"record_type": "entra_conditional_access_policy", "state_category": "enabled"},
        }
        change_severity, _reason = classify_entra_change(change)
        finding_severity = self._finding_severity("entra_ca_broad_access_without_mfa")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_wildcard_redirect_change_at_least_as_severe(self):
        from app.services.risk_rules.entra import classify_entra_change
        change = {
            "change_type": "modified",
            "field_path": "has_wildcard_redirect",
            "prev_value": False,
            "new_value": True,
            "provider_metadata": {"record_type": "entra_application"},
        }
        change_severity, _reason = classify_entra_change(change)
        finding_severity = self._finding_severity("entra_application_wildcard_redirect")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]
