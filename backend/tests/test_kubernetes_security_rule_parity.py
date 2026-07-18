"""Kubernetes security-rule registry parity tests (Kubernetes message 6 of 9).

Asserts exact Kubernetes rule-key parity across every metadata layer:
security rule module, evaluator dispatch, registry, confidence, pack,
coverage, and frontend catalog. Also checks severity/category consistency
and duplicate-key detection.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.services import security_coverage_service, security_rule_pack
from app.services.security_finding_evaluator import _PROVIDER_RULES
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules import kubernetes as k8s_rules

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FRONTEND_CATALOG = (
    _REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"
)


def _module_rule_keys() -> set[str]:
    src = Path(k8s_rules.__file__).read_text()
    consts = dict(re.findall(r'(_RULE_\w+)\s*=\s*"(kubernetes_[a-z_0-9]+)"', src))
    return set(consts.values())


def _registry_kubernetes_keys() -> set[str]:
    return {k for k in KNOWN_RULE_KEYS if k.startswith("kubernetes_")}


def _confidence_kubernetes_keys() -> set[str]:
    return {k for k in RULE_CONFIDENCE if k.startswith("kubernetes_")}


def _pack_kubernetes_keys() -> set[str]:
    return {k for k in security_rule_pack._RULE_META if k.startswith("kubernetes_")}


def _coverage_kubernetes_keys() -> set[str]:
    return {k for k in security_coverage_service.RULE_RECORD_TYPES if k.startswith("kubernetes_")}


def _frontend_kubernetes_keys() -> set[str]:
    text = _FRONTEND_CATALOG.read_text()
    return set(re.findall(r'key:\s*"(kubernetes_[a-z_0-9]+)"', text))


class TestModuleDispatchReachable:
    def test_evaluate_is_callable(self):
        assert callable(k8s_rules.evaluate)

    def test_kubernetes_dispatched_in_evaluator(self):
        assert "kubernetes" in _PROVIDER_RULES
        assert k8s_rules.evaluate in _PROVIDER_RULES["kubernetes"]

    def test_module_has_at_least_thirty_rule_keys(self):
        keys = _module_rule_keys()
        assert len(keys) >= 30, f"only {len(keys)} kubernetes rule keys found"

    def test_no_duplicate_rule_key_constants(self):
        src = Path(k8s_rules.__file__).read_text()
        consts = re.findall(r'(_RULE_\w+)\s*=\s*"(kubernetes_[a-z_0-9]+)"', src)
        keys = [k for _const, k in consts]
        assert len(keys) == len(set(keys)), "duplicate kubernetes_* rule key value found"


class TestRegistryParity:
    def test_module_keys_subset_of_registry(self):
        module_keys = _module_rule_keys()
        registry_keys = _registry_kubernetes_keys()
        missing = module_keys - registry_keys
        assert not missing, f"rule keys missing from security_rule_registry: {sorted(missing)}"

    def test_registry_has_no_extra_kubernetes_keys(self):
        module_keys = _module_rule_keys()
        registry_keys = _registry_kubernetes_keys()
        extra = registry_keys - module_keys
        assert not extra, f"registry has kubernetes_* keys with no matching rule: {sorted(extra)}"


class TestConfidenceParity:
    def test_every_registered_kubernetes_rule_has_confidence(self):
        registry_keys = _registry_kubernetes_keys()
        confidence_keys = _confidence_kubernetes_keys()
        missing = registry_keys - confidence_keys
        assert not missing, f"missing confidence entries: {sorted(missing)}"

    def test_no_extra_confidence_entries(self):
        registry_keys = _registry_kubernetes_keys()
        confidence_keys = _confidence_kubernetes_keys()
        extra = confidence_keys - registry_keys
        assert not extra, f"confidence has orphaned kubernetes_* keys: {sorted(extra)}"

    def test_confidence_values_are_high_or_medium(self):
        from app.services.security_rule_confidence import HIGH, MEDIUM
        for key in _confidence_kubernetes_keys():
            confidence, _guard = RULE_CONFIDENCE[key]
            assert confidence in (HIGH, MEDIUM), f"{key} has non-high/medium confidence {confidence!r}"


class TestPackParity:
    def test_every_registered_kubernetes_rule_in_pack(self):
        registry_keys = _registry_kubernetes_keys()
        pack_keys = _pack_kubernetes_keys()
        missing = registry_keys - pack_keys
        assert not missing, f"missing pack entries: {sorted(missing)}"

    def test_no_extra_pack_entries(self):
        registry_keys = _registry_kubernetes_keys()
        pack_keys = _pack_kubernetes_keys()
        extra = pack_keys - registry_keys
        assert not extra, f"pack has orphaned kubernetes_* keys: {sorted(extra)}"

    def test_pack_provider_is_kubernetes_for_all_entries(self):
        for key in _pack_kubernetes_keys():
            provider, _severity, _category = security_rule_pack._RULE_META[key]
            assert provider == "kubernetes"

    def test_pack_severity_values_are_valid(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for key in _pack_kubernetes_keys():
            _provider, severity, _category = security_rule_pack._RULE_META[key]
            assert severity in valid, f"{key} has invalid severity {severity!r}"

    def test_pack_manifest_self_check_passes(self):
        # Import-time assert in security_rule_pack already ran; re-derive to
        # prove kubernetes specifically is balanced against KNOWN_RULE_KEYS.
        assert set(security_rule_pack._RULE_META) == set(KNOWN_RULE_KEYS)

    def test_pack_summary_includes_kubernetes(self):
        summary = security_rule_pack.pack_summary()
        assert "kubernetes" in summary["providers"]
        k8s_rules_in_summary = [r for r in summary["rules"] if r["provider"] == "kubernetes"]
        assert len(k8s_rules_in_summary) == len(_pack_kubernetes_keys())


class TestCoverageParity:
    def test_kubernetes_in_providers_list(self):
        assert "kubernetes" in security_coverage_service.PROVIDERS

    def test_every_registered_kubernetes_rule_has_record_types(self):
        registry_keys = _registry_kubernetes_keys()
        coverage_keys = _coverage_kubernetes_keys()
        missing = registry_keys - coverage_keys
        assert not missing, f"missing coverage RULE_RECORD_TYPES entries: {sorted(missing)}"

    def test_no_extra_coverage_entries(self):
        registry_keys = _registry_kubernetes_keys()
        coverage_keys = _coverage_kubernetes_keys()
        extra = coverage_keys - registry_keys
        assert not extra, f"coverage has orphaned kubernetes_* keys: {sorted(extra)}"

    def test_provider_of_resolves_correctly(self):
        for key in _registry_kubernetes_keys():
            assert security_coverage_service._provider_of(key) == "kubernetes"

    def test_expected_record_types_non_empty(self):
        expected = security_coverage_service._expected_record_types("kubernetes")
        assert len(expected) > 0

    def test_kubernetes_has_provider_surfaces(self):
        assert "kubernetes" in security_coverage_service.PROVIDER_SURFACES
        assert len(security_coverage_service.PROVIDER_SURFACES["kubernetes"]) > 0


class TestFrontendParity:
    def test_frontend_catalog_file_exists(self):
        assert _FRONTEND_CATALOG.exists()

    def test_every_registered_kubernetes_rule_in_frontend_catalog(self):
        registry_keys = _registry_kubernetes_keys()
        frontend_keys = _frontend_kubernetes_keys()
        missing = registry_keys - frontend_keys
        assert not missing, f"missing frontend catalog entries: {sorted(missing)}"

    def test_no_frontend_only_kubernetes_rules(self):
        registry_keys = _registry_kubernetes_keys()
        frontend_keys = _frontend_kubernetes_keys()
        extra = frontend_keys - registry_keys
        assert not extra, f"frontend catalog has kubernetes_* keys with no backend rule: {sorted(extra)}"

    def test_frontend_entries_have_provider_kubernetes(self):
        text = _FRONTEND_CATALOG.read_text()
        # Every kubernetes_* catalog entry block must declare provider: "kubernetes"
        # nearby (within the same object literal) — spot check via a bounded window.
        for m in re.finditer(r'key:\s*"(kubernetes_[a-z_0-9]+)"', text):
            window = text[m.start(): m.start() + 400]
            assert 'provider: "kubernetes"' in window, f"{m.group(1)} missing provider field nearby"


class TestFullCrossLayerParity:
    def test_all_layers_have_identical_kubernetes_key_sets(self):
        module_keys = _module_rule_keys()
        registry_keys = _registry_kubernetes_keys()
        confidence_keys = _confidence_kubernetes_keys()
        pack_keys = _pack_kubernetes_keys()
        coverage_keys = _coverage_kubernetes_keys()
        frontend_keys = _frontend_kubernetes_keys()

        layers = {
            "module": module_keys,
            "registry": registry_keys,
            "confidence": confidence_keys,
            "pack": pack_keys,
            "coverage": coverage_keys,
            "frontend": frontend_keys,
        }
        reference = layers["registry"]
        for name, keys in layers.items():
            assert keys == reference, (
                f"{name} layer diverges from registry — "
                f"missing={sorted(reference - keys)} extra={sorted(keys - reference)}"
            )

    def test_expected_rule_count_is_59(self):
        # Pinned count — update deliberately if the taxonomy changes; a
        # silent drift here should fail loudly rather than pass unnoticed.
        assert len(_registry_kubernetes_keys()) == 59
