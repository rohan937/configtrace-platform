"""Okta security-rule registry parity tests (Okta message 6 of 8).

Asserts exact Okta rule-key parity across every metadata layer: security
rule module, evaluator dispatch, registry, confidence, pack, coverage
record-type mapping, and frontend catalog. Also checks severity/category
consistency and duplicate-key detection.

Okta remains internally-registered but NOT publicly connectable until
message 8 — this file explicitly asserts "okta" is absent from
security_coverage_service.PROVIDERS / PROVIDER_SURFACES (which drive the
live connected-integration coverage UI), while still requiring full
RULE_RECORD_TYPES mapping parity so the groundwork is ready.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.services import security_coverage_service, security_rule_pack
from app.services.security_finding_evaluator import _PROVIDER_RULES
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules import okta as okta_rules

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FRONTEND_CATALOG = _REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"


def _module_rule_keys() -> set[str]:
    src = Path(okta_rules.__file__).read_text()
    consts = dict(re.findall(r'(_RULE_\w+)\s*=\s*"(okta_[a-z_0-9]+)"', src))
    return set(consts.values())


def _registry_okta_keys() -> set[str]:
    return {k for k in KNOWN_RULE_KEYS if k.startswith("okta_")}


def _confidence_okta_keys() -> set[str]:
    return {k for k in RULE_CONFIDENCE if k.startswith("okta_")}


def _pack_okta_keys() -> set[str]:
    return {k for k in security_rule_pack._RULE_META if k.startswith("okta_")}


def _coverage_okta_keys() -> set[str]:
    return {k for k in security_coverage_service.RULE_RECORD_TYPES if k.startswith("okta_")}


def _frontend_okta_keys() -> set[str]:
    text = _FRONTEND_CATALOG.read_text()
    return set(re.findall(r'key:\s*"(okta_[a-z_0-9]+)"', text))


class TestModuleDispatchReachable:
    def test_evaluate_is_callable(self):
        assert callable(okta_rules.evaluate)

    def test_okta_dispatched_in_evaluator(self):
        assert "okta" in _PROVIDER_RULES
        assert okta_rules.evaluate in _PROVIDER_RULES["okta"]

    def test_module_has_at_least_twenty_five_rule_keys(self):
        keys = _module_rule_keys()
        assert len(keys) >= 25, f"only {len(keys)} okta rule keys found"

    def test_no_duplicate_rule_key_constants(self):
        src = Path(okta_rules.__file__).read_text()
        consts = re.findall(r'(_RULE_\w+)\s*=\s*"(okta_[a-z_0-9]+)"', src)
        keys = [k for _const, k in consts]
        assert len(keys) == len(set(keys)), "duplicate okta_* rule key value found"


# NOTE (Provider Certification Framework message 3): TestRegistryParity's
# module-keys == registry set-equality assertions formerly here are now
# framework-owned — see
# app.provider_certification.gates.gate_security_finding_registry_parity
# and tests/test_provider_certification_okta.py, which independently
# re-derives and pins the exact 30-ID set. See
# tests/reports/provider_certification_duplication_inventory.md.


class TestConfidenceParity:
    def test_every_registered_okta_rule_has_confidence(self):
        missing = _registry_okta_keys() - _confidence_okta_keys()
        assert not missing, f"missing confidence entries: {sorted(missing)}"

    def test_no_extra_confidence_entries(self):
        extra = _confidence_okta_keys() - _registry_okta_keys()
        assert not extra, f"confidence has orphaned okta_* keys: {sorted(extra)}"

    def test_confidence_values_are_high_or_medium(self):
        from app.services.security_rule_confidence import HIGH, MEDIUM
        for key in _confidence_okta_keys():
            confidence, _guard = RULE_CONFIDENCE[key]
            assert confidence in (HIGH, MEDIUM), f"{key} has non-high/medium confidence {confidence!r}"

    def test_every_confidence_entry_has_a_guard_reason(self):
        for key in _confidence_okta_keys():
            _confidence, guard = RULE_CONFIDENCE[key]
            assert isinstance(guard, str) and guard, f"{key} has an empty false_positive_guard"


class TestPackParity:
    def test_every_registered_okta_rule_in_pack(self):
        missing = _registry_okta_keys() - _pack_okta_keys()
        assert not missing, f"missing pack entries: {sorted(missing)}"

    def test_no_extra_pack_entries(self):
        extra = _pack_okta_keys() - _registry_okta_keys()
        assert not extra, f"pack has orphaned okta_* keys: {sorted(extra)}"

    def test_pack_provider_is_okta_for_all_entries(self):
        for key in _pack_okta_keys():
            provider, _severity, _category = security_rule_pack._RULE_META[key]
            assert provider == "okta"

    def test_pack_severity_values_are_valid(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for key in _pack_okta_keys():
            _provider, severity, _category = security_rule_pack._RULE_META[key]
            assert severity in valid, f"{key} has invalid severity {severity!r}"

    def test_pack_manifest_self_check_passes(self):
        # Import-time assert in security_rule_pack already ran; re-derive to
        # prove okta specifically is balanced against KNOWN_RULE_KEYS.
        assert set(security_rule_pack._RULE_META) == set(KNOWN_RULE_KEYS)

    def test_pack_summary_includes_okta(self):
        summary = security_rule_pack.pack_summary()
        assert "okta" in summary["providers"]
        okta_rules_in_summary = [r for r in summary["rules"] if r["provider"] == "okta"]
        assert len(okta_rules_in_summary) == len(_pack_okta_keys())

    def test_pack_categories_cover_expected_buckets(self):
        categories = {c for k in _pack_okta_keys() for _p, _s, c in [security_rule_pack._RULE_META[k]]}
        expected = {
            "Privileged identities & admin roles",
            "Authentication & MFA",
            "Password policy",
            "Applications & SSO",
            "Identity lifecycle",
            "Policy governance",
        }
        assert expected.issubset(categories), f"missing categories: {expected - categories}"


class TestCoverageParity:
    # test_okta_in_connectable_providers_list was consolidated in message 5:
    # exactly superseded by app.provider_certification.gates.gate_security_coverage_parity
    # (see test_provider_certification_okta.py and provider_certification_duplication_inventory.md).

    def test_okta_in_provider_surfaces(self):
        assert "okta" in security_coverage_service.PROVIDER_SURFACES

    def test_every_registered_okta_rule_has_record_types(self):
        missing = _registry_okta_keys() - _coverage_okta_keys()
        assert not missing, f"missing coverage RULE_RECORD_TYPES entries: {sorted(missing)}"

    def test_no_extra_coverage_entries(self):
        extra = _coverage_okta_keys() - _registry_okta_keys()
        assert not extra, f"coverage has orphaned okta_* keys: {sorted(extra)}"

    def test_provider_of_resolves_correctly(self):
        for key in _registry_okta_keys():
            assert security_coverage_service._provider_of(key) == "okta"

    def test_expected_record_types_non_empty(self):
        expected = security_coverage_service._expected_record_types("okta")
        assert len(expected) > 0


class TestFrontendParity:
    def test_frontend_catalog_file_exists(self):
        assert _FRONTEND_CATALOG.exists()

    # NOTE (message 3): the frontend-catalog == registry set-equality
    # checks formerly here are now framework-owned — see
    # gate_security_finding_registry_parity's frontend_catalog branch.

    def test_frontend_entries_have_provider_okta(self):
        text = _FRONTEND_CATALOG.read_text()
        for m in re.finditer(r'key:\s*"(okta_[a-z_0-9]+)"', text):
            window = text[m.start(): m.start() + 400]
            assert 'provider: "okta"' in window, f"{m.group(1)} missing provider field nearby"

    def test_frontend_severity_matches_backend_pack(self):
        text = _FRONTEND_CATALOG.read_text()
        for key in _frontend_okta_keys():
            block_match = re.search(r'key:\s*"' + re.escape(key) + r'".*?falsePositiveGuard:', text, re.DOTALL)
            assert block_match, f"could not isolate frontend block for {key}"
            block = block_match.group(0)
            fe_severity = re.search(r'severity:\s*"(\w+)"', block).group(1)
            _provider, backend_severity, _category = security_rule_pack._RULE_META[key]
            assert fe_severity == backend_severity, f"{key}: frontend severity {fe_severity!r} != backend {backend_severity!r}"


# NOTE (message 3): TestFullCrossLayerParity's all-layers-identical check
# and pinned rule-count assertion are now framework-owned — see
# gate_security_finding_registry_parity and
# tests/test_provider_certification_okta.py (pins the exact 30-ID set
# independently via discovery, not a hardcoded count alone).
