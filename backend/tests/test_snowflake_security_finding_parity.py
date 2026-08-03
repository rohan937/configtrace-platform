"""Snowflake security-rule registry parity tests (Snowflake message 6 of
8).

Asserts exact Snowflake rule-key parity across every metadata layer:
security rule module, evaluator dispatch, registry, confidence, pack,
coverage record-type mapping, and frontend catalog. Also checks severity/
category consistency, duplicate-key detection, and Finding-vs-Change
severity parity for representative rules.

Snowflake remains internally-registered but NOT publicly connectable
until message 8 — this file explicitly asserts "snowflake" is absent from
security_coverage_service.PROVIDER_SURFACES gating logic only insofar as
that mirrors non-connectable status; RULE_RECORD_TYPES/PROVIDER_SURFACES
themselves are populated ahead of launch (mirroring Okta/Entra's identical
pre-launch pattern at their own message 6).
"""

from __future__ import annotations

import re
from pathlib import Path

from app.services import security_coverage_service, security_rule_pack
from app.services.security_finding_evaluator import _PROVIDER_RULES
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules import snowflake as snowflake_rules

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FRONTEND_CATALOG = _REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"


def _module_rule_keys() -> set[str]:
    src = Path(snowflake_rules.__file__).read_text()
    consts = dict(re.findall(r'(_RULE_\w+)\s*=\s*"(snowflake_[a-z_0-9]+)"', src))
    return set(consts.values())


def _registry_snowflake_keys() -> set[str]:
    return {k for k in KNOWN_RULE_KEYS if k.startswith("snowflake_")}


def _confidence_snowflake_keys() -> set[str]:
    return {k for k in RULE_CONFIDENCE if k.startswith("snowflake_")}


def _pack_snowflake_keys() -> set[str]:
    return {k for k in security_rule_pack._RULE_META if k.startswith("snowflake_")}


def _coverage_snowflake_keys() -> set[str]:
    return {k for k in security_coverage_service.RULE_RECORD_TYPES if k.startswith("snowflake_")}


def _frontend_snowflake_keys() -> set[str]:
    text = _FRONTEND_CATALOG.read_text()
    return set(re.findall(r'key:\s*"(snowflake_[a-z_0-9]+)"', text))


class TestModuleDispatchReachable:
    def test_evaluate_is_callable(self):
        assert callable(snowflake_rules.evaluate)

    def test_snowflake_dispatched_in_evaluator(self):
        assert "snowflake" in _PROVIDER_RULES
        assert snowflake_rules.evaluate in _PROVIDER_RULES["snowflake"]

    def test_module_has_at_least_thirty_rule_keys(self):
        keys = _module_rule_keys()
        assert len(keys) >= 30, f"only {len(keys)} snowflake rule keys found"

    def test_no_duplicate_rule_key_constants(self):
        src = Path(snowflake_rules.__file__).read_text()
        consts = re.findall(r'(_RULE_\w+)\s*=\s*"(snowflake_[a-z_0-9]+)"', src)
        keys = [k for _const, k in consts]
        assert len(keys) == len(set(keys)), "duplicate snowflake_* rule key value found"


# NOTE (Provider Certification Framework message 2): TestRegistryParity's
# module-keys == registry set-equality assertions formerly here are now
# framework-owned — see
# app.provider_certification.gates.gate_security_finding_registry_parity
# and its negative-mutation coverage in
# tests/test_provider_certification_gates.py::TestSecurityFindingRegistryParityGate,
# plus tests/test_provider_certification_snowflake.py which independently
# re-derives and pins the exact 31-ID set. See
# tests/reports/provider_certification_duplication_inventory.md for the
# full consolidation record.


class TestConfidenceParity:
    def test_every_registered_snowflake_rule_has_confidence(self):
        missing = _registry_snowflake_keys() - _confidence_snowflake_keys()
        assert not missing, f"missing confidence entries: {sorted(missing)}"

    def test_no_extra_confidence_entries(self):
        extra = _confidence_snowflake_keys() - _registry_snowflake_keys()
        assert not extra, f"confidence has orphaned snowflake_* keys: {sorted(extra)}"

    def test_confidence_values_are_high_or_medium(self):
        from app.services.security_rule_confidence import HIGH, MEDIUM
        for key in _confidence_snowflake_keys():
            confidence, _guard = RULE_CONFIDENCE[key]
            assert confidence in (HIGH, MEDIUM), f"{key} has non-high/medium confidence {confidence!r}"

    def test_every_confidence_entry_has_a_guard_reason(self):
        for key in _confidence_snowflake_keys():
            _confidence, guard = RULE_CONFIDENCE[key]
            assert isinstance(guard, str) and guard, f"{key} has an empty false_positive_guard"


class TestPackParity:
    def test_every_registered_snowflake_rule_in_pack(self):
        missing = _registry_snowflake_keys() - _pack_snowflake_keys()
        assert not missing, f"missing pack entries: {sorted(missing)}"

    def test_no_extra_pack_entries(self):
        extra = _pack_snowflake_keys() - _registry_snowflake_keys()
        assert not extra, f"pack has orphaned snowflake_* keys: {sorted(extra)}"

    def test_pack_provider_is_snowflake_for_all_entries(self):
        for key in _pack_snowflake_keys():
            provider, _severity, _category = security_rule_pack._RULE_META[key]
            assert provider == "snowflake"

    def test_pack_severity_values_are_valid(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for key in _pack_snowflake_keys():
            _provider, severity, _category = security_rule_pack._RULE_META[key]
            assert severity in valid, f"{key} has invalid severity {severity!r}"

    def test_pack_manifest_self_check_passes(self):
        assert set(security_rule_pack._RULE_META) == set(KNOWN_RULE_KEYS)

    def test_pack_summary_includes_snowflake(self):
        summary = security_rule_pack.pack_summary()
        assert "snowflake" in summary["providers"]
        snowflake_rules_in_summary = [r for r in summary["rules"] if r["provider"] == "snowflake"]
        assert len(snowflake_rules_in_summary) == len(_pack_snowflake_keys())

    def test_pack_categories_cover_expected_buckets(self):
        categories = {c for k in _pack_snowflake_keys() for _p, _s, c in [security_rule_pack._RULE_META[k]]}
        expected = {
            "Privileged users",
            "Privileged service identities",
            "Grant administration & ownership",
            "Privileged/custom roles",
            "PUBLIC access",
            "Future grants",
            "Network policies",
            "Authentication policies",
            "Security integrations",
            "Storage/external access integrations",
            "Identity lifecycle",
        }
        assert expected.issubset(categories), f"missing categories: {expected - categories}"


class TestCoverageParity:
    def test_snowflake_in_providers_list(self):
        # Snowflake has appeared in the internal PROVIDERS list since
        # message 1 (foundation) — coverage reporting can exist
        # internally while the provider remains non-connectable/non-Live
        # until message 8.
        assert "snowflake" in security_coverage_service.PROVIDERS

    def test_snowflake_in_provider_surfaces(self):
        assert "snowflake" in security_coverage_service.PROVIDER_SURFACES

    def test_every_registered_snowflake_rule_has_record_types(self):
        missing = _registry_snowflake_keys() - _coverage_snowflake_keys()
        assert not missing, f"missing coverage RULE_RECORD_TYPES entries: {sorted(missing)}"

    def test_no_extra_coverage_entries(self):
        extra = _coverage_snowflake_keys() - _registry_snowflake_keys()
        assert not extra, f"coverage has orphaned snowflake_* keys: {sorted(extra)}"

    def test_provider_of_resolves_correctly(self):
        for key in _registry_snowflake_keys():
            assert security_coverage_service._provider_of(key) == "snowflake"

    def test_expected_record_types_non_empty(self):
        expected = security_coverage_service._expected_record_types("snowflake")
        assert len(expected) > 0


class TestFrontendParity:
    def test_frontend_catalog_file_exists(self):
        assert _FRONTEND_CATALOG.exists()

    # NOTE (message 2): the frontend-catalog == registry set-equality
    # checks formerly here (test_every_registered_snowflake_rule_in_frontend_catalog,
    # test_no_frontend_only_snowflake_rules) are now framework-owned — see
    # gate_security_finding_registry_parity's frontend_catalog branch.

    def test_frontend_entries_have_provider_snowflake(self):
        text = _FRONTEND_CATALOG.read_text()
        for m in re.finditer(r'key:\s*"(snowflake_[a-z_0-9]+)"', text):
            window = text[m.start(): m.start() + 400]
            assert 'provider: "snowflake"' in window, f"{m.group(1)} missing provider field nearby"

    def test_frontend_severity_matches_backend_pack(self):
        text = _FRONTEND_CATALOG.read_text()
        for key in _frontend_snowflake_keys():
            block_match = re.search(r'key:\s*"' + re.escape(key) + r'".*?falsePositiveGuard:', text, re.DOTALL)
            assert block_match, f"could not isolate frontend block for {key}"
            block = block_match.group(0)
            fe_severity = re.search(r'severity:\s*"(\w+)"', block).group(1)
            _provider, backend_severity, _category = security_rule_pack._RULE_META[key]
            assert fe_severity == backend_severity, f"{key}: frontend severity {fe_severity!r} != backend {backend_severity!r}"

    def test_no_frontend_wording_claims_internet_exposure(self):
        """MANDATORY guard: no snowflake_public_* frontend entry may ever
        claim PUBLIC role access is internet/anonymous exposure. Negation
        phrasing ("never internet exposure") is fine and expected — only
        the forbidden claim phrases themselves are banned."""
        forbidden_phrases = (
            "internet-exposed", "internet exposed", "publicly accessible from the internet",
            "public internet", "anonymous access", "exposed to the internet",
        )
        text = _FRONTEND_CATALOG.read_text()
        for key in _frontend_snowflake_keys():
            if not key.startswith("snowflake_public_"):
                continue
            block_match = re.search(r'key:\s*"' + re.escape(key) + r'".*?falsePositiveGuard:.*?",', text, re.DOTALL)
            assert block_match, f"could not isolate frontend block for {key}"
            block_lower = block_match.group(0).lower()
            for phrase in forbidden_phrases:
                assert phrase not in block_lower, f"{key} frontend copy contains forbidden phrase {phrase!r}"


# NOTE (message 2): TestFullCrossLayerParity's all-layers-identical check
# and pinned rule-count assertion are now framework-owned — see
# gate_security_finding_registry_parity (exact set equality across every
# layer) and tests/test_provider_certification_snowflake.py (pins the
# exact 31-ID set independently via discovery, not a hardcoded count alone).


class TestFindingVsChangeSeverityParity:
    """bad-state Change severity >= static Finding severity, for
    representative high-value rules (message-6 prevention of obvious
    mismatches — message 7 does exhaustive QA)."""

    _RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def _finding_severity(self, rule_key: str) -> str:
        _provider, severity, _category = security_rule_pack._RULE_META[rule_key]
        return severity

    def test_accountadmin_gained_change_at_least_as_severe(self):
        from app.services.risk_rules.snowflake import classify_snowflake_change
        change = {
            "change_type": "modified", "field_path": "has_accountadmin",
            "prev_value": False, "new_value": True,
            "provider_metadata": {"record_type": "snowflake_privileged_user", "user_name": "ALICE"},
        }
        change_severity, _reason = classify_snowflake_change(change)
        finding_severity = self._finding_severity("snowflake_user_accountadmin")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_securityadmin_gained_change_at_least_as_severe(self):
        from app.services.risk_rules.snowflake import classify_snowflake_change
        change = {
            "change_type": "modified", "field_path": "has_securityadmin",
            "prev_value": False, "new_value": True,
            "provider_metadata": {"record_type": "snowflake_privileged_user", "user_name": "BOB"},
        }
        change_severity, _reason = classify_snowflake_change(change)
        finding_severity = self._finding_severity("snowflake_user_securityadmin")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_manage_grants_gained_change_at_least_as_severe(self):
        from app.services.risk_rules.snowflake import classify_snowflake_change
        change = {
            "change_type": "modified", "field_path": "has_manage_grants",
            "prev_value": False, "new_value": True,
            "provider_metadata": {"record_type": "snowflake_privileged_role", "role_name": "CUSTOM_ADMIN"},
        }
        change_severity, _reason = classify_snowflake_change(change)
        finding_severity = self._finding_severity("snowflake_custom_role_manage_grants")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_public_future_ownership_change_at_least_as_severe(self):
        from app.services.risk_rules.snowflake import classify_snowflake_change
        change = {
            "change_type": "modified", "field_path": "future_public_ownership_count",
            "prev_value": 0, "new_value": 1,
            "provider_metadata": {"record_type": "snowflake_public_exposure"},
        }
        change_severity, _reason = classify_snowflake_change(change)
        finding_severity = self._finding_severity("snowflake_public_future_ownership_grant")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_network_anywhere_change_at_least_as_severe(self):
        from app.services.risk_rules.snowflake import classify_snowflake_change
        change = {
            "change_type": "modified", "field_path": "allows_anywhere_ipv4",
            "prev_value": "false", "new_value": "true",
            "provider_metadata": {"record_type": "snowflake_network_policy"},
        }
        change_severity, _reason = classify_snowflake_change(change)
        finding_severity = self._finding_severity("snowflake_network_policy_allows_anywhere")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_future_ownership_grant_change_at_least_as_severe(self):
        from app.services.risk_rules.snowflake import classify_snowflake_change
        change = {
            "change_type": "modified", "field_path": "future_ownership_count",
            "prev_value": 0, "new_value": 1,
            "provider_metadata": {"record_type": "snowflake_privileged_role"},
        }
        change_severity, _reason = classify_snowflake_change(change)
        finding_severity = self._finding_severity("snowflake_future_ownership_grant")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]
