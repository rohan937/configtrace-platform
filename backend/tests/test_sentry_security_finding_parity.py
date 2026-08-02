"""Sentry security-rule registry parity tests (Sentry message 6 of 8).

Asserts exact Sentry rule-key parity across every metadata layer: security
rule module, evaluator dispatch, registry, confidence, pack, coverage
record-type mapping, and frontend catalog. Also checks severity/category
consistency, duplicate-key detection, and Finding-vs-Change severity parity
for representative rules.

Sentry remains internally-registered but NOT publicly connectable — this
file asserts "sentry" is present in security_coverage_service.PROVIDERS/
PROVIDER_SURFACES (internal coverage reporting can exist ahead of public
launch, mirroring Okta/Entra/Snowflake's identical pre-launch pattern at
their own message 6) while NOT asserting anything about public
connectability (that remains owned by providers.ts/PROVIDER_IDS, untouched
this message).
"""

from __future__ import annotations

import re
from pathlib import Path

from app.services import security_coverage_service, security_rule_pack
from app.services.security_finding_evaluator import _PROVIDER_RULES
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules import sentry as sentry_rules

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FRONTEND_CATALOG = _REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"


def _module_rule_keys() -> set[str]:
    src = Path(sentry_rules.__file__).read_text()
    consts = dict(re.findall(r'(_RULE_\w+)\s*=\s*"(sentry_[a-z_0-9]+)"', src))
    return set(consts.values())


def _registry_sentry_keys() -> set[str]:
    return {k for k in KNOWN_RULE_KEYS if k.startswith("sentry_")}


def _confidence_sentry_keys() -> set[str]:
    return {k for k in RULE_CONFIDENCE if k.startswith("sentry_")}


def _pack_sentry_keys() -> set[str]:
    return {k for k in security_rule_pack._RULE_META if k.startswith("sentry_")}


def _coverage_sentry_keys() -> set[str]:
    return {k for k in security_coverage_service.RULE_RECORD_TYPES if k.startswith("sentry_")}


def _frontend_sentry_keys() -> set[str]:
    text = _FRONTEND_CATALOG.read_text()
    return set(re.findall(r'key:\s*"(sentry_[a-z_0-9]+)"', text))


class TestModuleDispatchReachable:
    def test_evaluate_is_callable(self):
        assert callable(sentry_rules.evaluate)

    def test_sentry_dispatched_in_evaluator(self):
        assert "sentry" in _PROVIDER_RULES
        assert sentry_rules.evaluate in _PROVIDER_RULES["sentry"]

    def test_module_has_at_least_fifteen_rule_keys(self):
        keys = _module_rule_keys()
        assert len(keys) >= 15, f"only {len(keys)} sentry rule keys found"

    def test_no_duplicate_rule_key_constants(self):
        src = Path(sentry_rules.__file__).read_text()
        consts = re.findall(r'(_RULE_\w+)\s*=\s*"(sentry_[a-z_0-9]+)"', src)
        keys = [k for _const, k in consts]
        assert len(keys) == len(set(keys)), "duplicate sentry_* rule key value found"


class TestRegistryParity:
    def test_module_keys_subset_of_registry(self):
        missing = _module_rule_keys() - _registry_sentry_keys()
        assert not missing, f"rule keys missing from security_rule_registry: {sorted(missing)}"

    def test_registry_has_no_extra_sentry_keys(self):
        extra = _registry_sentry_keys() - _module_rule_keys()
        assert not extra, f"registry has sentry_* keys with no matching rule: {sorted(extra)}"


class TestConfidenceParity:
    def test_every_registered_sentry_rule_has_confidence(self):
        missing = _registry_sentry_keys() - _confidence_sentry_keys()
        assert not missing, f"missing confidence entries: {sorted(missing)}"

    def test_no_extra_confidence_entries(self):
        extra = _confidence_sentry_keys() - _registry_sentry_keys()
        assert not extra, f"confidence has orphaned sentry_* keys: {sorted(extra)}"

    def test_confidence_values_are_high_or_medium(self):
        from app.services.security_rule_confidence import HIGH, MEDIUM
        for key in _confidence_sentry_keys():
            confidence, _guard = RULE_CONFIDENCE[key]
            assert confidence in (HIGH, MEDIUM), f"{key} has non-high/medium confidence {confidence!r}"

    def test_every_confidence_entry_has_a_guard_reason(self):
        for key in _confidence_sentry_keys():
            _confidence, guard = RULE_CONFIDENCE[key]
            assert isinstance(guard, str) and guard, f"{key} has an empty false_positive_guard"


class TestPackParity:
    def test_every_registered_sentry_rule_in_pack(self):
        missing = _registry_sentry_keys() - _pack_sentry_keys()
        assert not missing, f"missing pack entries: {sorted(missing)}"

    def test_no_extra_pack_entries(self):
        extra = _pack_sentry_keys() - _registry_sentry_keys()
        assert not extra, f"pack has orphaned sentry_* keys: {sorted(extra)}"

    def test_pack_provider_is_sentry_for_all_entries(self):
        for key in _pack_sentry_keys():
            provider, _severity, _category = security_rule_pack._RULE_META[key]
            assert provider == "sentry"

    def test_pack_severity_values_are_valid(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for key in _pack_sentry_keys():
            _provider, severity, _category = security_rule_pack._RULE_META[key]
            assert severity in valid, f"{key} has invalid severity {severity!r}"

    def test_pack_manifest_self_check_passes(self):
        assert set(security_rule_pack._RULE_META) == set(KNOWN_RULE_KEYS)

    def test_pack_summary_includes_sentry(self):
        summary = security_rule_pack.pack_summary()
        assert "sentry" in summary["providers"]
        sentry_rules_in_summary = [r for r in summary["rules"] if r["provider"] == "sentry"]
        assert len(sentry_rules_in_summary) == len(_pack_sentry_keys())

    def test_pack_categories_cover_expected_buckets(self):
        categories = {c for k in _pack_sentry_keys() for _p, _s, c in [security_rule_pack._RULE_META[k]]}
        expected = {
            "Privileged organization members",
            "Pending privileged invitations",
            "Privileged teams & project access",
            "Alert coverage",
            "Alert notification routing",
            "Ownership routing",
            "Configuration integrity",
        }
        assert expected.issubset(categories), f"missing categories: {expected - categories}"


class TestCoverageParity:
    def test_sentry_in_providers_list(self):
        # Sentry has appeared in the internal PROVIDERS list since message
        # 1 (foundation) — coverage reporting can exist internally while
        # the provider remains non-connectable/non-Live.
        assert "sentry" in security_coverage_service.PROVIDERS

    def test_sentry_in_provider_surfaces(self):
        assert "sentry" in security_coverage_service.PROVIDER_SURFACES

    def test_every_registered_sentry_rule_has_record_types(self):
        missing = _registry_sentry_keys() - _coverage_sentry_keys()
        assert not missing, f"missing coverage RULE_RECORD_TYPES entries: {sorted(missing)}"

    def test_no_extra_coverage_entries(self):
        extra = _coverage_sentry_keys() - _registry_sentry_keys()
        assert not extra, f"coverage has orphaned sentry_* keys: {sorted(extra)}"

    def test_provider_of_resolves_correctly(self):
        for key in _registry_sentry_keys():
            assert security_coverage_service._provider_of(key) == "sentry"

    def test_expected_record_types_non_empty(self):
        expected = security_coverage_service._expected_record_types("sentry")
        assert len(expected) > 0


class TestCapabilityMatrixParity:
    def test_sentry_security_rules_flag_is_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("sentry")
        assert cap is not None
        assert cap.security.security_rules is True

    def test_sentry_maturity_stays_planned(self):
        from app.services.provider_capability_matrix_service import get_provider_capability

        cap = get_provider_capability("sentry")
        assert cap.maturity == "planned"

    def test_sentry_still_absent_from_full_capabilities_list(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES,
            PROVIDER_CAPABILITIES_PARTIAL,
        )

        assert "sentry" in {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        assert "sentry" not in {p.provider for p in PROVIDER_CAPABILITIES}


class TestFrontendParity:
    def test_frontend_catalog_file_exists(self):
        assert _FRONTEND_CATALOG.exists()

    def test_every_registered_sentry_rule_in_frontend_catalog(self):
        missing = _registry_sentry_keys() - _frontend_sentry_keys()
        assert not missing, f"missing frontend catalog entries: {sorted(missing)}"

    def test_no_frontend_only_sentry_rules(self):
        extra = _frontend_sentry_keys() - _registry_sentry_keys()
        assert not extra, f"frontend catalog has sentry_* keys with no backend rule: {sorted(extra)}"

    def test_frontend_entries_have_provider_sentry(self):
        text = _FRONTEND_CATALOG.read_text()
        for m in re.finditer(r'key:\s*"(sentry_[a-z_0-9]+)"', text):
            window = text[m.start(): m.start() + 400]
            assert 'provider: "sentry"' in window, f"{m.group(1)} missing provider field nearby"

    def test_frontend_severity_matches_backend_pack(self):
        text = _FRONTEND_CATALOG.read_text()
        for key in _frontend_sentry_keys():
            block_match = re.search(r'key:\s*"' + re.escape(key) + r'".*?falsePositiveGuard:', text, re.DOTALL)
            assert block_match, f"could not isolate frontend block for {key}"
            block = block_match.group(0)
            fe_severity = re.search(r'severity:\s*"(\w+)"', block).group(1)
            _provider, backend_severity, _category = security_rule_pack._RULE_META[key]
            assert fe_severity == backend_severity, f"{key}: frontend severity {fe_severity!r} != backend {backend_severity!r}"

    def test_frontend_sentry_not_in_connectable_provider_ids(self):
        providers_ts = _REPO_ROOT / "frontend" / "src" / "lib" / "providers.ts"
        text = providers_ts.read_text()
        conn_match = re.search(r"CONNECTABLE_PROVIDER_IDS[^=]*=\s*\[(.*?)\];", text, re.DOTALL)
        assert conn_match, "could not locate CONNECTABLE_PROVIDER_IDS array"
        assert '"sentry"' not in conn_match.group(1)

    def test_no_frontend_wording_claims_compromise(self):
        """MANDATORY guard: no sentry_* frontend entry may claim a
        confirmed compromise/breach/attacker action — these are
        configuration-posture findings only."""
        forbidden_phrases = (
            "compromised", "breached", "attacker", "exfiltrat", "account takeover",
            "unauthorized access", "hacked",
        )
        text = _FRONTEND_CATALOG.read_text()
        for key in _frontend_sentry_keys():
            block_match = re.search(r'key:\s*"' + re.escape(key) + r'".*?falsePositiveGuard:.*?",', text, re.DOTALL)
            assert block_match, f"could not isolate frontend block for {key}"
            block_lower = block_match.group(0).lower()
            for phrase in forbidden_phrases:
                assert phrase not in block_lower, f"{key} frontend copy contains forbidden phrase {phrase!r}"


class TestFullCrossLayerParity:
    def test_all_layers_have_identical_sentry_key_sets(self):
        layers = {
            "module": _module_rule_keys(),
            "registry": _registry_sentry_keys(),
            "confidence": _confidence_sentry_keys(),
            "pack": _pack_sentry_keys(),
            "coverage": _coverage_sentry_keys(),
            "frontend": _frontend_sentry_keys(),
        }
        reference = layers["registry"]
        for name, keys in layers.items():
            assert keys == reference, (
                f"{name} layer diverges from registry — "
                f"missing={sorted(reference - keys)} extra={sorted(keys - reference)}"
            )

    def test_expected_rule_count_is_20(self):
        # Pinned count — update deliberately if the taxonomy changes; a
        # silent drift here should fail loudly rather than pass unnoticed.
        assert len(_registry_sentry_keys()) == 20


class TestFindingVsChangeSeverityParity:
    """bad-state Change severity >= static Finding severity, for
    representative high-value rules (message-6 prevention of obvious
    mismatches — message 7 does exhaustive QA)."""

    _RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def _finding_severity(self, rule_key: str) -> str:
        _provider, severity, _category = security_rule_pack._RULE_META[rule_key]
        return severity

    def test_member_promoted_to_owner_change_is_a_documented_exception(self):
        """Message 5's own severity guide fixes 'member->owner' at High
        (never Critical) for the Change-classification path — the static
        Finding for an active Owner is Critical (reflecting the role's
        absolute authority as CURRENT STATE), while the Change reflects
        the transition event itself. This divergence was fixed in message
        5's worked severity examples before message 6 existed, so it is a
        pre-existing, explicitly documented exception to the message-6
        Finding-vs-Change >= rule, not a new inconsistency introduced by
        this message."""
        from app.services.risk_rules.sentry import classify_sentry_change
        change = {
            "change_type": "modified", "field_path": "privilege_tier",
            "prev_value": "low", "new_value": "critical",
            "provider_metadata": {"record_type": "sentry_privileged_member", "member_id": "m1", "org_role_category": "owner"},
        }
        change_severity, _reason = classify_sentry_change(change)
        assert change_severity == "high"
        finding_severity = self._finding_severity("sentry_active_organization_owner")
        assert finding_severity == "critical"

    def test_org_wide_access_gained_change_at_least_as_severe(self):
        from app.services.risk_rules.sentry import classify_sentry_change
        change = {
            "change_type": "modified", "field_path": "organization_wide_project_access",
            "prev_value": False, "new_value": True,
            "provider_metadata": {"record_type": "sentry_privileged_member", "member_id": "m1"},
        }
        change_severity, _reason = classify_sentry_change(change)
        finding_severity = self._finding_severity("sentry_active_organization_manager")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_routing_target_unresolved_on_enabled_rule_change_at_least_as_severe(self):
        from app.services.risk_rules.sentry import classify_sentry_change
        change = {
            "change_type": "modified", "field_path": "target_resolved",
            "prev_value": True, "new_value": False,
            "provider_metadata": {"record_type": "sentry_routing_context", "context_enabled": True},
        }
        change_severity, _reason = classify_sentry_change(change)
        finding_severity = self._finding_severity("sentry_alert_targets_missing_member")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]

    def test_integration_disabled_while_targeted_change_at_least_as_severe(self):
        from app.services.risk_rules.sentry import classify_sentry_change
        change = {
            "change_type": "modified", "field_path": "integration_status_category",
            "prev_value": "active", "new_value": "disabled",
            "provider_metadata": {"record_type": "sentry_routing_context", "context_enabled": True},
        }
        change_severity, _reason = classify_sentry_change(change)
        finding_severity = self._finding_severity("sentry_alert_references_disabled_integration")
        assert self._RANK[change_severity] >= self._RANK[finding_severity]
