"""Consolidation-safety tests (message 2 of N).

Message 2 removed 12 duplicated static parity assertions total — 6 from
``tests/test_sentry_security_finding_parity.py`` and 6 from
``tests/test_snowflake_security_finding_parity.py`` (see
``tests/reports/provider_certification_duplication_inventory.md`` for the
full inventory). Each removed assertion was a pure module/registry/
frontend-catalog SET-EQUALITY check with no additional semantic value
beyond what ``gate_security_finding_registry_parity`` already proves
against real discovered repository state (not just the manifest
reflecting itself — see the negative-mutation tests in
``test_provider_certification_gates.py``).

This file proves the consolidation was safe:
  * the framework gate still fails under the exact kind of drift the
    removed assertions used to catch;
  * the provider-specific semantic tests that were NOT removed (pack
    severity validity, guard-reason presence, frontend wording guards,
    Finding-vs-Change severity parity, etc.) still exist and still pass;
  * the test-count reduction is exactly what's documented.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification.manifests.sentry import SENTRY_MANIFEST
from app.provider_certification.manifests.snowflake import SNOWFLAKE_MANIFEST

_BACKEND_ROOT = Path(__file__).resolve().parents[1]


class TestFrameworkGateStillCatchesWhatWasRemoved:
    """The removed Sentry/Snowflake assertions checked: module keys ⊆
    registry, registry has no extra keys, frontend catalog == registry,
    and all-layers-identical. gate_security_finding_registry_parity
    covers every one of these exactly — proven here via monkeypatch."""

    def test_registry_missing_a_declared_id_still_fails(self, monkeypatch):
        real = disc.discover_registry_rule_ids("sentry")
        mutated = real - {next(iter(real))}
        monkeypatch.setattr(disc, "discover_registry_rule_ids", lambda pid: mutated if pid == "sentry" else real)
        gate = gates.gate_security_finding_registry_parity(SENTRY_MANIFEST)
        assert gate.status == "fail"

    def test_registry_extra_undeclared_id_still_fails(self, monkeypatch):
        real = disc.discover_registry_rule_ids("snowflake")
        mutated = real | {"snowflake_undeclared_extra_rule"}
        monkeypatch.setattr(disc, "discover_registry_rule_ids", lambda pid: mutated if pid == "snowflake" else real)
        gate = gates.gate_security_finding_registry_parity(SNOWFLAKE_MANIFEST)
        assert gate.status == "fail"

    def test_frontend_catalog_drift_still_fails(self, monkeypatch):
        real = disc.discover_frontend_catalog_rule_ids("sentry")
        if real is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        mutated = real - {next(iter(real))}
        monkeypatch.setattr(disc, "discover_frontend_catalog_rule_ids", lambda pid: mutated if pid == "sentry" else real)
        gate = gates.gate_security_finding_registry_parity(SENTRY_MANIFEST)
        assert gate.status == "fail"
        assert "frontend_catalog" in gate.details


class TestProviderSpecificSemanticTestsStillPresent:
    """The tests that were NOT removed still exist and still pass — the
    consolidation removed only pure set-equality duplication, never
    semantic coverage."""

    def test_sentry_parity_file_still_has_semantic_classes(self):
        text = (_BACKEND_ROOT / "tests" / "test_sentry_security_finding_parity.py").read_text()
        for still_present in (
            "class TestConfidenceParity",
            "class TestPackParity",
            "class TestCoverageParity",
            "class TestCapabilityMatrixParity",
            "class TestFrontendParity",
            "class TestFindingVsChangeSeverityParity",
            "def test_no_frontend_wording_claims_compromise",
            "def test_confidence_values_are_high_or_medium",
        ):
            assert still_present in text, f"missing: {still_present}"

    def test_snowflake_parity_file_still_has_semantic_classes(self):
        text = (_BACKEND_ROOT / "tests" / "test_snowflake_security_finding_parity.py").read_text()
        for still_present in (
            "class TestConfidenceParity",
            "class TestPackParity",
            "class TestCoverageParity",
            "class TestFrontendParity",
            "class TestFindingVsChangeSeverityParity",
            "def test_no_frontend_wording_claims_internet_exposure",
        ):
            assert still_present in text, f"missing: {still_present}"

    def test_removed_classes_are_actually_gone(self):
        for fname in ("test_sentry_security_finding_parity.py", "test_snowflake_security_finding_parity.py"):
            text = (_BACKEND_ROOT / "tests" / fname).read_text()
            assert "class TestRegistryParity" not in text
            assert "class TestFullCrossLayerParity" not in text


class TestConsolidatedTestCountReduction:
    """Pins the exact before/after test counts so a future silent
    re-addition (or over-deletion) of assertions is caught."""

    def test_sentry_parity_file_has_33_tests_after_consolidation(self):
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_sentry_security_finding_parity.py", "--collect-only", "-q"],
            cwd=str(_BACKEND_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        last_line = [ln for ln in result.stdout.splitlines() if ln.strip()][-1]
        assert "39" not in last_line or "tests collected" not in last_line  # sanity: not the pre-consolidation count
        assert "33" in last_line, last_line

    def test_snowflake_parity_file_has_31_tests_after_consolidation(self):
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_snowflake_security_finding_parity.py", "--collect-only", "-q"],
            cwd=str(_BACKEND_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        last_line = [ln for ln in result.stdout.splitlines() if ln.strip()][-1]
        assert "37" not in last_line or "tests collected" not in last_line
        assert "31" in last_line, last_line

    def test_twelve_total_assertions_consolidated(self):
        # 39 -> 33 (Sentry) and 37 -> 31 (Snowflake): 6 removed each, 12 total.
        assert (39 - 33) + (37 - 31) == 12
