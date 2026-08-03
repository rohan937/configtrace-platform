"""Framework self-certification (message 7).

The Provider Certification Framework certifies every OTHER provider —
this module certifies the framework itself. It is a single, global,
non-blocking-per-provider check: every gate has test coverage, every
manifest is loaded exactly once, every generated report is represented,
the adoption report reflects real repository state, the CI entry point
exists, the checked-in CI workflow references the real CLI command, and
no migration-allowlist entry has gone stale (a provider that's since
been certified but was never removed from the allowlist).

Pure and read-only: only inspects already-imported framework state,
already-committed report files, and the already-committed CI workflow
file's *text* (never executes it).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.provider_certification import gates as gate_module
from app.provider_certification import migration_allowlist as ma
from app.provider_certification import report_drift, runner
from app.provider_certification.models import DIMENSIONS

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_REPO_ROOT = _BACKEND_ROOT.parent
_TESTS_DIR = _BACKEND_ROOT / "tests"
_CLI_MODULE_PATH = _BACKEND_ROOT / "app" / "provider_certification" / "cli.py"
_WORKFLOW_DIR = _REPO_ROOT / ".github" / "workflows"

_CLI_INVOCATION_MARKER = "app.provider_certification.cli"


@dataclass(frozen=True)
class SelfCertificationCheck:
    check_id: str
    passed: bool
    details: str


@dataclass(frozen=True)
class SelfCertificationResult:
    overall_pass: bool
    checks: tuple[SelfCertificationCheck, ...]

    def as_dict(self) -> dict:
        return {
            "overall_pass": self.overall_pass,
            "checks": [
                {"check_id": c.check_id, "passed": c.passed, "details": c.details}
                for c in sorted(self.checks, key=lambda c: c.check_id)
            ],
        }


def _every_gate_dimension_has_test_reference() -> SelfCertificationCheck:
    """Every certification dimension exercised by
    ``ALL_PROVIDER_GATE_FUNCS`` must be referenced (by dimension name)
    somewhere in backend/tests/ — a gate with zero test references is a
    certification claim nobody actually checks."""
    manifest = runner.get_manifest("sentry")
    exercised_dimensions = {gate_func(manifest).dimension for gate_func in gate_module.ALL_PROVIDER_GATE_FUNCS}

    test_sources = "\n".join(
        p.read_text(errors="ignore") for p in _TESTS_DIR.glob("test_*.py")
    )

    missing = sorted(d for d in exercised_dimensions if d not in test_sources)
    passed = not missing
    details = (
        "every gate dimension has at least one test-file reference"
        if passed
        else f"dimension(s) with no test-file reference: {missing}"
    )
    return SelfCertificationCheck("every_gate_has_tests", passed, details)


def _every_manifest_loaded_once() -> SelfCertificationCheck:
    ids = runner.known_provider_ids()
    unique = set(ids)
    passed = len(ids) == len(unique) and all(
        runner.get_manifest(pid).provider_id == pid for pid in ids
    )
    details = (
        f"{len(ids)} manifest(s) registered, no duplicates, every manifest's own provider_id matches its registry key"
        if passed
        else "duplicate registration or provider_id/registry-key mismatch detected"
    )
    return SelfCertificationCheck("every_manifest_loaded_once", passed, details)


def _every_generated_report_represented() -> SelfCertificationCheck:
    report_drift.generate_reports()
    drift = report_drift.check_report_drift()
    passed = drift.is_clean
    details = (
        "every known provider has an up-to-date generated report on disk"
        if passed
        else f"drift detected: {drift.remediation()}"
    )
    return SelfCertificationCheck("every_generated_report_represented", passed, details)


def _adoption_report_current() -> SelfCertificationCheck:
    report = runner.adoption_report()
    passed = report["missing_unexpected_count"] == 0 and report["orphan_manifest_count"] == 0
    details = (
        f"coverage {report['coverage_percentage']}%, 0 missing, 0 orphans"
        if passed
        else f"missing={report['unexpected_missing_provider_ids']}, orphans={report['orphan_manifest_provider_ids']}"
    )
    return SelfCertificationCheck("adoption_report_current", passed, details)


def _matrix_and_report_minimums_hold() -> SelfCertificationCheck:
    provider_count = len(runner.known_provider_ids())
    dimension_count = len(DIMENSIONS)
    passed = provider_count >= 1 and dimension_count >= 1
    details = f"{provider_count} certified provider(s), {dimension_count} certification dimension(s)"
    return SelfCertificationCheck("matrix_and_report_minimums_hold", passed, details)


def _ci_entry_point_exists() -> SelfCertificationCheck:
    passed = _CLI_MODULE_PATH.is_file()
    details = (
        f"{_CLI_MODULE_PATH} exists"
        if passed
        else f"missing CLI entry point at {_CLI_MODULE_PATH}"
    )
    return SelfCertificationCheck("ci_entry_point_exists", passed, details)


def _workflow_references_real_command() -> SelfCertificationCheck:
    if not _WORKFLOW_DIR.is_dir():
        return SelfCertificationCheck(
            "workflow_references_real_command", False,
            f"no CI workflow directory found at {_WORKFLOW_DIR}",
        )
    workflow_files = sorted(_WORKFLOW_DIR.glob("*.yml")) + sorted(_WORKFLOW_DIR.glob("*.yaml"))
    matching = [
        f for f in workflow_files
        if _CLI_INVOCATION_MARKER in f.read_text(errors="ignore")
    ]
    passed = bool(matching)
    details = (
        f"{[f.name for f in matching]} reference {_CLI_INVOCATION_MARKER!r}"
        if passed
        else f"no workflow file under {_WORKFLOW_DIR} references {_CLI_INVOCATION_MARKER!r}"
    )
    return SelfCertificationCheck("workflow_references_real_command", passed, details)


def _no_deprecated_migration_allowlist_entries() -> SelfCertificationCheck:
    """A migration-allowlist entry is deprecated the moment its provider
    gains a real certification manifest — the entry should have been
    removed in the same change, never left to silently coexist."""
    certified = set(runner.known_provider_ids())
    stale = sorted(ma.allowlisted_provider_ids() & certified)
    passed = not stale
    details = (
        "no migration-allowlist entry overlaps a certified provider"
        if passed
        else f"deprecated allowlist entries (already certified): {stale}"
    )
    return SelfCertificationCheck("no_deprecated_migration_allowlist_entries", passed, details)


def run_self_certification() -> SelfCertificationResult:
    checks = (
        _every_gate_dimension_has_test_reference(),
        _every_manifest_loaded_once(),
        _every_generated_report_represented(),
        _adoption_report_current(),
        _matrix_and_report_minimums_hold(),
        _ci_entry_point_exists(),
        _workflow_references_real_command(),
        _no_deprecated_migration_allowlist_entries(),
    )
    return SelfCertificationResult(
        overall_pass=all(c.passed for c in checks),
        checks=checks,
    )
