"""Changed-provider impact analysis (message 7).

Given a set of changed repository paths (from a git diff, a CI event,
or a test fixture), determines:
  - which providers are directly affected
  - which global certification dimensions are affected
  - whether full-catalog certification is required
  - a per-path rationale

Pure, read-only, deterministic — string/path classification only. Never
shells out except (optionally) to read a git diff via ``git diff
--name-status``, and even then only with a list-form subprocess call
(never ``shell=True``).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_REPO_ROOT = _BACKEND_ROOT.parent

# ── Provider-specific path patterns ─────────────────────────────────────────
# Each pattern captures the provider_id in group 1 when it matches a
# provider-specific (not shared/global) path.

_PROVIDER_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^backend/app/connectors/(?P<pid>[a-z0-9_]+)_schema\.py$"),
    re.compile(r"^backend/app/connectors/(?P<pid>[a-z0-9_]+)\.py$"),
    re.compile(r"^backend/app/services/risk_rules/(?P<pid>[a-z0-9_]+)\.py$"),
    re.compile(r"^backend/app/services/security_rules/(?P<pid>[a-z0-9_]+)\.py$"),
    re.compile(r"^backend/app/provider_certification/manifests/(?P<pid>[a-z0-9_]+)\.py$"),
    re.compile(r"^backend/tests/reports/provider_certification/(?P<pid>[a-z0-9_]+)\.json$"),
    re.compile(r"^backend/tests/test_(?P<pid>[a-z0-9_]+)_provider_depth_qa\.py$"),
    re.compile(r"^backend/tests/test_(?P<pid>[a-z0-9_]+)_risk_rules\.py$"),
    re.compile(r"^backend/tests/test_(?P<pid>[a-z0-9_]+)_connector.*\.py$"),
    re.compile(r"^backend/tests/test_provider_certification_(?P<pid>[a-z0-9_]+)\.py$"),
    re.compile(r"^frontend/src/components/integrations/(?P<Pid>[A-Za-z0-9]+)IntegrationForm\.tsx$"),
)

# Explicitly-excluded provider_id-shaped values that are actually
# framework-level infrastructure files matched incidentally by a
# provider pattern's regex (e.g. "test_provider_certification_runner.py"
# structurally matches the "test_provider_certification_<pid>.py"
# pattern but "runner" is a framework module, not a provider). Kept as
# an explicit, documented list so these are never mistaken for unknown
# provider-shaped files (which would otherwise wrongly force
# full-catalog certification on every framework-test-only change).
_NON_PROVIDER_IDS: frozenset[str] = frozenset({
    "runner", "reports", "manifest_coverage", "staleness", "cross_manifest",
    "consolidation", "matrix_expansion", "matrix_expansion_message6",
    "migration_allowlist", "seven_provider_summary", "eleven_provider_summary",
    "seventeen_provider_summary", "full_catalog_summary", "cli", "impact",
    "report_drift", "fingerprint", "ci_policy", "performance",
    "framework_self_certification", "summary", "adoption",
})

# ── Shared/global path patterns → certification dimension name ─────────────

_GLOBAL_PATH_DIMENSIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^backend/app/services/diff_service\.py$"), "diff_tracked_fields"),
    (re.compile(r"^backend/app/services/security_rule_registry\.py$"), "security_finding_registry_parity"),
    (re.compile(r"^backend/app/services/security_rule_confidence(_.*)?\.py$"), "security_finding_registry_parity"),
    (re.compile(r"^backend/app/services/security_rule_pack\.py$"), "security_finding_registry_parity"),
    (re.compile(r"^backend/app/services/security_coverage_service\.py$"), "security_coverage_parity"),
    (re.compile(r"^backend/app/services/provider_capability_matrix_service\.py$"), "capability_matrix_parity"),
    (re.compile(r"^backend/app/schemas/integration\.py$"), "credential_schema"),
    (re.compile(r"^backend/app/services/integration_service\.py$"), "creation_validation"),
    (re.compile(r"^backend/app/routers/integrations\.py$"), "creation_validation"),
    (re.compile(r"^backend/app/services/sync_service\.py$"), "sync_dispatch"),
    (re.compile(r"^backend/app/workers/sync_task\.py$"), "worker_dispatch"),
    (re.compile(r"^backend/app/services/security_finding_evaluator\.py$"), "security_finding_registry_parity"),
    (re.compile(r"^backend/app/provider_certification/(models|gates|discovery|cross_manifest|runner|fingerprint|impact|report_drift|cli)\.py$"), "framework_self_certification"),
    (re.compile(r"^backend/app/provider_certification/migration_allowlist\.py$"), "provider_manifest_coverage"),
    (re.compile(r"^backend/app/services/provider_expansion_framework\.py$"), "provider_expansion_freeze"),
    (re.compile(r"^frontend/src/lib/providers\.ts$"), "frontend_provider_parity"),
    (re.compile(r"^frontend/src/lib/securityRuleCatalog\.ts$"), "security_finding_registry_parity"),
)


@dataclass(frozen=True)
class PathClassification:
    path: str
    is_provider_specific: bool
    provider_id: str | None
    is_global: bool
    global_dimension: str | None
    is_unknown_provider_shaped: bool
    rationale: str


@dataclass(frozen=True)
class ImpactResult:
    directly_affected_providers: tuple[str, ...]
    globally_affected_dimensions: tuple[str, ...]
    full_catalog_required: bool
    unknown_provider_files: tuple[str, ...]
    per_path: tuple[PathClassification, ...]

    def as_dict(self) -> dict:
        return {
            "directly_affected_providers": sorted(self.directly_affected_providers),
            "globally_affected_dimensions": sorted(self.globally_affected_dimensions),
            "full_catalog_required": self.full_catalog_required,
            "unknown_provider_files": sorted(self.unknown_provider_files),
            "per_path": [
                {
                    "path": c.path,
                    "is_provider_specific": c.is_provider_specific,
                    "provider_id": c.provider_id,
                    "is_global": c.is_global,
                    "global_dimension": c.global_dimension,
                    "is_unknown_provider_shaped": c.is_unknown_provider_shaped,
                    "rationale": c.rationale,
                }
                for c in sorted(self.per_path, key=lambda c: c.path)
            ],
        }


def _known_provider_ids() -> frozenset[str]:
    from app.provider_certification import runner

    runner._ensure_manifests_loaded()
    return frozenset(runner.known_provider_ids())


def _looks_like_a_connector_file(path: str) -> str | None:
    """A backend/app/connectors/<name>.py or <name>_schema.py file whose
    <name> does NOT match any known provider and isn't obviously a
    shared base/exception module — a candidate 'unknown provider-shaped
    file' per the message-7 spec (item 15)."""
    m = re.match(r"^backend/app/connectors/(?P<name>[a-z0-9_]+?)(?:_schema)?\.py$", path)
    if not m:
        return None
    name = m.group("name")
    if name in ("base", "exceptions", "__init__"):
        return None
    return name


def classify_path(path: str) -> PathClassification:
    """Classify a single changed repository path."""
    known = _known_provider_ids()

    for pattern in _PROVIDER_PATH_PATTERNS:
        m = pattern.match(path)
        if m:
            groupdict = m.groupdict()
            raw_pid = groupdict.get("pid")
            pascal_pid = groupdict.get("Pid")
            if pascal_pid is not None:
                # Frontend form pattern captures PascalCase (e.g.
                # "GoogleCloud", "PagerDuty"). Providers don't follow a
                # single, invertible PascalCase<->snake_case convention
                # (PagerDuty -> "pagerduty", not "pager_duty"; GoogleCloud
                # -> "google_cloud", WITH an underscore) — so match by
                # comparing case-insensitively with underscores/spaces
                # stripped from both sides against every KNOWN provider_id,
                # rather than guessing a single splitting heuristic.
                target = pascal_pid.lower()
                match = next((p for p in known if p.replace("_", "") == target), None)
                pid = match if match is not None else target
            elif raw_pid is not None:
                pid = raw_pid
            else:
                continue
            if pid in _NON_PROVIDER_IDS:
                break
            if pid in known:
                return PathClassification(
                    path=path, is_provider_specific=True, provider_id=pid,
                    is_global=False, global_dimension=None, is_unknown_provider_shaped=False,
                    rationale=f"matches provider-specific pattern for known provider {pid!r}",
                )
            return PathClassification(
                path=path, is_provider_specific=True, provider_id=pid,
                is_global=False, global_dimension=None, is_unknown_provider_shaped=True,
                rationale=f"matches provider-specific pattern but {pid!r} has no registered manifest — treated conservatively",
            )

    for pattern, dimension in _GLOBAL_PATH_DIMENSIONS:
        if pattern.match(path):
            return PathClassification(
                path=path, is_provider_specific=False, provider_id=None,
                is_global=True, global_dimension=dimension, is_unknown_provider_shaped=False,
                rationale=f"matches shared/global path affecting the {dimension!r} certification dimension",
            )

    unknown_connector = _looks_like_a_connector_file(path)
    if unknown_connector is not None and unknown_connector not in known:
        return PathClassification(
            path=path, is_provider_specific=False, provider_id=None,
            is_global=True, global_dimension="provider_manifest_coverage", is_unknown_provider_shaped=True,
            rationale=f"connector-shaped file for unregistered provider {unknown_connector!r} — cannot rule out a new/renamed provider",
        )

    return PathClassification(
        path=path, is_provider_specific=False, provider_id=None,
        is_global=False, global_dimension=None, is_unknown_provider_shaped=False,
        rationale="does not match any known provider-specific or shared/global certification-relevant pattern",
    )


def analyze_impact(changed_paths: list[str]) -> ImpactResult:
    """Analyze a list of changed repository paths (already
    old-path/new-path resolved for renames — callers should include
    BOTH the old and new path of a rename)."""
    classifications = tuple(classify_path(p) for p in changed_paths)

    providers: set[str] = set()
    dimensions: set[str] = set()
    unknown_files: set[str] = set()
    full_catalog = False

    for c in classifications:
        if c.is_provider_specific and c.provider_id and not c.is_unknown_provider_shaped:
            providers.add(c.provider_id)
        if c.is_unknown_provider_shaped:
            unknown_files.add(c.path)
            full_catalog = True
        if c.is_global:
            dimensions.add(c.global_dimension or "unknown")
            full_catalog = True

    return ImpactResult(
        directly_affected_providers=tuple(sorted(providers)),
        globally_affected_dimensions=tuple(sorted(dimensions)),
        full_catalog_required=full_catalog,
        unknown_provider_files=tuple(sorted(unknown_files)),
        per_path=classifications,
    )


# ── Git integration ──────────────────────────────────────────────────────────


class GitDiffError(RuntimeError):
    pass


def get_changed_paths(base: str, head: str, repo_root: Path | None = None) -> list[str]:
    """Run ``git diff --name-status <base>...<head>`` locally (no
    network) and return the flat list of changed paths, including BOTH
    sides of a rename. Never uses shell=True. Raises GitDiffError on
    any failure (missing merge base, shallow clone, invalid SHA) so
    callers can fall back to full-catalog certification rather than
    silently returning an empty (falsely "nothing changed") result."""
    root = repo_root or _REPO_ROOT
    try:
        result = subprocess.run(
            ["git", "diff", "--name-status", f"{base}...{head}"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitDiffError(f"failed to invoke git diff: {exc}") from exc

    if result.returncode != 0:
        raise GitDiffError(f"git diff failed (exit {result.returncode}): {result.stderr.strip()}")

    return parse_diff_name_status(result.stdout)


def parse_diff_name_status(output: str) -> list[str]:
    """Parse ``git diff --name-status`` output (safe, no shell
    involved) into a flat list of paths. Renames (``R###\\told\\tnew``)
    contribute BOTH old and new paths; adds/deletes/modifies contribute
    one path each."""
    paths: list[str] = []
    for line in output.splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue
        parts = line.split("\t")
        if not parts:
            continue
        status = parts[0]
        if status.startswith("R") or status.startswith("C"):
            # Rename/copy: status\told_path\tnew_path
            if len(parts) >= 3:
                paths.append(parts[1])
                paths.append(parts[2])
            elif len(parts) == 2:
                paths.append(parts[1])
        else:
            if len(parts) >= 2:
                paths.append(parts[1])
    return paths


def analyze_impact_from_git(base: str, head: str, repo_root: Path | None = None) -> ImpactResult:
    """Convenience wrapper: git diff -> analyze_impact(). On ANY git
    failure (missing merge base, shallow clone, unknown SHA), returns a
    conservative full-catalog-required result rather than raising —
    "uncertain impact forces full certification" (message-7 policy),
    never a silent skip."""
    try:
        paths = get_changed_paths(base, head, repo_root=repo_root)
    except GitDiffError:
        return ImpactResult(
            directly_affected_providers=(),
            globally_affected_dimensions=("git_diff_unavailable",),
            full_catalog_required=True,
            unknown_provider_files=(),
            per_path=(),
        )
    if not paths:
        # An empty diff genuinely means nothing changed — not the same
        # as "we don't know" — full certification is NOT forced here.
        return ImpactResult(
            directly_affected_providers=(),
            globally_affected_dimensions=(),
            full_catalog_required=False,
            unknown_provider_files=(),
            per_path=(),
        )
    return analyze_impact(paths)
