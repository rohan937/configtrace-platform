"""CI enforcement policy (message 7).

Pure decision logic the CI workflow uses to decide (a) whether a diff
needs focused or full-catalog certification, and (b) whether a CI run's
combined results block a merge. Contains no I/O of its own — it only
combines the outputs of ``impact.py`` / ``report_drift.py`` / the CLI's
certification results into a single, deterministic decision, so the
actual branching logic is testable in Python rather than living only as
untestable shell script inside a workflow YAML file.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.provider_certification.impact import ImpactResult

_MAIN_REFS = frozenset({"main", "refs/heads/main"})


@dataclass(frozen=True)
class CIStrategy:
    run_full_catalog: bool
    focused_provider_ids: tuple[str, ...]
    reason: str

    def as_dict(self) -> dict:
        return {
            "run_full_catalog": self.run_full_catalog,
            "focused_provider_ids": sorted(self.focused_provider_ids),
            "reason": self.reason,
        }


def decide_strategy(
    *, event_name: str, ref_name: str, impact: ImpactResult, merge_base_available: bool,
) -> CIStrategy:
    """Decide what certification a CI run should perform for one event.

    Conservative by construction: any condition under which affected
    providers cannot be safely narrowed (push to main, no merge base,
    impact analysis itself flagging full-catalog) wins over a narrower
    focused-certification result — certification is never silently
    skipped due to uncertainty.
    """
    if event_name == "push" and ref_name in _MAIN_REFS:
        return CIStrategy(
            run_full_catalog=True, focused_provider_ids=(),
            reason="push to main branch always runs full-catalog certification",
        )
    if not merge_base_available:
        return CIStrategy(
            run_full_catalog=True, focused_provider_ids=(),
            reason="no merge base available (shallow clone or unrelated histories) — "
                   "falling back to full-catalog certification",
        )
    if impact.full_catalog_required:
        signal = ", ".join(impact.globally_affected_dimensions) or ", ".join(impact.unknown_provider_files) or "shared/global change"
        return CIStrategy(
            run_full_catalog=True, focused_provider_ids=(),
            reason=f"impact analysis requires full-catalog certification: {signal}",
        )
    if not impact.directly_affected_providers:
        return CIStrategy(
            run_full_catalog=False, focused_provider_ids=(),
            reason="no provider-affecting or shared/global paths changed — "
                   "certification not required for this diff",
        )
    return CIStrategy(
        run_full_catalog=False, focused_provider_ids=impact.directly_affected_providers,
        reason="focused certification for directly affected providers",
    )


@dataclass(frozen=True)
class CIGateResult:
    blocks_merge: bool
    reasons: tuple[str, ...]

    def as_dict(self) -> dict:
        return {"blocks_merge": self.blocks_merge, "reasons": list(self.reasons)}


def evaluate_ci_gates(
    *, certification_passed: bool, report_drift_clean: bool,
    manifest_coverage_ok: bool, framework_tests_passed: bool,
) -> CIGateResult:
    """Combine every CI-relevant signal into a single merge-blocking
    decision. Any single failing signal blocks the merge — gates are
    never averaged or partially weighted."""
    reasons: list[str] = []
    if not certification_passed:
        reasons.append("provider certification gate failed")
    if not report_drift_clean:
        reasons.append("generated certification reports are stale")
    if not manifest_coverage_ok:
        reasons.append("a provider-affecting change was made without a corresponding manifest update")
    if not framework_tests_passed:
        reasons.append("provider certification framework tests failed")
    return CIGateResult(blocks_merge=bool(reasons), reasons=tuple(reasons))
