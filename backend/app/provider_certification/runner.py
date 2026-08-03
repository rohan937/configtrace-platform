"""Certification runner service.

``certify_provider(provider_id)`` and ``certify_all_providers()`` are the
public entry points. Both are pure/read-only: no network call, no DB
session, no customer credential access, no connector instantiation, no
sync trigger. See ``test_provider_certification_runner.py`` for the
tests that pin this.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.provider_certification import cross_manifest as cross_manifest_module
from app.provider_certification import gates as gate_module
from app.provider_certification.models import (
    PARTIAL_ALLOWED_DEFERRED_DIMENSIONS,
    CertificationGate,
    CertificationResult,
    ProviderCertificationManifest,
)

_BACKEND_ROOT = Path(__file__).resolve().parents[2]

# Manifest registry — populated by importing the manifests package.
# Kept explicit (not a dynamic directory scan) so an unknown provider_id
# fails clearly rather than silently returning nothing.
_MANIFESTS: dict[str, ProviderCertificationManifest] = {}

PILOT_PROVIDERS: tuple[str, ...] = ("sentry", "snowflake", "okta", "entra")


class UnknownProviderError(ValueError):
    pass


class MissingManifestError(ValueError):
    pass


def register_manifest(manifest: ProviderCertificationManifest) -> None:
    _MANIFESTS[manifest.provider_id] = manifest


def _ensure_manifests_loaded() -> None:
    if _MANIFESTS:
        return
    # Import triggers each manifest module's module-level
    # register_manifest() call.
    from app.provider_certification.manifests import entra as _entra_manifest  # noqa: F401
    from app.provider_certification.manifests import okta as _okta_manifest  # noqa: F401
    from app.provider_certification.manifests import sentry as _sentry_manifest  # noqa: F401
    from app.provider_certification.manifests import snowflake as _snowflake_manifest  # noqa: F401


def known_provider_ids() -> tuple[str, ...]:
    _ensure_manifests_loaded()
    return tuple(sorted(_MANIFESTS))


def get_manifest(provider_id: str) -> ProviderCertificationManifest:
    _ensure_manifests_loaded()
    if provider_id not in _MANIFESTS:
        raise MissingManifestError(
            f"No certification manifest registered for provider_id={provider_id!r}. "
            f"Known providers: {sorted(_MANIFESTS)}"
        )
    return _MANIFESTS[provider_id]


def _overall_status(manifest: ProviderCertificationManifest, gates: tuple[CertificationGate, ...]) -> str:
    """A provider may receive overall PASS only when:
      * every blocking gate passes (or is not_applicable)
      * no blocking gate is unknown
      * deferred blocking gates are only present on dimensions the
        provider's maturity is explicitly allowed to defer
      * no gate failed
    """
    has_fail = any(g.status == "fail" and g.blocking for g in gates)
    has_unknown = any(g.status == "unknown" and g.blocking for g in gates)
    if has_fail or has_unknown:
        return "fail"

    disallowed_deferred = [
        g
        for g in gates
        if g.status == "deferred"
        and g.blocking
        and not (
            manifest.maturity == "partial"
            and g.dimension in PARTIAL_ALLOWED_DEFERRED_DIMENSIONS
        )
        and manifest.maturity != "planned"
    ]
    if disallowed_deferred:
        return "fail"

    return "pass"


def certify_provider(provider_id: str) -> CertificationResult:
    """Certify a single provider. Raises MissingManifestError if the
    provider has no registered manifest — a provider with no manifest
    never silently passes."""
    manifest = get_manifest(provider_id)

    gates: list[CertificationGate] = []
    for gate_func in gate_module.ALL_PROVIDER_GATE_FUNCS:
        gates.append(gate_func(manifest))
    # Global gates — attached to every provider's result since these are
    # repository-wide invariants, not per-provider capabilities.
    gates.append(gate_module.gate_provider_expansion_freeze())
    all_manifests = tuple(_MANIFESTS[pid] for pid in sorted(_MANIFESTS))
    gates.extend(cross_manifest_module.run_cross_manifest_gates(all_manifests))

    gates_tuple = tuple(sorted(gates, key=lambda g: g.gate_id))
    overall = _overall_status(manifest, gates_tuple)
    return CertificationResult(
        provider_id=provider_id,
        maturity=manifest.maturity,
        overall_status=overall,
        gates=gates_tuple,
    )


def certify_all_providers(provider_ids: tuple[str, ...] | None = None) -> dict[str, CertificationResult]:
    """Certify every known (or explicitly listed) provider. Deterministic
    ordering: sorted by provider_id."""
    ids = provider_ids if provider_ids is not None else known_provider_ids()
    return {pid: certify_provider(pid) for pid in sorted(ids)}


def write_report(result: CertificationResult, output_dir: Path | None = None) -> Path:
    """Write the deterministic JSON report to
    backend/tests/reports/provider_certification/<provider>.json."""
    out_dir = output_dir or (_BACKEND_ROOT / "tests" / "reports" / "provider_certification")
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{result.provider_id}.json"
    path.write_text(result.to_json() + "\n")
    return path


def certification_summary(results: dict[str, CertificationResult] | None = None) -> dict:
    """Deterministic per-provider comparison summary, sorted by
    provider_id. No timestamps, no environment-specific paths."""
    results = results if results is not None else certify_all_providers()
    per_provider = {}
    for pid in sorted(results):
        r = results[pid]
        manifest = get_manifest(pid)
        per_provider[pid] = {
            "maturity": r.maturity,
            "overall_status": r.overall_status,
            "summary": r.summary,
            "record_count": len(manifest.expected_record_types),
            "finding_count": len(manifest.security_finding_rule_ids),
        }
    return {
        "schema_version": 1,
        "providers": per_provider,
        "all_pass": all(r.overall_status == "pass" for r in results.values()),
    }


def write_summary_report(output_dir: Path | None = None) -> Path:
    """Write the deterministic all-providers summary JSON to
    backend/tests/reports/provider_certification/summary.json."""
    import json

    out_dir = output_dir or (_BACKEND_ROOT / "tests" / "reports" / "provider_certification")
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "summary.json"
    path.write_text(json.dumps(certification_summary(), sort_keys=True, indent=2) + "\n")
    return path
