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

# A separate "have we run the FULL import block" flag — NOT simply
# `bool(_MANIFESTS)`. If some other module imports one specific manifest
# directly (``from app.provider_certification.manifests.entra import
# ENTRA_MANIFEST``, a real pattern several test files use), that
# manifest's own module-level ``register_manifest()`` call populates
# ``_MANIFESTS`` as a side effect BEFORE ``_ensure_manifests_loaded()``
# ever runs — a dict-truthiness guard would then wrongly treat that
# partial, incidental population as "fully loaded" and skip importing
# every other manifest for the rest of the process.
_manifests_fully_loaded: bool = False

PILOT_PROVIDERS: tuple[str, ...] = (
    "sentry", "snowflake", "okta", "entra", "kubernetes", "github", "gitlab",
    "cloudflare", "supabase", "firebase", "stripe",
    "aws", "vercel", "datadog", "pagerduty", "slack", "jira",
    "auth0", "azure", "clerk", "google_cloud", "linear", "sendgrid",
    "shopify", "terraform_cloud", "twilio",
)


class UnknownProviderError(ValueError):
    pass


class MissingManifestError(ValueError):
    pass


def register_manifest(manifest: ProviderCertificationManifest) -> None:
    _MANIFESTS[manifest.provider_id] = manifest


def _ensure_manifests_loaded() -> None:
    global _manifests_fully_loaded
    if _manifests_fully_loaded:
        return
    # Import triggers each manifest module's module-level
    # register_manifest() call.
    from app.provider_certification.manifests import auth0 as _auth0_manifest  # noqa: F401
    from app.provider_certification.manifests import aws as _aws_manifest  # noqa: F401
    from app.provider_certification.manifests import azure as _azure_manifest  # noqa: F401
    from app.provider_certification.manifests import clerk as _clerk_manifest  # noqa: F401
    from app.provider_certification.manifests import cloudflare as _cloudflare_manifest  # noqa: F401
    from app.provider_certification.manifests import datadog as _datadog_manifest  # noqa: F401
    from app.provider_certification.manifests import entra as _entra_manifest  # noqa: F401
    from app.provider_certification.manifests import firebase as _firebase_manifest  # noqa: F401
    from app.provider_certification.manifests import github as _github_manifest  # noqa: F401
    from app.provider_certification.manifests import gitlab as _gitlab_manifest  # noqa: F401
    from app.provider_certification.manifests import google_cloud as _google_cloud_manifest  # noqa: F401
    from app.provider_certification.manifests import jira as _jira_manifest  # noqa: F401
    from app.provider_certification.manifests import kubernetes as _kubernetes_manifest  # noqa: F401
    from app.provider_certification.manifests import linear as _linear_manifest  # noqa: F401
    from app.provider_certification.manifests import okta as _okta_manifest  # noqa: F401
    from app.provider_certification.manifests import pagerduty as _pagerduty_manifest  # noqa: F401
    from app.provider_certification.manifests import sendgrid as _sendgrid_manifest  # noqa: F401
    from app.provider_certification.manifests import sentry as _sentry_manifest  # noqa: F401
    from app.provider_certification.manifests import shopify as _shopify_manifest  # noqa: F401
    from app.provider_certification.manifests import slack as _slack_manifest  # noqa: F401
    from app.provider_certification.manifests import snowflake as _snowflake_manifest  # noqa: F401
    from app.provider_certification.manifests import stripe as _stripe_manifest  # noqa: F401
    from app.provider_certification.manifests import supabase as _supabase_manifest  # noqa: F401
    from app.provider_certification.manifests import terraform_cloud as _terraform_cloud_manifest  # noqa: F401
    from app.provider_certification.manifests import twilio as _twilio_manifest  # noqa: F401
    from app.provider_certification.manifests import vercel as _vercel_manifest  # noqa: F401
    _manifests_fully_loaded = True


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
    gates.append(gate_module.gate_provider_manifest_coverage(all_manifests))
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
        declared = set(manifest.security_finding_rule_ids)
        reachability_covered = {rid for ev in manifest.reachability_evidence for rid in ev.covered_rule_ids}
        reachability_exempted = {rid for ex in manifest.reachability_exemptions for rid in ex.rule_ids}
        parity_covered = {rid for ev in manifest.change_parity_evidence for rid in ev.covered_rule_ids}
        parity_excepted = {exc.rule_id for exc in manifest.change_parity_exceptions}
        deferred_gate_ids = sorted(g.gate_id for g in r.gates if g.status == "deferred")
        per_provider[pid] = {
            "provider_id": manifest.provider_id,
            "display_name": manifest.display_name,
            "category": manifest.category,
            "maturity": r.maturity,
            "overall_status": r.overall_status,
            "summary": r.summary,
            "public": manifest.expected_public,
            "connectable": manifest.expected_connectable,
            "live": manifest.expected_live,
            "record_count": len(manifest.expected_record_types),
            "finding_count": len(declared),
            "supported_capability_count": len(manifest.supported_capabilities),
            "unsupported_capability_count": len(manifest.unsupported_capabilities),
            "completeness_scope_count": len(manifest.completeness_scopes) + len(manifest.completeness_scope_declarations),
            "reachability_evidence_coverage": {
                "covered": len(declared & reachability_covered),
                "exempted": len(declared & reachability_exempted),
                "declared": len(declared),
            },
            "parity_evidence_coverage": {
                "covered": len(declared & parity_covered),
                "excepted": len(declared & parity_excepted),
                "declared": len(declared),
            },
            "exemption_count": len(manifest.reachability_exemptions) + len(manifest.change_parity_exceptions),
            "warnings": sum(1 for g in r.gates if g.status == "warning"),
            "deferred_gates": deferred_gate_ids,
            "deferred_gate_count": len(deferred_gate_ids),
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


def adoption_report() -> dict:
    """Repository-wide certification adoption coverage (message 5):
    launched vs. certified vs. allowlisted vs. missing vs. orphan
    provider-ID sets, deterministic and timestamp-free."""
    from app.provider_certification import discovery as disc
    from app.provider_certification import migration_allowlist as ma

    launched = disc.discover_launched_provider_ids()
    certified = set(known_provider_ids())
    allowlisted = ma.allowlisted_provider_ids()
    planned_ids = {pid for pid in certified if get_manifest(pid).maturity == "planned"}
    missing = launched - certified - allowlisted
    orphans = certified - launched - planned_ids
    coverage_pct = round(100.0 * len(certified & (launched | planned_ids)) / len(launched | planned_ids), 2) if (launched | planned_ids) else 100.0
    return {
        "schema_version": 1,
        "launched_provider_count": len(launched),
        "certified_provider_count": len(certified),
        "allowlisted_provider_count": len(allowlisted),
        "missing_unexpected_count": len(missing),
        "orphan_manifest_count": len(orphans),
        "coverage_percentage": coverage_pct,
        "certified_provider_ids": sorted(certified),
        "allowlisted_provider_ids": sorted(allowlisted),
        "unexpected_missing_provider_ids": sorted(missing),
        "orphan_manifest_provider_ids": sorted(orphans),
    }


def write_adoption_report(output_dir: Path | None = None) -> Path:
    """Write the deterministic certification adoption report to
    backend/tests/reports/provider_certification_adoption.json."""
    import json

    out_dir = output_dir or (_BACKEND_ROOT / "tests" / "reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "provider_certification_adoption.json"
    path.write_text(json.dumps(adoption_report(), sort_keys=True, indent=2) + "\n")
    return path
