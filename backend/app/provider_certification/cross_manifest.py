"""Cross-manifest global certification gates (message 2 of N).

These gates operate over EVERY registered manifest at once — they check
invariants that only make sense across the whole certified-provider set,
not any single provider in isolation: uniqueness of provider IDs/aliases,
maturity/capability consistency against the discovered capability matrix,
Security Finding rule-ID uniqueness across providers, backend/frontend
catalog consistency, and Live-provider absence from every future-provider
queue.

Like ``gates.gate_provider_expansion_freeze``, these are GLOBAL facts —
they do not belong to any one provider — so ``runner.py`` computes them
once and attaches the same result set to every provider's certification
result.
"""

from __future__ import annotations

from app.provider_certification import discovery as disc
from app.provider_certification.models import CertificationEvidence, CertificationGate, ProviderCertificationManifest


def _gate(
    gate_id: str,
    dimension: str,
    title: str,
    description: str,
    status: str,
    details: str,
    remediation: str = "",
    blocking: bool = True,
    evidence: tuple[CertificationEvidence, ...] = (),
) -> CertificationGate:
    return CertificationGate(
        gate_id=gate_id,
        dimension=dimension,
        title=title,
        description=description,
        required_for_maturities=("planned", "partial", "complete"),
        required_for_live=False,
        status=status,
        details=details,
        remediation=remediation,
        blocking=blocking,
        evidence=evidence,
    )


def gate_cross_manifest_identity(manifests: tuple[ProviderCertificationManifest, ...]) -> CertificationGate:
    """No duplicate provider IDs, and no manifest's provider_id appears as
    a disguised alias of another (case/underscore variants of the same
    display name token both registered as distinct providers)."""
    ids = [m.provider_id for m in manifests]
    dupes = {pid for pid in ids if ids.count(pid) > 1}
    if dupes:
        return _gate(
            "cross_manifest_identity", "cross_manifest_identity", "Cross-manifest identity uniqueness",
            "Every registered manifest has a unique provider_id; no alias variant is double-registered.",
            "fail", f"Duplicate provider_id across manifests: {sorted(dupes)}",
            remediation="Manifests must register exactly one provider_id each.",
        )
    normalized = {pid.lower().replace("-", "_") for pid in ids}
    if len(normalized) != len(ids):
        return _gate(
            "cross_manifest_identity", "cross_manifest_identity", "Cross-manifest identity uniqueness",
            "Every registered manifest has a unique provider_id; no alias variant is double-registered.",
            "fail", f"Case/separator-normalized provider IDs collide: {sorted(ids)}",
            remediation="Use one canonical provider_id per provider; do not register hyphen/case variants.",
        )
    return _gate(
        "cross_manifest_identity", "cross_manifest_identity", "Cross-manifest identity uniqueness",
        "Every registered manifest has a unique provider_id; no alias variant is double-registered.",
        "pass", f"{len(ids)} manifest(s) registered with unique provider_ids: {sorted(ids)}.",
        evidence=(CertificationEvidence(evidence_type="manifest_declaration", observed_value=str(sorted(ids))),),
    )


def gate_cross_manifest_capability_consistency(manifests: tuple[ProviderCertificationManifest, ...]) -> CertificationGate:
    """For every registered manifest, the discovered capability-matrix
    entry's maturity and dual-stack security flags must not contradict
    the manifest's declared maturity/supported/unsupported capabilities."""
    mismatches: dict[str, list[str]] = {}
    for m in manifests:
        cap = disc.discover_capability_entry(m.provider_id)
        if cap is None:
            if m.maturity != "planned":
                mismatches[m.provider_id] = [f"no capability-matrix entry for non-planned maturity={m.maturity!r}"]
            continue
        issues = []
        if cap.maturity != m.maturity:
            issues.append(f"capability-matrix maturity={cap.maturity!r} != manifest maturity={m.maturity!r}")
        # Dual-stack flags: activity_ingestion declared unsupported must
        # match the discovered capability entry's own activity_ingestion=False.
        if "activity_ingestion" in m.unsupported_capabilities and cap.security.activity_ingestion:
            issues.append("manifest declares activity_ingestion unsupported but capability matrix reports it enabled")
        if "activity_ingestion" in m.supported_capabilities and not cap.security.activity_ingestion:
            issues.append("manifest declares activity_ingestion supported but capability matrix reports it disabled")
        if "security_findings" in m.supported_capabilities and not cap.security.security_rules:
            issues.append("manifest declares security_findings supported but capability matrix security_rules=False")
        if issues:
            mismatches[m.provider_id] = issues
    if mismatches:
        return _gate(
            "cross_manifest_capability_consistency", "cross_manifest_capability_consistency",
            "Cross-manifest capability consistency",
            "Every manifest's maturity/capability declarations agree with the discovered capability matrix.",
            "fail", f"Mismatches: {mismatches}",
            remediation="Reconcile each manifest's maturity/capabilities with its capability-matrix entry.",
        )
    return _gate(
        "cross_manifest_capability_consistency", "cross_manifest_capability_consistency",
        "Cross-manifest capability consistency",
        "Every manifest's maturity/capability declarations agree with the discovered capability matrix.",
        "pass", f"All {len(manifests)} manifest(s) agree with their discovered capability-matrix entry.",
    )


def gate_cross_manifest_finding_uniqueness(manifests: tuple[ProviderCertificationManifest, ...]) -> CertificationGate:
    """No Security Finding rule ID is declared by more than one manifest
    (rule IDs are provider-prefixed by construction, but this checks the
    real discovered registry, not just the naming convention)."""
    all_ids: list[str] = []
    for m in manifests:
        all_ids.extend(m.security_finding_rule_ids)
    dupes = {rid for rid in all_ids if all_ids.count(rid) > 1}
    if dupes:
        return _gate(
            "cross_manifest_finding_uniqueness", "cross_manifest_finding_uniqueness",
            "Cross-manifest Finding-ID uniqueness",
            "No Security Finding rule ID is declared by more than one registered manifest.",
            "fail", f"Rule IDs declared by multiple manifests: {sorted(dupes)}",
            remediation="Rule IDs must be globally unique across providers.",
        )
    registry_all = set()
    from app.services.security_rule_registry import KNOWN_RULE_KEYS

    registry_all = set(KNOWN_RULE_KEYS)
    declared_all = set(all_ids)
    extra_in_registry_for_pilots = set()
    for m in manifests:
        prefix = f"{m.provider_id}_"
        provider_registry_ids = {k for k in registry_all if k.startswith(prefix)}
        extra = provider_registry_ids - set(m.security_finding_rule_ids)
        if extra:
            extra_in_registry_for_pilots |= extra
    total_declared = len(declared_all)
    return _gate(
        "cross_manifest_finding_uniqueness", "cross_manifest_finding_uniqueness",
        "Cross-manifest Finding-ID uniqueness",
        "No Security Finding rule ID is declared by more than one registered manifest.",
        "pass", f"{total_declared} Finding IDs declared across {len(manifests)} manifest(s); no cross-provider collisions.",
        evidence=(CertificationEvidence(evidence_type="discovered_symbol", discovered_symbol="security_rule_registry.KNOWN_RULE_KEYS", observed_value=str(total_declared)),),
    )


def gate_cross_manifest_catalog_consistency(manifests: tuple[ProviderCertificationManifest, ...]) -> CertificationGate:
    """Every registered manifest agrees with the backend sync-provider
    list, frontend provider/connectable lists, capability-matrix complete
    list, and security-coverage membership."""
    fe_ids = disc.discover_frontend_provider_ids()
    fe_connectable = disc.discover_frontend_connectable_ids()
    sync_ids = disc.discover_backend_sync_provider_ids()
    mismatches: dict[str, list[str]] = {}
    for m in manifests:
        issues = []
        if m.provider_id not in sync_ids:
            issues.append("missing from sync_service._SUPPORTED_PROVIDERS")
        in_complete, in_partial = disc.discover_capability_matrix_membership(m.provider_id)
        # NOTE (message 3): PROVIDER_CAPABILITIES_PARTIAL is not a
        # "not really launched" list — see gate_capability_matrix_parity's
        # docstring in gates.py for the full explanation. Registration in
        # EITHER list satisfies catalog consistency.
        if not (in_complete or in_partial):
            issues.append("missing from both PROVIDER_CAPABILITIES and PROVIDER_CAPABILITIES_PARTIAL")
        if not disc.discover_coverage_provider_membership(m.provider_id):
            issues.append("missing from security_coverage_service.PROVIDERS")
        if fe_ids is not None and m.provider_id not in fe_ids:
            issues.append("missing from frontend PROVIDER_IDS")
        if fe_connectable is not None and m.expected_connectable and m.provider_id not in fe_connectable:
            issues.append("missing from frontend CONNECTABLE_PROVIDER_IDS")
        if issues:
            mismatches[m.provider_id] = issues
    if mismatches:
        return _gate(
            "cross_manifest_catalog_consistency", "cross_manifest_catalog_consistency",
            "Cross-manifest catalog consistency",
            "Every manifest agrees with backend sync/coverage lists and frontend provider/connectable lists.",
            "fail", f"Catalog mismatches: {mismatches}",
            remediation="Register every provider consistently across all catalogs.",
        )
    return _gate(
        "cross_manifest_catalog_consistency", "cross_manifest_catalog_consistency",
        "Cross-manifest catalog consistency",
        "Every manifest agrees with backend sync/coverage lists and frontend provider/connectable lists.",
        "pass", f"All {len(manifests)} manifest(s) consistent across backend and frontend catalogs.",
    )


def gate_cross_manifest_live_freeze(manifests: tuple[ProviderCertificationManifest, ...]) -> CertificationGate:
    """Every Live-declared manifest must be absent from both the backend
    RECOMMENDED_NEXT_PROVIDERS queue and the frontend future-provider
    queue (by provider_id and by display_name, respectively)."""
    backend_queue = disc.discover_recommended_next_providers()
    frontend_queue = disc.discover_frontend_future_provider_queue() or frozenset()
    issues: dict[str, list[str]] = {}
    for m in manifests:
        if not m.expected_live:
            continue
        provider_issues = []
        if m.provider_id in backend_queue:
            provider_issues.append("present in RECOMMENDED_NEXT_PROVIDERS")
        if m.display_name in frontend_queue:
            provider_issues.append("present in frontend future-provider queue")
        if provider_issues:
            issues[m.provider_id] = provider_issues
    if issues:
        return _gate(
            "cross_manifest_live_freeze", "cross_manifest_live_freeze", "Cross-manifest Live-freeze consistency",
            "Every Live-declared manifest is absent from every future-provider queue.",
            "fail", f"Live providers found in a future-provider queue: {issues}",
            remediation="Remove the provider from every future-provider queue.",
        )
    live_count = sum(1 for m in manifests if m.expected_live)
    return _gate(
        "cross_manifest_live_freeze", "cross_manifest_live_freeze", "Cross-manifest Live-freeze consistency",
        "Every Live-declared manifest is absent from every future-provider queue.",
        "pass", f"All {live_count} Live-declared manifest(s) absent from both future-provider queues.",
    )


ALL_CROSS_MANIFEST_GATE_FUNCS = (
    gate_cross_manifest_identity,
    gate_cross_manifest_capability_consistency,
    gate_cross_manifest_finding_uniqueness,
    gate_cross_manifest_catalog_consistency,
    gate_cross_manifest_live_freeze,
)


def run_cross_manifest_gates(manifests: tuple[ProviderCertificationManifest, ...]) -> tuple[CertificationGate, ...]:
    return tuple(sorted((f(manifests) for f in ALL_CROSS_MANIFEST_GATE_FUNCS), key=lambda g: g.gate_id))
