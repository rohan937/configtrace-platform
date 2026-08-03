"""Typed models for the Provider Certification Framework.

Everything here is a plain, frozen dataclass — no ORM, no Pydantic, no
network I/O. Manifests are validated at construction time
(``__post_init__``) so a contradictory manifest fails immediately and
loudly, rather than silently certifying nonsense later.

A manifest declaration is NEVER, by itself, certification evidence — see
``app.provider_certification.gates`` for the evaluators that check
declared intent against discovered repository reality.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = 1

# ── Evidence quality taxonomy (message 4) ──────────────────────────────────────
# "deferred" is intentionally excluded — it is not a property an evidence
# entry can carry; it is what the gate reports when NO evidence/exceptions
# are declared at all.
_EVIDENCE_QUALITIES = frozenset({"direct", "grouped", "static_only"})

# ── Completeness-scope taxonomy (message 4) ────────────────────────────────────
# Generic granularities only — never a provider name. Extend this set as
# genuinely new granularities are needed by future providers; do not add
# a value that only one provider will ever use without checking whether
# an existing value already covers it.
COMPLETENESS_SCOPE_GRANULARITIES = frozenset({
    "family",
    "account",
    "organization",
    "project",
    "repository",
    "group",
    "cluster",
    "namespace",
    "zone",
    "parent_resource",
    "detail",
    "derived_dependency",
})

# ── Maturity taxonomy ─────────────────────────────────────────────────────────
#
# Mirrors app.services.provider_capability_matrix_service.MATURITY_LEVELS
# exactly — this framework does not reinterpret that taxonomy, it just
# attaches certification meaning to each level.

MATURITY_LEVELS = frozenset({"planned", "partial", "complete"})

MATURITY_SEMANTICS: dict[str, str] = {
    "planned": (
        "Internal groundwork only. Non-connectable, non-public, non-Live. "
        "Incomplete frontend/public surfaces are acceptable. Most gates are "
        "not_applicable or deferred; only identity/backend-registration "
        "gates are required."
    ),
    "partial": (
        "Launched provider — configuration drift and Security Findings are "
        "expected end-to-end. Activity/event ingestion, signals, "
        "correlations, and demo/case tooling are NOT required (deferred is "
        "acceptable for those dimensions only)."
    ),
    "complete": (
        "Only for providers where the FULL dual-stack capability model "
        "(drift AND activity ingestion AND signals AND correlations AND "
        "demo/case reporting) is actually implemented. No deferred gates "
        "are allowed for a provider declaring 'complete' — every dimension "
        "must resolve to pass or not_applicable."
    ),
}

# Dimensions that may be `deferred` for a `partial`-maturity provider without
# blocking overall PASS. Any other gate that resolves to `deferred` blocks
# overall PASS for a partial provider. A `complete` provider allows none of
# these; a `planned` provider allows all gates outside identity/backend
# registration to be not_applicable or deferred.
PARTIAL_ALLOWED_DEFERRED_DIMENSIONS = frozenset(
    {
        "activity_ingestion",
        "activity_signals",
        "risk_activity_correlations",
        "demo_case_reporting",
        "change_classification_exhaustive_proof",
    }
)


# ── Certification dimensions ──────────────────────────────────────────────────
#
# Stable string IDs. Never renumber/rename an existing ID — evidence and
# historical reports reference these.

DIMENSIONS: dict[str, str] = {
    "identity": "Provider identity (ID/label/category consistency)",
    "backend_registration": "Backend registration (sync dispatch, schema literal, coverage list, capability matrix)",
    "credential_schema": "Credential schema (fields exist, sensitivity marked)",
    "creation_validation": "Creation validation (synchronous validate-before-persist)",
    "reconnect_rotation": "Reconnect / credential rotation dispatch",
    "sync_dispatch": "Sync service dispatch",
    "worker_dispatch": "Worker task dispatch",
    "connector_contract": "Connector contract (class exists, credential mapping)",
    "read_only_behavior": "Read-only behavior (no mutating HTTP/SQL, no CLI)",
    "stable_resource_identity": "Stable resource identity (non-slug-based)",
    "record_inventory": "Record inventory (expected == discovered record types)",
    "diff_tracked_fields": "Diff tracked-field entries for every record type",
    "change_classifier_coverage": "Change classifier dispatch coverage",
    "provider_metadata": "Provider metadata support",
    "completeness_model": "Completeness model declaration",
    "false_removal_protection": "False-removal protection declaration",
    "retry_pagination_reliability": "Retry/pagination reliability evidence",
    "deterministic_ordering": "Deterministic ordering / idempotency evidence",
    "security_finding_registry_parity": "Security Finding registry/confidence/pack/coverage parity",
    "finding_reachability": "Finding reachability (evaluator wired)",
    "finding_change_parity": "Finding-vs-Change severity parity evidence",
    "sensitive_data_controls": "Sensitive-data controls",
    "capability_matrix_parity": "Capability matrix parity",
    "security_coverage_parity": "Security coverage service parity",
    "frontend_provider_parity": "Frontend provider parity (IDs, connectable, form)",
    "public_connectable_live_consistency": "Public/connectable/Live consistency",
    "dependency_env_audit": "Database/dependency/env-var audit",
    "known_limitations": "Known limitations documented",
    "test_evidence": "Test evidence references",
    "activity_ingestion": "Activity/event ingestion (dual-stack, optional)",
    "activity_signals": "Incident signals from activity (dual-stack, optional)",
    "risk_activity_correlations": "Risk x activity correlations (dual-stack, optional)",
    "demo_case_reporting": "Demo seed/case/report/timeline/graph (dual-stack, optional)",
    "change_classification_exhaustive_proof": "Exhaustive change-classification transition proof",
    "provider_expansion_freeze": "Global: provider expansion freeze state",
    "adapter_consistency": "Provider discovery adapter agrees with (or has no contradiction against) generic discovery",
    "cross_manifest_identity": "Global: no duplicate provider IDs/aliases across registered manifests",
    "cross_manifest_capability_consistency": "Global: maturity/capability declarations agree with the discovered capability matrix across all registered manifests",
    "cross_manifest_finding_uniqueness": "Global: no Security Finding rule-ID collisions across registered manifests",
    "cross_manifest_catalog_consistency": "Global: every registered manifest agrees with backend/frontend/capability-matrix/security-coverage catalogs",
    "cross_manifest_live_freeze": "Global: every Live-declared manifest is absent from every future-provider queue",
    "security_finding_reachability": "Every declared Finding rule ID has direct evidence, grouped evidence, or an explicit static-only exemption that real connector-shaped records reach the evaluator",
    "finding_change_parity": "Every declared Finding rule ID with a direct Change transition has parity evidence or an explicit, rationale-backed severity exception",
    "cross_manifest_reachability_parity_coverage": "Global: every provider declaring Security Findings has reachability and parity evidence registered",
}


def is_known_dimension(dimension: str) -> bool:
    return dimension in DIMENSIONS


# ── Certification status taxonomy ─────────────────────────────────────────────

STATUS_VALUES = frozenset({"pass", "fail", "warning", "not_applicable", "deferred", "unknown"})


class CertificationStatusError(ValueError):
    pass


def validate_status(status: str) -> str:
    if status not in STATUS_VALUES:
        raise CertificationStatusError(
            f"Invalid certification status {status!r}; must be one of {sorted(STATUS_VALUES)}"
        )
    return status


# ── Evidence model ─────────────────────────────────────────────────────────────

EVIDENCE_TYPES = frozenset(
    {
        "discovered_symbol",
        "test_file",
        "test_node_id",
        "report",
        "source_grep",
        "capability_matrix_entry",
        "manifest_declaration",
    }
)


@dataclass(frozen=True)
class CertificationEvidence:
    """A single piece of evidence backing a gate's status.

    Never arbitrary prose alone — always tied to a concrete, checkable
    thing: a discovered symbol, a real test file, a report path, or an
    exact expected/observed value pair.
    """

    evidence_type: str
    file: str | None = None
    test_node_id: str | None = None
    report: str | None = None
    discovered_symbol: str | None = None
    expected_value: str | None = None
    observed_value: str | None = None
    note: str = ""

    def __post_init__(self) -> None:
        if self.evidence_type not in EVIDENCE_TYPES:
            raise ValueError(
                f"Invalid evidence_type {self.evidence_type!r}; must be one of {sorted(EVIDENCE_TYPES)}"
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "evidence_type": self.evidence_type,
            "file": self.file,
            "test_node_id": self.test_node_id,
            "report": self.report,
            "discovered_symbol": self.discovered_symbol,
            "expected_value": self.expected_value,
            "observed_value": self.observed_value,
            "note": self.note,
        }


# ── Certification gate model ──────────────────────────────────────────────────


@dataclass(frozen=True)
class CertificationGate:
    """The result of evaluating one certification dimension for one provider.

    Evaluators are trusted Python code (see ``gates.py``) — nothing
    executable is ever persisted in the JSON/manifest output, only this
    structured result.
    """

    gate_id: str
    dimension: str
    title: str
    description: str
    required_for_maturities: tuple[str, ...]
    required_for_live: bool
    status: str
    details: str
    remediation: str = ""
    blocking: bool = True
    evidence: tuple[CertificationEvidence, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not is_known_dimension(self.dimension):
            raise ValueError(f"Unknown certification dimension: {self.dimension!r}")
        validate_status(self.status)
        for m in self.required_for_maturities:
            if m not in MATURITY_LEVELS:
                raise ValueError(f"Unknown maturity in required_for_maturities: {m!r}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "dimension": self.dimension,
            "title": self.title,
            "description": self.description,
            "required_for_maturities": list(self.required_for_maturities),
            "required_for_live": self.required_for_live,
            "status": self.status,
            "details": self.details,
            "remediation": self.remediation,
            "blocking": self.blocking,
            "evidence": [e.as_dict() for e in self.evidence],
        }


# ── Finding-reachability evidence model (message 3) ───────────────────────────
#
# "A predicate can evaluate a handcrafted record" is not reachability
# evidence — this framework requires evidence that a REAL,
# connector-shaped record (via the connector's own fetch/normalize path,
# or a documented fixture pipeline standing in for it) reaches the
# Security Finding evaluator. Not every rule needs its own dedicated
# end-to-end test: one connector/normalizer path commonly produces
# several related record shapes that trigger several related rules —
# such cases are declared as one GROUPED evidence entry covering
# multiple rule IDs, with an explicit mapping (``covered_rule_ids``).


@dataclass(frozen=True)
class FindingReachabilityEvidence:
    """One piece of evidence that real, connector-shaped records reach
    the Security Finding evaluator for one or more declared rule IDs.

    ``test_file`` must be a real, existing path relative to the backend
    root, inside ``tests/`` (never a live-API call). ``test_selector``
    is a keyword/substring used to identify the relevant test(s) inside
    that file (a class name, a shared fixture name, or similar) —
    test-time tooling (never the runtime certifier) counts matches to
    prove ``minimum_test_count`` is met.
    """

    provider_id: str
    test_file: str
    test_selector: str
    covered_rule_ids: tuple[str, ...]
    source_record_type: str = ""
    derived_record_type: str = ""
    real_connector_path_required: bool = True
    minimum_test_count: int = 1
    note: str = ""
    quality: str = "direct"
    """Evidence quality (message 4): one of ``_EVIDENCE_QUALITIES``.
    ``direct``/``grouped`` evidence can satisfy PASS on their own.
    ``static_only`` evidence requires a corresponding
    ``ReachabilityExemption`` to be non-blocking — it proves predicates
    can evaluate handcrafted records, not that a real connector path
    reaches the evaluator. ``deferred`` is not valid on evidence itself
    (deferred is the ABSENCE of evidence, expressed by declaring none)."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "test_file": self.test_file,
            "test_selector": self.test_selector,
            "covered_rule_ids": sorted(self.covered_rule_ids),
            "source_record_type": self.source_record_type,
            "derived_record_type": self.derived_record_type,
            "real_connector_path_required": self.real_connector_path_required,
            "minimum_test_count": self.minimum_test_count,
            "note": self.note,
            "quality": self.quality,
        }


@dataclass(frozen=True)
class ReachabilityExemption:
    """A declared, non-silent exemption for rule IDs whose source
    posture cannot be deterministically constructed through the
    connector fixture pipeline without external/private API support.

    Never silent: every exempted rule ID must appear here with a
    concrete, provider-specific reason. ``blocking=True`` means the
    exemption itself is a certification concern requiring explicit
    review (still counted as "covered" for reachability purposes, but
    flagged in gate details) — ``blocking=False`` (default) is a
    routine, accepted static-only limitation."""

    rule_ids: tuple[str, ...]
    reason: str
    blocking: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_ids": sorted(self.rule_ids),
            "reason": self.reason,
            "blocking": self.blocking,
        }


# ── Finding-vs-Change parity evidence model (message 3) ───────────────────────


@dataclass(frozen=True)
class FindingChangeParityEvidence:
    """Evidence that a real ``compute_diff()``-pipeline test proves
    Change severity is at least as severe as the corresponding static
    Finding severity for the declared rule IDs."""

    provider_id: str
    test_file: str
    test_selector: str
    covered_rule_ids: tuple[str, ...]
    transition_record_types: tuple[str, ...] = field(default_factory=tuple)
    minimum_test_count: int = 1
    note: str = ""
    quality: str = "direct"

    def as_dict(self) -> dict[str, Any]:
        return {
            "quality": self.quality,
            "provider_id": self.provider_id,
            "test_file": self.test_file,
            "test_selector": self.test_selector,
            "covered_rule_ids": sorted(self.covered_rule_ids),
            "transition_record_types": sorted(self.transition_record_types),
            "minimum_test_count": self.minimum_test_count,
            "note": self.note,
        }


_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


@dataclass(frozen=True)
class ParityException:
    """An explicitly-declared, non-silent exception where a Change
    transition's severity is intentionally lower than (or otherwise
    diverges from) the corresponding static Finding severity — e.g. a
    documented business-logic reason a specific transition is treated
    more leniently. Never silent: requires a durable rationale and a
    real evidence test proving the exception was deliberately reviewed,
    not merely unimplemented."""

    rule_id: str
    static_severity: str
    transition_severity: str
    rationale: str
    evidence_test: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "static_severity": self.static_severity,
            "transition_severity": self.transition_severity,
            "rationale": self.rationale,
            "evidence_test": self.evidence_test,
        }


# ── Typed completeness-scope declaration (message 4) ───────────────────────────


@dataclass(frozen=True)
class CompletenessScopeDeclaration:
    """A single typed completeness/false-removal scope.

    Replaces the message-1/2/3 free-form ``completeness_scopes`` /
    ``false_removal_scopes`` string tuples with a structured
    declaration for NEW usage — those string fields remain for
    backward compatibility and are not removed. A provider may declare
    both, or only the typed form, or only the legacy strings.
    """

    scope_id: str
    record_types: tuple[str, ...]
    granularity: str
    parent_record_type: str | None = None
    status_field: str | None = None
    suppression_symbol: str | None = None
    derived_dependents: tuple[str, ...] = field(default_factory=tuple)
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "record_types": sorted(self.record_types),
            "granularity": self.granularity,
            "parent_record_type": self.parent_record_type,
            "status_field": self.status_field,
            "suppression_symbol": self.suppression_symbol,
            "derived_dependents": sorted(self.derived_dependents),
            "note": self.note,
        }


# ── Provider certification manifest ───────────────────────────────────────────


class ManifestValidationError(ValueError):
    """Raised when a manifest declares a contradictory or invalid state."""


@dataclass(frozen=True)
class ProviderCertificationManifest:
    """Provider-owned declarative certification manifest.

    This is DECLARED INTENT ONLY. The certification runner compares this
    against discovered repository reality (see ``discovery.py``) — the
    manifest is never trusted as evidence by itself.
    """

    provider_id: str
    display_name: str
    category: str
    maturity: str

    expected_public: bool
    expected_connectable: bool
    expected_live: bool

    credential_fields: tuple[str, ...]
    sensitive_credential_fields: tuple[str, ...]
    authentication_model: str

    expected_record_types: tuple[str, ...]
    derived_record_types: tuple[str, ...] = field(default_factory=tuple)

    security_finding_rule_ids: tuple[str, ...] = field(default_factory=tuple)

    supported_capabilities: tuple[str, ...] = field(default_factory=tuple)
    unsupported_capabilities: tuple[str, ...] = field(default_factory=tuple)

    completeness_scopes: tuple[str, ...] = field(default_factory=tuple)
    false_removal_scopes: tuple[str, ...] = field(default_factory=tuple)

    expected_frontend_form: str | None = None
    expected_reconnect: bool = False

    allowed_dependencies: tuple[str, ...] = field(default_factory=tuple)
    prohibited_dependencies: tuple[str, ...] = field(default_factory=tuple)
    required_env_vars: tuple[str, ...] = field(default_factory=tuple)
    prohibited_env_vars: tuple[str, ...] = field(default_factory=tuple)

    known_limitations: tuple[str, ...] = field(default_factory=tuple)
    evidence_test_files: tuple[str, ...] = field(default_factory=tuple)
    evidence_reports: tuple[str, ...] = field(default_factory=tuple)

    reachability_evidence: tuple[FindingReachabilityEvidence, ...] = field(default_factory=tuple)
    reachability_exemptions: tuple[ReachabilityExemption, ...] = field(default_factory=tuple)
    change_parity_evidence: tuple[FindingChangeParityEvidence, ...] = field(default_factory=tuple)
    change_parity_exceptions: tuple[ParityException, ...] = field(default_factory=tuple)

    completeness_scope_declarations: tuple[CompletenessScopeDeclaration, ...] = field(default_factory=tuple)
    """Typed completeness declarations (message 4) — additive, optional.
    See CompletenessScopeDeclaration. Legacy completeness_scopes /
    false_removal_scopes strings remain the primary declaration surface;
    this field is for new, structured detail where a provider wants it."""

    certification_owner: str = "provider-certification-framework"
    manifest_version: int = 1

    # ── Validation ────────────────────────────────────────────────────────────

    def __post_init__(self) -> None:
        errors: list[str] = []

        if not self.provider_id or not self.provider_id.islower():
            errors.append(f"provider_id must be a non-empty lowercase string, got {self.provider_id!r}")

        if self.maturity not in MATURITY_LEVELS:
            errors.append(f"maturity must be one of {sorted(MATURITY_LEVELS)}, got {self.maturity!r}")

        # ── contradiction: Live true + connectable false ──────────────────────
        if self.expected_live and not self.expected_connectable:
            errors.append("expected_live=True requires expected_connectable=True")

        # ── contradiction: connectable true + public false ────────────────────
        if self.expected_connectable and not self.expected_public:
            errors.append("expected_connectable=True requires expected_public=True")

        # ── contradiction: internal (planned) provider listed as public ───────
        if self.maturity == "planned" and (self.expected_public or self.expected_connectable or self.expected_live):
            errors.append(
                "maturity='planned' providers must not be expected_public/expected_connectable/expected_live"
            )

        # ── contradiction: security findings true + zero rule IDs ─────────────
        if "security_findings" in self.supported_capabilities and not self.security_finding_rule_ids:
            errors.append("supported_capabilities includes 'security_findings' but security_finding_rule_ids is empty")
        if self.security_finding_rule_ids and "security_findings" not in self.supported_capabilities:
            errors.append("security_finding_rule_ids is non-empty but 'security_findings' is not in supported_capabilities")

        # ── duplicate record types ─────────────────────────────────────────────
        if len(self.expected_record_types) != len(set(self.expected_record_types)):
            dupes = _duplicates(self.expected_record_types)
            errors.append(f"expected_record_types contains duplicates: {sorted(dupes)}")

        # ── duplicate derived record types / overlap with expected ────────────
        if len(self.derived_record_types) != len(set(self.derived_record_types)):
            dupes = _duplicates(self.derived_record_types)
            errors.append(f"derived_record_types contains duplicates: {sorted(dupes)}")
        overlap = set(self.derived_record_types) - set(self.expected_record_types)
        if overlap:
            errors.append(
                f"derived_record_types must be a subset of expected_record_types; not declared: {sorted(overlap)}"
            )

        # ── duplicate Finding IDs ───────────────────────────────────────────────
        if len(self.security_finding_rule_ids) != len(set(self.security_finding_rule_ids)):
            dupes = _duplicates(self.security_finding_rule_ids)
            errors.append(f"security_finding_rule_ids contains duplicates: {sorted(dupes)}")
        for rule_id in self.security_finding_rule_ids:
            if not rule_id.startswith(f"{self.provider_id}_"):
                errors.append(f"security_finding_rule_id {rule_id!r} does not start with '{self.provider_id}_'")

        # ── secret credential not marked sensitive ─────────────────────────────
        missing_sensitivity = set(self.credential_fields) & _SECRET_LOOKING_FIELD_NAMES(self.credential_fields) - set(
            self.sensitive_credential_fields
        )
        if missing_sensitivity:
            errors.append(
                f"credential fields look secret but are not in sensitive_credential_fields: {sorted(missing_sensitivity)}"
            )
        unknown_sensitive = set(self.sensitive_credential_fields) - set(self.credential_fields)
        if unknown_sensitive:
            errors.append(
                f"sensitive_credential_fields references fields not in credential_fields: {sorted(unknown_sensitive)}"
            )

        # ── reconnect required but no reconnect dispatch declared ──────────────
        # (expected_reconnect=True is the manifest's own declaration that
        # reconnect dispatch SHOULD exist; the gate layer verifies it does.
        # Here we only reject the inverse contradiction: Live provider that
        # explicitly declares expected_reconnect=False.)
        if self.expected_live and not self.expected_reconnect:
            errors.append("expected_live=True requires expected_reconnect=True (Live providers must support credential rotation)")

        # ── frontend form required but provider would be absent from frontend ──
        if self.expected_connectable and not self.expected_frontend_form:
            errors.append("expected_connectable=True requires expected_frontend_form to be declared")

        # ── unsupported capability advertised as supported ─────────────────────
        overlap_caps = set(self.supported_capabilities) & set(self.unsupported_capabilities)
        if overlap_caps:
            errors.append(f"capability declared both supported and unsupported: {sorted(overlap_caps)}")

        # ── complete maturity with required capability gaps ────────────────────
        if self.maturity == "complete":
            required_for_complete = {
                "security_findings",
                "activity_ingestion",
                "activity_signals",
                "risk_activity_correlations",
                "demo_case_reporting",
            }
            missing = required_for_complete - set(self.supported_capabilities)
            if missing:
                errors.append(
                    f"maturity='complete' requires every dual-stack capability; missing from supported_capabilities: {sorted(missing)}"
                )

        # ── allowed vs prohibited dependency overlap ───────────────────────────
        dep_overlap = set(self.allowed_dependencies) & set(self.prohibited_dependencies)
        if dep_overlap:
            errors.append(f"dependency declared both allowed and prohibited: {sorted(dep_overlap)}")
        env_overlap = set(self.required_env_vars) & set(self.prohibited_env_vars)
        if env_overlap:
            errors.append(f"env var declared both required and prohibited: {sorted(env_overlap)}")

        # ── reachability / parity evidence validation (message 3) ──────────────
        known_rule_ids = set(self.security_finding_rule_ids)

        seen_evidence_ids: set[tuple[str, str]] = set()
        for ev in self.reachability_evidence:
            if ev.provider_id != self.provider_id:
                errors.append(
                    f"reachability_evidence declares provider_id={ev.provider_id!r}, "
                    f"which differs from the manifest's own provider_id={self.provider_id!r} "
                    "(no shared-evidence allowance is configured)"
                )
            unknown = set(ev.covered_rule_ids) - known_rule_ids
            if unknown:
                errors.append(f"reachability_evidence covers unknown rule ID(s): {sorted(unknown)}")
            if ev.minimum_test_count < 1:
                errors.append(f"reachability_evidence minimum_test_count must be >= 1, got {ev.minimum_test_count}")
            if not ev.test_file.startswith("tests/"):
                errors.append(f"reachability_evidence test_file must be inside tests/: {ev.test_file!r}")
            ev_id = (ev.test_file, ev.test_selector)
            if ev_id in seen_evidence_ids:
                errors.append(f"duplicate reachability_evidence (test_file, test_selector): {ev_id!r}")
            seen_evidence_ids.add(ev_id)

        for exemption in self.reachability_exemptions:
            unknown = set(exemption.rule_ids) - known_rule_ids
            if unknown:
                errors.append(f"reachability_exemptions references unknown rule ID(s): {sorted(unknown)}")
            if not exemption.reason:
                errors.append("reachability_exemptions entry has an empty reason")

        if "security_findings" in self.supported_capabilities and known_rule_ids:
            reachability_covered = {rid for ev in self.reachability_evidence for rid in ev.covered_rule_ids}
            exempted = {rid for ex in self.reachability_exemptions for rid in ex.rule_ids}
            uncovered = known_rule_ids - reachability_covered - exempted
            if uncovered:
                errors.append(
                    f"rule ID(s) declared with neither reachability evidence nor an exemption: {sorted(uncovered)}"
                )

        seen_parity_ids: set[tuple[str, str]] = set()
        for ev in self.change_parity_evidence:
            if ev.provider_id != self.provider_id:
                errors.append(
                    f"change_parity_evidence declares provider_id={ev.provider_id!r}, "
                    f"which differs from the manifest's own provider_id={self.provider_id!r}"
                )
            unknown = set(ev.covered_rule_ids) - known_rule_ids
            if unknown:
                errors.append(f"change_parity_evidence covers unknown rule ID(s): {sorted(unknown)}")
            if ev.minimum_test_count < 1:
                errors.append(f"change_parity_evidence minimum_test_count must be >= 1, got {ev.minimum_test_count}")
            if not ev.test_file.startswith("tests/"):
                errors.append(f"change_parity_evidence test_file must be inside tests/: {ev.test_file!r}")
            ev_id = (ev.test_file, ev.test_selector)
            if ev_id in seen_parity_ids:
                errors.append(f"duplicate change_parity_evidence (test_file, test_selector): {ev_id!r}")
            seen_parity_ids.add(ev_id)

        seen_exception_rules: set[str] = set()
        for exc in self.change_parity_exceptions:
            if exc.rule_id not in known_rule_ids:
                errors.append(f"change_parity_exceptions references unknown rule ID: {exc.rule_id!r}")
            if exc.rule_id in seen_exception_rules:
                errors.append(f"duplicate change_parity_exceptions entry for rule ID: {exc.rule_id!r}")
            seen_exception_rules.add(exc.rule_id)
            if not exc.evidence_test:
                errors.append(f"change_parity_exceptions for {exc.rule_id!r} has no evidence_test")
            if not exc.rationale:
                errors.append(f"change_parity_exceptions for {exc.rule_id!r} has an empty rationale")
            if exc.static_severity not in _VALID_SEVERITIES:
                errors.append(f"change_parity_exceptions for {exc.rule_id!r} has invalid static_severity {exc.static_severity!r}")
            if exc.transition_severity not in _VALID_SEVERITIES:
                errors.append(f"change_parity_exceptions for {exc.rule_id!r} has invalid transition_severity {exc.transition_severity!r}")

        # ── evidence quality validation (message 4) ─────────────────────────────
        for ev in self.reachability_evidence:
            if ev.quality not in _EVIDENCE_QUALITIES:
                errors.append(f"reachability_evidence quality must be one of {sorted(_EVIDENCE_QUALITIES)}, got {ev.quality!r}")
        for ev in self.change_parity_evidence:
            if ev.quality not in _EVIDENCE_QUALITIES:
                errors.append(f"change_parity_evidence quality must be one of {sorted(_EVIDENCE_QUALITIES)}, got {ev.quality!r}")

        # ── typed completeness-scope declaration validation (message 4) ────────
        known_record_types = set(self.expected_record_types) | set(self.derived_record_types)
        seen_scope_ids: set[str] = set()
        for scope in self.completeness_scope_declarations:
            if scope.scope_id in seen_scope_ids:
                errors.append(f"duplicate completeness_scope_declarations scope_id: {scope.scope_id!r}")
            seen_scope_ids.add(scope.scope_id)
            if scope.granularity not in COMPLETENESS_SCOPE_GRANULARITIES:
                errors.append(
                    f"completeness_scope_declarations[{scope.scope_id!r}].granularity must be one of "
                    f"{sorted(COMPLETENESS_SCOPE_GRANULARITIES)}, got {scope.granularity!r}"
                )
            unknown_rt = set(scope.record_types) - known_record_types
            if unknown_rt:
                errors.append(
                    f"completeness_scope_declarations[{scope.scope_id!r}].record_types references "
                    f"unknown record type(s): {sorted(unknown_rt)}"
                )
            if scope.parent_record_type is not None and scope.parent_record_type not in known_record_types:
                errors.append(
                    f"completeness_scope_declarations[{scope.scope_id!r}].parent_record_type "
                    f"{scope.parent_record_type!r} is not a known record type"
                )
            unknown_dd = set(scope.derived_dependents) - set(self.derived_record_types)
            if unknown_dd:
                errors.append(
                    f"completeness_scope_declarations[{scope.scope_id!r}].derived_dependents references "
                    f"unknown derived record type(s): {sorted(unknown_dd)}"
                )

        if errors:
            raise ManifestValidationError(
                f"Invalid certification manifest for provider {self.provider_id!r}:\n"
                + "\n".join(f"  - {e}" for e in errors)
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "display_name": self.display_name,
            "category": self.category,
            "maturity": self.maturity,
            "expected_public": self.expected_public,
            "expected_connectable": self.expected_connectable,
            "expected_live": self.expected_live,
            "credential_fields": list(self.credential_fields),
            "sensitive_credential_fields": list(self.sensitive_credential_fields),
            "authentication_model": self.authentication_model,
            "expected_record_types": list(self.expected_record_types),
            "derived_record_types": list(self.derived_record_types),
            "security_finding_rule_ids": sorted(self.security_finding_rule_ids),
            "supported_capabilities": sorted(self.supported_capabilities),
            "unsupported_capabilities": sorted(self.unsupported_capabilities),
            "completeness_scopes": list(self.completeness_scopes),
            "false_removal_scopes": list(self.false_removal_scopes),
            "expected_frontend_form": self.expected_frontend_form,
            "expected_reconnect": self.expected_reconnect,
            "allowed_dependencies": list(self.allowed_dependencies),
            "prohibited_dependencies": list(self.prohibited_dependencies),
            "required_env_vars": list(self.required_env_vars),
            "prohibited_env_vars": list(self.prohibited_env_vars),
            "known_limitations": list(self.known_limitations),
            "evidence_test_files": list(self.evidence_test_files),
            "evidence_reports": list(self.evidence_reports),
            "reachability_evidence": [e.as_dict() for e in sorted(self.reachability_evidence, key=lambda e: (e.test_file, e.test_selector))],
            "reachability_exemptions": [e.as_dict() for e in sorted(self.reachability_exemptions, key=lambda e: sorted(e.rule_ids))],
            "change_parity_evidence": [e.as_dict() for e in sorted(self.change_parity_evidence, key=lambda e: (e.test_file, e.test_selector))],
            "change_parity_exceptions": [e.as_dict() for e in sorted(self.change_parity_exceptions, key=lambda e: e.rule_id)],
            "completeness_scope_declarations": [e.as_dict() for e in sorted(self.completeness_scope_declarations, key=lambda e: e.scope_id)],
            "certification_owner": self.certification_owner,
            "manifest_version": self.manifest_version,
        }


def _duplicates(values: tuple[str, ...]) -> set[str]:
    seen: set[str] = set()
    dupes: set[str] = set()
    for v in values:
        if v in seen:
            dupes.add(v)
        seen.add(v)
    return dupes


_SECRET_NAME_MARKERS = ("token", "secret", "password", "key", "pat", "dsn")


def _SECRET_LOOKING_FIELD_NAMES(fields: tuple[str, ...]) -> set[str]:
    """Heuristic: field names containing a secret-ish marker are expected
    to be declared sensitive. This is a manifest-authoring guardrail, not
    a substitute for the real sensitive-data gate in ``gates.py``."""
    return {f for f in fields if any(marker in f.lower() for marker in _SECRET_NAME_MARKERS)}


# ── Certification result model ────────────────────────────────────────────────


@dataclass(frozen=True)
class CertificationResult:
    provider_id: str
    maturity: str
    overall_status: str
    gates: tuple[CertificationGate, ...]
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_status(self.overall_status)

    @property
    def summary(self) -> dict[str, int]:
        counts = {s: 0 for s in sorted(STATUS_VALUES)}
        for g in self.gates:
            counts[g.status] += 1
        return {
            "passed": counts["pass"],
            "failed": counts["fail"],
            "warnings": counts["warning"],
            "not_applicable": counts["not_applicable"],
            "deferred": counts["deferred"],
            "unknown": counts["unknown"],
        }

    def as_dict(self) -> dict[str, Any]:
        gates_sorted = sorted(self.gates, key=lambda g: g.gate_id)
        return {
            "schema_version": self.schema_version,
            "provider_id": self.provider_id,
            "maturity": self.maturity,
            "overall_status": self.overall_status,
            "gates": [g.as_dict() for g in gates_sorted],
            "summary": self.summary,
        }

    def to_json(self) -> str:
        import json

        return json.dumps(self.as_dict(), sort_keys=True, indent=2)
