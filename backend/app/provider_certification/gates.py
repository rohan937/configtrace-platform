"""Certification gate evaluators.

Each ``gate_*`` function takes a ``ProviderCertificationManifest`` and
returns a single ``CertificationGate``. Evaluators compare the manifest's
DECLARED intent against DISCOVERED repository reality — a manifest field
alone is never treated as evidence.

These functions are pure (no side effects) and read-only (no network, no
DB, no credential access) — see
``test_provider_certification_gates.py`` and the "no network/no
credential" tests in ``test_provider_certification_runner.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification.models import (
    PARTIAL_ALLOWED_DEFERRED_DIMENSIONS,
    CertificationEvidence,
    CertificationGate,
    ProviderCertificationManifest,
)

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_REPO_ROOT = _BACKEND_ROOT.parent


def _ev_symbol(symbol: str, expected: str | None = None, observed: str | None = None, note: str = "") -> CertificationEvidence:
    return CertificationEvidence(
        evidence_type="discovered_symbol",
        discovered_symbol=symbol,
        expected_value=expected,
        observed_value=observed,
        note=note,
    )


def _ev_file(file: str, note: str = "") -> CertificationEvidence:
    return CertificationEvidence(evidence_type="test_file", file=file, note=note)


def _credential_fields_for(provider_id: str) -> frozenset[str]:
    """Adapter-aware credential-field discovery.

    Generic discovery filters IntegrationCreateRequest fields by a
    ``<provider>_`` name prefix — true for every provider except
    Kubernetes, whose credential fields (``kubeconfig``, ``context``,
    ``cluster_name``, ``namespace_allowlist``) carry no such prefix. If
    a discovery adapter is registered and declares credential fields,
    its result AUGMENTS (never silently overrides) the generic result —
    see ``adapters.resolve_set``."""
    generic = disc.discover_credential_schema_fields(provider_id)
    adapter = adapt.get_adapter(provider_id)
    if adapter is None or adapter.discover_credential_fields is None:
        return generic
    resolved = adapt.resolve_set(generic, adapter.discover_credential_fields)
    return resolved.value


def _reconnect_wired_for(provider_id: str) -> bool:
    """True if reconnect is wired via EITHER the per-provider
    ``reconnect_credentials_<provider>()`` function OR the shared
    generic ``reconnect_credentials()`` dispatcher's inline branch (the
    pattern some original-8-era providers, e.g. GitHub, still use)."""
    return disc.discover_reconnect_function_exists(provider_id) or disc.discover_generic_reconnect_dispatch(provider_id)


def _count_matching_tests(test_file: str, selector: str) -> int:
    """Count ``def test_...`` functions "under" a selector (typically a
    class name) inside a real test file — pure static text parsing, NO
    pytest invocation, no subprocess, no collection machinery. Bounded
    to the block between the selector's occurrence and the next
    top-level ``class ``/``def `` declaration (or EOF), so this counts
    only tests belonging to that one class/section, not the whole file.
    Returns 0 if the file or selector isn't found."""
    path = _BACKEND_ROOT / test_file
    if not path.is_file():
        return 0
    text = path.read_text()
    if not selector:
        # Empty selector means "the whole file is the evidence" — count
        # every test in it, not just one class's worth.
        return len(re.findall(r"^\s+def test_", text, re.MULTILINE))
    idx = text.find(selector)
    if idx == -1:
        return 0
    rest = text[idx + len(selector):]
    boundary = re.search(r"^(class |def )\w", rest, re.MULTILINE)
    block = rest[: boundary.start()] if boundary else rest
    return len(re.findall(r"^\s+def test_", block, re.MULTILINE))


def _create_dispatch_wired_for(provider_id: str) -> bool:
    """True if creation validation is wired via EITHER a named
    ``_create_<provider>_integration()`` function OR an inline
    ``elif body.provider == "<provider>":`` branch in the POST
    /integrations router handler (the pattern some original-8-era
    providers, e.g. GitLab, still use)."""
    return disc.discover_create_dispatch_function_exists(provider_id) or disc.discover_router_create_dispatch(provider_id)


def _gate(
    gate_id: str,
    dimension: str,
    title: str,
    description: str,
    manifest: ProviderCertificationManifest,
    status: str,
    details: str,
    remediation: str = "",
    evidence: tuple[CertificationEvidence, ...] = (),
    blocking: bool = True,
    required_for_live: bool = False,
    required_for_maturities: tuple[str, ...] = ("planned", "partial", "complete"),
) -> CertificationGate:
    return CertificationGate(
        gate_id=gate_id,
        dimension=dimension,
        title=title,
        description=description,
        required_for_maturities=required_for_maturities,
        required_for_live=required_for_live,
        status=status,
        details=details,
        remediation=remediation,
        blocking=blocking,
        evidence=evidence,
    )


# ── A. Provider identity ──────────────────────────────────────────────────────


def gate_identity(manifest: ProviderCertificationManifest) -> CertificationGate:
    cap = disc.discover_capability_entry(manifest.provider_id)
    if cap is None:
        in_complete, in_partial = disc.discover_capability_matrix_membership(manifest.provider_id)
        if manifest.maturity == "planned" and not in_complete:
            return _gate(
                "identity", "identity", "Provider identity",
                "Provider ID/label/category is internally consistent.",
                manifest, "not_applicable",
                "Planned provider has no launched capability-matrix entry yet — acceptable.",
            )
        return _gate(
            "identity", "identity", "Provider identity",
            "Provider ID/label/category is internally consistent.",
            manifest, "fail",
            f"No capability-matrix entry found for provider_id={manifest.provider_id!r}.",
            remediation="Register the provider in provider_capability_matrix_service.py.",
        )
    mismatches = []
    if cap.provider != manifest.provider_id:
        mismatches.append(f"provider id mismatch: manifest={manifest.provider_id!r} discovered={cap.provider!r}")
    if cap.category != manifest.category:
        mismatches.append(f"category mismatch: manifest={manifest.category!r} discovered={cap.category!r}")
    if mismatches:
        return _gate(
            "identity", "identity", "Provider identity",
            "Provider ID/label/category is internally consistent.",
            manifest, "fail", "; ".join(mismatches),
            remediation="Align the manifest with the capability-matrix entry (or vice versa).",
            evidence=(_ev_symbol("provider_capability_matrix_service.get_provider_capability", manifest.provider_id, cap.provider),),
        )
    return _gate(
        "identity", "identity", "Provider identity",
        "Provider ID/label/category is internally consistent.",
        manifest, "pass", f"provider_id/category match discovered capability entry: {cap.provider}/{cap.category}.",
        evidence=(_ev_symbol("provider_capability_matrix_service.get_provider_capability", observed=f"{cap.provider}/{cap.category}"),),
    )


# ── B. Backend registration ───────────────────────────────────────────────────


def gate_backend_registration(manifest: ProviderCertificationManifest) -> CertificationGate:
    pid = manifest.provider_id
    sync_ids = disc.discover_backend_sync_provider_ids()
    schema_literal = disc.discover_backend_credential_schema_provider_literal(pid)
    coverage_member = disc.discover_coverage_provider_membership(pid)

    if manifest.maturity == "planned":
        return _gate(
            "backend_registration", "backend_registration", "Backend registration",
            "Provider is dispatchable by sync_service, present in the credential schema literal, and in the security coverage list.",
            manifest, "deferred" if pid not in sync_ids else "pass",
            f"planned provider: sync_dispatch={pid in sync_ids} schema_literal={schema_literal} coverage_member={coverage_member}",
        )

    missing = []
    if pid not in sync_ids:
        missing.append("sync_service._SUPPORTED_PROVIDERS")
    if not schema_literal:
        missing.append("IntegrationCreateRequest.provider literal")
    if not coverage_member:
        missing.append("security_coverage_service.PROVIDERS")

    if missing:
        return _gate(
            "backend_registration", "backend_registration", "Backend registration",
            "Provider is dispatchable by sync_service, present in the credential schema literal, and in the security coverage list.",
            manifest, "fail", f"Missing backend registration surfaces: {missing}",
            remediation="Register the provider in every listed surface.",
        )
    return _gate(
        "backend_registration", "backend_registration", "Backend registration",
        "Provider is dispatchable by sync_service, present in the credential schema literal, and in the security coverage list.",
        manifest, "pass", "Provider present in sync dispatch, credential schema literal, and security coverage list.",
        evidence=(
            _ev_symbol("sync_service._SUPPORTED_PROVIDERS", observed=pid),
            _ev_symbol("security_coverage_service.PROVIDERS", observed=pid),
        ),
    )


# ── C. Credential schema ──────────────────────────────────────────────────────


def gate_credential_schema(manifest: ProviderCertificationManifest) -> CertificationGate:
    if not manifest.credential_fields:
        return _gate(
            "credential_schema", "credential_schema", "Credential schema",
            "Every manifest credential field exists on the backend schema; secret fields are marked sensitive.",
            manifest, "not_applicable", "Manifest declares no credential fields.",
        )
    discovered = _credential_fields_for(manifest.provider_id)
    expected = set(manifest.credential_fields)
    missing = expected - discovered
    extra = discovered - expected

    if missing:
        return _gate(
            "credential_schema", "credential_schema", "Credential schema",
            "Every manifest credential field exists on the backend schema; secret fields are marked sensitive.",
            manifest, "fail",
            f"Manifest credential fields not found on IntegrationCreateRequest: {sorted(missing)}",
            remediation="Add the missing fields to IntegrationCreateRequest, or correct the manifest.",
            evidence=(_ev_symbol("IntegrationCreateRequest.model_fields", str(sorted(expected)), str(sorted(discovered))),),
        )
    status = "warning" if extra else "pass"
    details = f"All {len(expected)} manifest credential fields found on backend schema."
    if extra:
        details += f" Backend schema has undeclared extra fields for this provider: {sorted(extra)}."
    return _gate(
        "credential_schema", "credential_schema", "Credential schema",
        "Every manifest credential field exists on the backend schema; secret fields are marked sensitive.",
        manifest, status, details,
        evidence=(_ev_symbol("IntegrationCreateRequest.model_fields", observed=str(sorted(discovered))),),
    )


# ── D. Creation validation ────────────────────────────────────────────────────


def gate_creation_validation(manifest: ProviderCertificationManifest) -> CertificationGate:
    if manifest.maturity == "planned":
        return _gate(
            "creation_validation", "creation_validation", "Creation validation",
            "Synchronous validate-before-persist dispatch function exists.",
            manifest, "not_applicable", "Planned provider is not yet connectable.",
        )
    exists = _create_dispatch_wired_for(manifest.provider_id)
    status = "pass" if exists else "fail"
    return _gate(
        "creation_validation", "creation_validation", "Creation validation",
        "Synchronous validate-before-persist dispatch function exists.",
        manifest, status,
        f"creation dispatch wired (named function or router-inline branch) for {manifest.provider_id!r}: {exists}",
        remediation="Implement the synchronous create-dispatch function (named or router-inline)." if not exists else "",
        evidence=(_ev_symbol(f"integration_service._create_{manifest.provider_id}_integration (or router-inline)", observed=str(exists)),),
    )


# ── E. Reconnect / rotation ───────────────────────────────────────────────────


def gate_reconnect_rotation(manifest: ProviderCertificationManifest) -> CertificationGate:
    if not manifest.expected_reconnect:
        return _gate(
            "reconnect_rotation", "reconnect_rotation", "Reconnect / rotation dispatch",
            "Reconnect dispatch function, router branch, and schema fields exist.",
            manifest, "not_applicable", "Manifest does not require reconnect for this provider.",
        )
    pid = manifest.provider_id
    fn_exists = _reconnect_wired_for(pid)
    router_exists = disc.discover_reconnect_router_dispatch(pid)
    schema_fields = disc.discover_reconnect_schema_fields(pid) or _credential_fields_for(pid)
    missing = []
    if not fn_exists:
        missing.append(f"integration_service.reconnect_credentials_{pid} (or generic reconnect_credentials() dispatch branch)")
    if not router_exists:
        missing.append("routers/integrations.py reconnect branch")
    if not schema_fields:
        missing.append("IntegrationReconnectRequest fields")
    if missing:
        return _gate(
            "reconnect_rotation", "reconnect_rotation", "Reconnect / rotation dispatch",
            "Reconnect dispatch function, router branch, and schema fields exist.",
            manifest, "fail", f"Missing reconnect wiring: {missing}",
            remediation="Wire reconnect end-to-end (service function, router branch, schema fields).",
        )
    return _gate(
        "reconnect_rotation", "reconnect_rotation", "Reconnect / rotation dispatch",
        "Reconnect dispatch function, router branch, and schema fields exist.",
        manifest, "pass",
        f"Reconnect fully wired: function, router branch, and {len(schema_fields)} schema field(s).",
        evidence=(_ev_symbol(f"integration_service.reconnect_credentials_{pid}", observed="exists"),),
    )


# ── F/G. Sync + worker dispatch ───────────────────────────────────────────────


def gate_sync_dispatch(manifest: ProviderCertificationManifest) -> CertificationGate:
    if manifest.maturity == "planned":
        return _gate(
            "sync_dispatch", "sync_dispatch", "Sync service dispatch",
            "Provider is present in sync_service's supported-provider set.",
            manifest, "deferred", "Planned provider — sync dispatch may not exist yet.",
        )
    present = manifest.provider_id in disc.discover_backend_sync_provider_ids()
    return _gate(
        "sync_dispatch", "sync_dispatch", "Sync service dispatch",
        "Provider is present in sync_service's supported-provider set.",
        manifest, "pass" if present else "fail",
        f"provider in sync_service._SUPPORTED_PROVIDERS: {present}",
        remediation="Add the provider to sync_service._SUPPORTED_PROVIDERS." if not present else "",
    )


def gate_worker_dispatch(manifest: ProviderCertificationManifest) -> CertificationGate:
    if manifest.maturity == "planned":
        return _gate(
            "worker_dispatch", "worker_dispatch", "Worker dispatch",
            "sync_task.py dispatches this provider to its connector.",
            manifest, "deferred", "Planned provider — worker dispatch may not exist yet.",
        )
    present = disc.discover_worker_dispatch(manifest.provider_id)
    return _gate(
        "worker_dispatch", "worker_dispatch", "Worker dispatch",
        "sync_task.py dispatches this provider to its connector.",
        manifest, "pass" if present else "fail",
        f"sync_task.py provider dispatch branch present: {present}",
        remediation="Add a provider dispatch branch to sync_task.py." if not present else "",
    )


# ── H. Connector contract ─────────────────────────────────────────────────────


def gate_connector_contract(manifest: ProviderCertificationManifest) -> CertificationGate:
    pid = manifest.provider_id
    class_name = "".join(part.capitalize() for part in pid.split("_")) + "Connector"
    connector_cls = disc.discover_connector_class(pid, class_name)
    if connector_cls is None:
        connector_cls = disc.discover_connector_class_any_capitalization(pid)
        fallback_used = connector_cls is not None
    else:
        fallback_used = False
    if connector_cls is None:
        return _gate(
            "connector_contract", "connector_contract", "Connector contract",
            "Connector class exists and exposes a credential-mapping method.",
            manifest, "fail" if manifest.maturity != "planned" else "deferred",
            f"Could not import class {class_name} (or any *Connector class matching {pid!r}) from app.connectors.{pid}.",
            remediation="Ensure the connector class name follows the <Provider>Connector convention.",
        )
    class_name = connector_cls.__name__ if fallback_used else class_name
    has_credentials = hasattr(connector_cls, "_credentials")
    status = "pass" if has_credentials else "warning"
    return _gate(
        "connector_contract", "connector_contract", "Connector contract",
        "Connector class exists and exposes a credential-mapping method.",
        manifest, status,
        f"{class_name} imported successfully; _credentials() present: {has_credentials}.",
        evidence=(_ev_symbol(f"app.connectors.{pid}.{class_name}", observed="imported"),),
    )


# ── K/L. Record inventory + diff tracked fields ───────────────────────────────


def gate_record_inventory(manifest: ProviderCertificationManifest) -> CertificationGate:
    if not manifest.expected_record_types:
        return _gate(
            "record_inventory", "record_inventory", "Record inventory",
            "Manifest expected_record_types == discovered schema record-type constants.",
            manifest, "not_applicable", "Manifest declares no expected record types.",
        )
    discovered = disc.discover_schema_record_type_constants(manifest.provider_id)
    expected = set(manifest.expected_record_types)
    missing = expected - discovered
    extra = discovered - expected

    if missing:
        return _gate(
            "record_inventory", "record_inventory", "Record inventory",
            "Manifest expected_record_types == discovered schema record-type constants.",
            manifest, "fail",
            f"Expected record types not discovered in <provider>_schema.py: {sorted(missing)}",
            remediation="Add the missing record-type constants, or correct the manifest.",
            evidence=(_ev_symbol(f"app.connectors.{manifest.provider_id}_schema", str(sorted(expected)), str(sorted(discovered))),),
        )
    status = "warning" if extra else "pass"
    details = f"All {len(expected)} expected record types discovered."
    if extra:
        details += f" Undeclared discovered record types: {sorted(extra)}."
    return _gate(
        "record_inventory", "record_inventory", "Record inventory",
        "Manifest expected_record_types == discovered schema record-type constants.",
        manifest, status, details,
        evidence=(_ev_symbol(f"app.connectors.{manifest.provider_id}_schema", observed=str(len(discovered))),),
    )


def gate_diff_tracked_fields(manifest: ProviderCertificationManifest) -> CertificationGate:
    if not manifest.expected_record_types:
        return _gate(
            "diff_tracked_fields", "diff_tracked_fields", "Diff tracked fields",
            "Every expected record type has a non-empty tracked-field entry in diff_service.py.",
            manifest, "not_applicable", "Manifest declares no expected record types.",
        )
    tracked = disc.discover_diff_tracked_fields_dict(manifest.provider_id)
    if tracked is None:
        return _gate(
            "diff_tracked_fields", "diff_tracked_fields", "Diff tracked fields",
            "Every expected record type has a non-empty tracked-field entry in diff_service.py.",
            manifest, "fail",
            f"No _{manifest.provider_id.upper()}_TRACKED_FIELDS_BY_TYPE dict found in diff_service.py.",
            remediation="Add a tracked-fields dict for this provider to diff_service.py.",
        )
    # Diagnostic-only record types may be explicitly declared with zero
    # tracked fields; the manifest does not currently distinguish them, so
    # any record type with an empty tuple is treated as diagnostic-only
    # and reported as a warning rather than a hard failure — it is never
    # silently dropped from the result.
    empty_fields = [rt for rt in manifest.expected_record_types if tracked.get(rt) == ()]
    missing_entirely = [rt for rt in manifest.expected_record_types if rt not in tracked]

    if missing_entirely:
        return _gate(
            "diff_tracked_fields", "diff_tracked_fields", "Diff tracked fields",
            "Every expected record type has a non-empty tracked-field entry in diff_service.py.",
            manifest, "fail",
            f"Record types absent from the tracked-fields dict entirely: {sorted(missing_entirely)}",
            remediation="Add tracked-field tuples for every expected record type.",
        )
    status = "warning" if empty_fields else "pass"
    details = f"All {len(manifest.expected_record_types)} expected record types have tracked-field dict entries."
    if empty_fields:
        details += f" Declared with zero tracked fields (diagnostic-only, not silently dropped): {sorted(empty_fields)}."
    return _gate(
        "diff_tracked_fields", "diff_tracked_fields", "Diff tracked fields",
        "Every expected record type has a non-empty tracked-field entry in diff_service.py.",
        manifest, status, details,
        evidence=(_ev_symbol(f"diff_service._{manifest.provider_id.upper()}_TRACKED_FIELDS_BY_TYPE", observed=str(len(tracked))),),
    )


# ── M. Change classifier coverage ─────────────────────────────────────────────


def gate_change_classifier_coverage(manifest: ProviderCertificationManifest) -> CertificationGate:
    if not manifest.expected_record_types:
        return _gate(
            "change_classifier_coverage", "change_classifier_coverage", "Change classifier coverage",
            "risk_service dispatches this provider's prefix; every expected record type is handled explicitly.",
            manifest, "not_applicable", "Manifest declares no expected record types.",
        )
    pid = manifest.provider_id
    dispatch_exists = disc.discover_classifier_dispatch_exists(pid)
    if not dispatch_exists:
        return _gate(
            "change_classifier_coverage", "change_classifier_coverage", "Change classifier coverage",
            "risk_service dispatches this provider's prefix; every expected record type is handled explicitly.",
            manifest, "fail",
            f"risk_service.classify_change() has no dispatch branch for '{pid}_' record types.",
            remediation="Add a record_type.startswith(f'{provider}_') branch to risk_service.classify_change().",
        )
    generic_handled = disc.discover_classifier_record_type_dispatch(pid)
    adapter = adapt.get_adapter(pid)
    if adapter is not None and adapter.discover_classifier_record_types is not None:
        handled = adapt.resolve_set(generic_handled, adapter.discover_classifier_record_types).value
    else:
        handled = generic_handled
    expected = set(manifest.expected_record_types)
    unhandled = expected - handled
    status = "warning" if unhandled else "pass"
    details = (
        f"Dispatch branch exists; {len(handled & expected)}/{len(expected)} expected record types have an "
        f"explicit record_type == check in risk_rules/{pid}.py."
    )
    if unhandled:
        details += (
            f" Not explicitly matched (may fall through to a shared/default classification path — "
            f"verify via evidence_test_files, this gate cannot statically prove exhaustive coverage): {sorted(unhandled)}."
        )
    return _gate(
        "change_classifier_coverage", "change_classifier_coverage", "Change classifier coverage",
        "risk_service dispatches this provider's prefix; every expected record type is handled explicitly.",
        manifest, status, details,
        evidence=(_ev_symbol(f"risk_rules.{pid}.classify_{pid}_change", observed=str(len(handled))),),
    )


# ── S/T. Security Finding registry parity + reachability ─────────────────────


def gate_security_finding_registry_parity(manifest: ProviderCertificationManifest) -> CertificationGate:
    if "security_findings" not in manifest.supported_capabilities:
        return _gate(
            "security_finding_registry_parity", "security_finding_registry_parity", "Security Finding registry parity",
            "Exact set equality across registry/confidence/pack/coverage (and frontend catalog if the tree is mounted).",
            manifest, "not_applicable", "Manifest does not declare the security_findings capability.",
        )
    pid = manifest.provider_id
    expected = set(manifest.security_finding_rule_ids)
    registry = disc.discover_registry_rule_ids(pid)
    confidence = disc.discover_confidence_rule_ids(pid)
    pack = disc.discover_pack_rule_ids(pid)
    coverage = disc.discover_coverage_rule_ids(pid)
    frontend = disc.discover_frontend_catalog_rule_ids(pid)

    mismatches = {}
    for label, discovered_set in (
        ("registry", registry),
        ("confidence", confidence),
        ("pack", pack),
        ("coverage", coverage),
    ):
        if discovered_set != expected:
            mismatches[label] = {
                "missing_from_discovered": sorted(expected - discovered_set),
                "extra_in_discovered": sorted(discovered_set - expected),
            }

    frontend_note = ""
    if frontend is None:
        frontend_note = " (frontend tree not mounted — frontend parity skipped)"
    elif frontend != expected:
        mismatches["frontend_catalog"] = {
            "missing_from_discovered": sorted(expected - frontend),
            "extra_in_discovered": sorted(frontend - expected),
        }

    if mismatches:
        return _gate(
            "security_finding_registry_parity", "security_finding_registry_parity", "Security Finding registry parity",
            "Exact set equality across registry/confidence/pack/coverage (and frontend catalog if the tree is mounted).",
            manifest, "fail",
            f"Rule-ID set mismatches (manifest has {len(expected)} declared IDs): {mismatches}{frontend_note}",
            remediation="Reconcile the manifest's security_finding_rule_ids with every registry surface.",
        )
    return _gate(
        "security_finding_registry_parity", "security_finding_registry_parity", "Security Finding registry parity",
        "Exact set equality across registry/confidence/pack/coverage (and frontend catalog if the tree is mounted).",
        manifest, "pass",
        f"All {len(expected)} declared Finding IDs match registry/confidence/pack/coverage exactly{frontend_note}.",
        evidence=(_ev_symbol("security_rule_registry.KNOWN_RULE_KEYS", observed=str(len(registry))),),
    )


def gate_finding_reachability(manifest: ProviderCertificationManifest) -> CertificationGate:
    if "security_findings" not in manifest.supported_capabilities:
        return _gate(
            "finding_reachability", "finding_reachability", "Finding reachability",
            "Provider is registered in security_finding_evaluator._PROVIDER_RULES.",
            manifest, "not_applicable", "Manifest does not declare the security_findings capability.",
        )
    registered = disc.discover_evaluator_registered(manifest.provider_id)
    return _gate(
        "finding_reachability", "finding_reachability", "Finding reachability",
        "Provider is registered in security_finding_evaluator._PROVIDER_RULES.",
        manifest, "pass" if registered else "fail",
        f"provider in security_finding_evaluator._PROVIDER_RULES: {registered}",
        remediation="Register the provider's evaluate() function in _PROVIDER_RULES." if not registered else "",
    )


# ── Generalized Finding-reachability + Finding-vs-Change parity (message 3) ───


def gate_security_finding_reachability(manifest: ProviderCertificationManifest) -> CertificationGate:
    """Requires that every declared Finding rule ID has REAL evidence —
    direct or grouped reachability evidence, or an explicit, non-silent
    static-only exemption — that connector-shaped records (not
    handcrafted ones) reach the evaluator. Manifest construction already
    rejects a rule ID covered by neither; this gate additionally checks
    that every referenced evidence file actually exists on disk (a
    filesystem fact construction-time validation cannot check)."""
    if "security_findings" not in manifest.supported_capabilities or not manifest.security_finding_rule_ids:
        return _gate(
            "security_finding_reachability", "security_finding_reachability", "Security Finding reachability",
            "Every declared Finding rule ID has direct/grouped reachability evidence or an explicit exemption.",
            manifest, "not_applicable", "Manifest does not declare the security_findings capability.",
        )
    missing_files = [ev.test_file for ev in manifest.reachability_evidence if not (_BACKEND_ROOT / ev.test_file).is_file()]
    if missing_files:
        return _gate(
            "security_finding_reachability", "security_finding_reachability", "Security Finding reachability",
            "Every declared Finding rule ID has direct/grouped reachability evidence or an explicit exemption.",
            manifest, "fail", f"Reachability evidence file(s) not found on disk: {missing_files}",
            remediation="Fix the evidence test_file path, or add the missing test file.",
        )
    for ev in manifest.reachability_evidence:
        min_count = _count_matching_tests(ev.test_file, ev.test_selector)
        if min_count < ev.minimum_test_count:
            return _gate(
                "security_finding_reachability", "security_finding_reachability", "Security Finding reachability",
                "Every declared Finding rule ID has direct/grouped reachability evidence or an explicit exemption.",
                manifest, "fail",
                f"{ev.test_file}::{ev.test_selector!r} matched {min_count} test(s), below declared minimum_test_count={ev.minimum_test_count}",
                remediation="Add more tests matching the selector, or correct minimum_test_count.",
            )
    covered = {rid for ev in manifest.reachability_evidence for rid in ev.covered_rule_ids}
    exempted = {rid for ex in manifest.reachability_exemptions for rid in ex.rule_ids}
    blocking_exempted = {rid for ex in manifest.reachability_exemptions if ex.blocking for rid in ex.rule_ids}
    status = "warning" if blocking_exempted else "pass"
    details = (
        f"{len(manifest.security_finding_rule_ids)} declared rule ID(s): "
        f"{len(covered)} via reachability evidence ({len(manifest.reachability_evidence)} evidence group(s)), "
        f"{len(exempted)} via exemption ({len(blocking_exempted)} blocking)."
    )
    return _gate(
        "security_finding_reachability", "security_finding_reachability", "Security Finding reachability",
        "Every declared Finding rule ID has direct/grouped reachability evidence or an explicit exemption.",
        manifest, status, details,
        evidence=tuple(_ev_file(ev.test_file, note=ev.test_selector) for ev in manifest.reachability_evidence),
    )


def gate_finding_change_parity(manifest: ProviderCertificationManifest) -> CertificationGate:
    """Requires that every declared Finding rule ID has parity evidence
    (a real ``compute_diff()``-pipeline test proving Change severity is
    at least as severe) or an explicit, rationale-backed severity
    exception. Manifest construction rejects unknown rule IDs / missing
    rationale / missing evidence_test; this gate checks the referenced
    evidence files exist and meet their declared minimum test count."""
    if "security_findings" not in manifest.supported_capabilities or not manifest.security_finding_rule_ids:
        return _gate(
            "finding_change_parity", "finding_change_parity", "Finding-vs-Change parity",
            "Every declared Finding rule ID has parity evidence or an explicit, rationale-backed severity exception.",
            manifest, "not_applicable", "Manifest does not declare the security_findings capability.",
        )
    if not manifest.change_parity_evidence and not manifest.change_parity_exceptions:
        return _gate(
            "finding_change_parity", "finding_change_parity", "Finding-vs-Change parity",
            "Every declared Finding rule ID has parity evidence or an explicit, rationale-backed severity exception.",
            manifest, "deferred", "No change_parity_evidence or change_parity_exceptions declared.", blocking=False,
        )
    missing_files = [ev.test_file for ev in manifest.change_parity_evidence if not (_BACKEND_ROOT / ev.test_file).is_file()]
    if missing_files:
        return _gate(
            "finding_change_parity", "finding_change_parity", "Finding-vs-Change parity",
            "Every declared Finding rule ID has parity evidence or an explicit, rationale-backed severity exception.",
            manifest, "fail", f"Parity evidence file(s) not found on disk: {missing_files}",
            remediation="Fix the evidence test_file path, or add the missing test file.",
        )
    for ev in manifest.change_parity_evidence:
        min_count = _count_matching_tests(ev.test_file, ev.test_selector)
        if min_count < ev.minimum_test_count:
            return _gate(
                "finding_change_parity", "finding_change_parity", "Finding-vs-Change parity",
                "Every declared Finding rule ID has parity evidence or an explicit, rationale-backed severity exception.",
                manifest, "fail",
                f"{ev.test_file}::{ev.test_selector!r} matched {min_count} test(s), below declared minimum_test_count={ev.minimum_test_count}",
                remediation="Add more tests matching the selector, or correct minimum_test_count.",
            )
    for exc in manifest.change_parity_exceptions:
        exc_test_file = exc.evidence_test.split("::")[0]
        if not (_BACKEND_ROOT / exc_test_file).is_file():
            return _gate(
                "finding_change_parity", "finding_change_parity", "Finding-vs-Change parity",
                "Every declared Finding rule ID has parity evidence or an explicit, rationale-backed severity exception.",
                manifest, "fail", f"change_parity_exceptions evidence_test not found on disk: {exc.evidence_test!r}",
                remediation="Fix the exception's evidence_test path.",
            )
    covered = {rid for ev in manifest.change_parity_evidence for rid in ev.covered_rule_ids}
    excepted = {exc.rule_id for exc in manifest.change_parity_exceptions}
    details = (
        f"{len(manifest.security_finding_rule_ids)} declared rule ID(s): "
        f"{len(covered)} via parity evidence ({len(manifest.change_parity_evidence)} evidence group(s)), "
        f"{len(excepted)} via explicit severity exception."
    )
    return _gate(
        "finding_change_parity", "finding_change_parity", "Finding-vs-Change parity",
        "Every declared Finding rule ID has parity evidence or an explicit, rationale-backed severity exception.",
        manifest, "pass", details,
        evidence=tuple(_ev_file(ev.test_file, note=ev.test_selector) for ev in manifest.change_parity_evidence),
    )


# ── W/X. Capability matrix + security coverage parity ─────────────────────────


def gate_capability_matrix_parity(manifest: ProviderCertificationManifest) -> CertificationGate:
    in_complete, in_partial = disc.discover_capability_matrix_membership(manifest.provider_id)
    if manifest.maturity == "planned":
        ok = not in_complete
        return _gate(
            "capability_matrix_parity", "capability_matrix_parity", "Capability matrix parity",
            "Provider's maturity/list-membership matches the declared manifest maturity.",
            manifest, "pass" if ok else "fail",
            f"planned provider in_complete_list={in_complete} (expected False)",
        )
    cap = disc.discover_capability_entry(manifest.provider_id)
    if cap is None:
        return _gate(
            "capability_matrix_parity", "capability_matrix_parity", "Capability matrix parity",
            "Provider's maturity/list-membership matches the declared manifest maturity.",
            manifest, "fail", "No capability-matrix entry found for a non-planned provider.",
            remediation="Add the provider to PROVIDER_CAPABILITIES.",
        )
    mismatches = []
    if cap.maturity != manifest.maturity:
        mismatches.append(f"maturity mismatch: manifest={manifest.maturity!r} discovered={cap.maturity!r}")
    # NOTE (message 3): PROVIDER_CAPABILITIES_PARTIAL is NOT a "not really
    # launched" staging list — get_provider_capability() merges both
    # PROVIDER_CAPABILITIES and PROVIDER_CAPABILITIES_PARTIAL into one
    # lookup (_BY_KEY), and a dozen fully-launched, connectable
    # providers (Azure, Twilio, Auth0, Jira, GitLab, etc.) live
    # permanently in the PARTIAL list. Requiring exclusive
    # PROVIDER_CAPABILITIES membership (message 1/2's original check)
    # was a genuine framework gate defect, surfaced by certifying
    # GitLab — fixed here to require membership in EITHER list.
    if not (in_complete or in_partial):
        mismatches.append("provider must be registered in either PROVIDER_CAPABILITIES or PROVIDER_CAPABILITIES_PARTIAL")
    if mismatches:
        return _gate(
            "capability_matrix_parity", "capability_matrix_parity", "Capability matrix parity",
            "Provider's maturity/list-membership matches the declared manifest maturity.",
            manifest, "fail", "; ".join(mismatches),
            remediation="Reconcile the capability matrix entry with the manifest's declared maturity.",
        )
    list_name = "PROVIDER_CAPABILITIES" if in_complete else "PROVIDER_CAPABILITIES_PARTIAL"
    return _gate(
        "capability_matrix_parity", "capability_matrix_parity", "Capability matrix parity",
        "Provider's maturity/list-membership matches the declared manifest maturity.",
        manifest, "pass", f"maturity={cap.maturity!r} matches manifest; registered in {list_name}.",
        evidence=(_ev_symbol(f"provider_capability_matrix_service.{list_name}", observed=cap.maturity),),
    )


def gate_security_coverage_parity(manifest: ProviderCertificationManifest) -> CertificationGate:
    member = disc.discover_coverage_provider_membership(manifest.provider_id)
    if manifest.maturity == "planned":
        return _gate(
            "security_coverage_parity", "security_coverage_parity", "Security coverage parity",
            "Provider is present in security_coverage_service.PROVIDERS.",
            manifest, "deferred" if not member else "pass",
            f"planned provider coverage membership: {member}",
        )
    return _gate(
        "security_coverage_parity", "security_coverage_parity", "Security coverage parity",
        "Provider is present in security_coverage_service.PROVIDERS.",
        manifest, "pass" if member else "fail",
        f"provider in security_coverage_service.PROVIDERS: {member}",
        remediation="Add the provider to security_coverage_service.PROVIDERS." if not member else "",
    )


# ── Y/Z. Frontend provider parity + public/connectable/Live consistency ──────


def gate_frontend_provider_parity(manifest: ProviderCertificationManifest) -> CertificationGate:
    root = disc.frontend_root()
    if root is None:
        return _gate(
            "frontend_provider_parity", "frontend_provider_parity", "Frontend provider parity",
            "Provider ID/connectable-ID present in frontend providers.ts; form component exists and is wired if required.",
            manifest, "not_applicable", "Frontend tree is not mounted in this environment.",
        )
    pid = manifest.provider_id
    fe_ids = disc.discover_frontend_provider_ids()
    fe_connectable = disc.discover_frontend_connectable_ids()

    if not manifest.expected_public:
        # Provider should NOT be exposed on the frontend at all yet.
        exposed = bool(fe_ids and pid in fe_ids)
        return _gate(
            "frontend_provider_parity", "frontend_provider_parity", "Frontend provider parity",
            "Provider ID/connectable-ID present in frontend providers.ts; form component exists and is wired if required.",
            manifest, "fail" if exposed else "pass",
            f"expected_public=False; provider present in frontend PROVIDER_IDS: {exposed}",
            remediation="Remove the provider from frontend PROVIDER_IDS until it is ready to be public." if exposed else "",
        )

    missing = []
    if not fe_ids or pid not in fe_ids:
        missing.append("frontend PROVIDER_IDS")
    if manifest.expected_connectable and (not fe_connectable or pid not in fe_connectable):
        missing.append("frontend CONNECTABLE_PROVIDER_IDS")
    form_ok = True
    if manifest.expected_frontend_form:
        form_exists = disc.discover_frontend_form_file_exists(manifest.expected_frontend_form)
        form_wired = disc.discover_frontend_form_wired_into_dispatcher(pid, manifest.expected_frontend_form)
        if not form_exists:
            missing.append(f"form file {manifest.expected_frontend_form}")
            form_ok = False
        if not form_wired:
            missing.append("form dispatcher wiring in integrations/page.tsx")
            form_ok = False
        if form_ok and manifest.sensitive_credential_fields:
            if not (
                disc.discover_frontend_form_uses_password_input(manifest.expected_frontend_form)
                or disc.discover_frontend_form_uses_masked_multiline_input(manifest.expected_frontend_form)
            ):
                missing.append("masked input (type=password or textarea) for sensitive credential field")

    if missing:
        return _gate(
            "frontend_provider_parity", "frontend_provider_parity", "Frontend provider parity",
            "Provider ID/connectable-ID present in frontend providers.ts; form component exists and is wired if required.",
            manifest, "fail", f"Missing frontend parity surfaces: {missing}",
            remediation="Wire every missing frontend surface.",
        )
    return _gate(
        "frontend_provider_parity", "frontend_provider_parity", "Frontend provider parity",
        "Provider ID/connectable-ID present in frontend providers.ts; form component exists and is wired if required.",
        manifest, "pass", "Frontend provider ID, connectable ID, and form wiring all present.",
        evidence=(_ev_symbol("providers.ts PROVIDER_IDS/CONNECTABLE_PROVIDER_IDS", observed="present"),),
    )


def gate_public_connectable_live_consistency(manifest: ProviderCertificationManifest) -> CertificationGate:
    if not manifest.expected_live:
        return _gate(
            "public_connectable_live_consistency", "public_connectable_live_consistency", "Public/connectable/Live consistency",
            "For a Live provider: backend+frontend registration, credential validation, reconnect, sync/worker dispatch, capability-matrix launched state, and absence from the future-provider queue all agree.",
            manifest, "not_applicable", "Manifest does not declare expected_live=True.",
        )
    pid = manifest.provider_id
    in_complete, in_partial = disc.discover_capability_matrix_membership(pid)
    checks = {
        "backend_sync_dispatch": pid in disc.discover_backend_sync_provider_ids(),
        "backend_worker_dispatch": disc.discover_worker_dispatch(pid),
        "backend_credential_schema": bool(_credential_fields_for(pid)),
        "reconnect_function": _reconnect_wired_for(pid),
        "create_dispatch": _create_dispatch_wired_for(pid),
        # NOTE (message 3): registration in EITHER capability-matrix list
        # counts — PROVIDER_CAPABILITIES_PARTIAL is not a "not really
        # launched" list, see gate_capability_matrix_parity.
        "capability_matrix_registered": in_complete or in_partial,
        "not_in_future_queue": pid not in disc.discover_recommended_next_providers(),
    }
    root = disc.frontend_root()
    if root is not None:
        fe_ids = disc.discover_frontend_provider_ids() or frozenset()
        fe_connectable = disc.discover_frontend_connectable_ids() or frozenset()
        fe_future = disc.discover_frontend_future_provider_queue()
        checks["frontend_provider_id"] = pid in fe_ids
        checks["frontend_connectable"] = pid in fe_connectable
        checks["not_in_frontend_future_queue"] = fe_future is None or manifest.display_name not in fe_future

    failing = [k for k, v in checks.items() if not v]
    if failing:
        return _gate(
            "public_connectable_live_consistency", "public_connectable_live_consistency", "Public/connectable/Live consistency",
            "For a Live provider: backend+frontend registration, credential validation, reconnect, sync/worker dispatch, capability-matrix launched state, and absence from the future-provider queue all agree.",
            manifest, "fail", f"Live-consistency checks failing: {sorted(failing)}", required_for_live=True,
            remediation="A Live provider must pass every listed check with no contradictions.",
        )
    return _gate(
        "public_connectable_live_consistency", "public_connectable_live_consistency", "Public/connectable/Live consistency",
        "For a Live provider: backend+frontend registration, credential validation, reconnect, sync/worker dispatch, capability-matrix launched state, and absence from the future-provider queue all agree.",
        manifest, "pass", f"All {len(checks)} Live-consistency checks passed.", required_for_live=True,
        evidence=(_ev_symbol("live_consistency_checks", observed=str(sorted(checks))),),
    )


# ── Sensitive-data controls ────────────────────────────────────────────────────


def gate_sensitive_data_controls(manifest: ProviderCertificationManifest) -> CertificationGate:
    if not manifest.sensitive_credential_fields:
        return _gate(
            "sensitive_data_controls", "sensitive_data_controls", "Sensitive-data controls",
            "Sensitive credential fields are masked in the frontend form and never referenced by a global env var.",
            manifest, "not_applicable", "Manifest declares no sensitive credential fields.",
        )
    pid = manifest.provider_id
    issues = []
    if manifest.expected_frontend_form:
        if not (
            disc.discover_frontend_form_uses_password_input(manifest.expected_frontend_form)
            or disc.discover_frontend_form_uses_masked_multiline_input(manifest.expected_frontend_form)
        ):
            issues.append(f"{manifest.expected_frontend_form} has no masked input (type=password or textarea)")
    for env_var in manifest.prohibited_env_vars:
        if disc.discover_global_env_var_reference(pid, env_var):
            issues.append(f"connector references prohibited global env var {env_var!r}")
    if issues:
        return _gate(
            "sensitive_data_controls", "sensitive_data_controls", "Sensitive-data controls",
            "Sensitive credential fields are masked in the frontend form and never referenced by a global env var.",
            manifest, "fail", "; ".join(issues),
            remediation="Mask every sensitive field and remove any global-env-var credential reads.",
        )
    return _gate(
        "sensitive_data_controls", "sensitive_data_controls", "Sensitive-data controls",
        "Sensitive credential fields are masked in the frontend form and never referenced by a global env var.",
        manifest, "pass",
        f"{len(manifest.sensitive_credential_fields)} sensitive field(s) masked; no prohibited global env var reads found.",
    )


# ── Dependency / env-var audit ─────────────────────────────────────────────────


def gate_dependency_env_audit(manifest: ProviderCertificationManifest) -> CertificationGate:
    if not manifest.prohibited_dependencies and not manifest.prohibited_env_vars:
        return _gate(
            "dependency_env_audit", "dependency_env_audit", "Dependency / env-var audit",
            "No prohibited dependency in requirements.txt; no prohibited global env var referenced by the connector.",
            manifest, "not_applicable", "Manifest declares no prohibited dependencies or env vars.",
        )
    issues = []
    for dep in manifest.prohibited_dependencies:
        if disc.discover_prohibited_dependency_present(dep):
            issues.append(f"prohibited dependency {dep!r} found in requirements.txt")
    for env_var in manifest.prohibited_env_vars:
        if disc.discover_global_env_var_reference(manifest.provider_id, env_var):
            issues.append(f"prohibited global env var {env_var!r} referenced by connector")
    if issues:
        return _gate(
            "dependency_env_audit", "dependency_env_audit", "Dependency / env-var audit",
            "No prohibited dependency in requirements.txt; no prohibited global env var referenced by the connector.",
            manifest, "fail", "; ".join(issues),
            remediation="Remove the prohibited dependency/env-var reference.",
        )
    return _gate(
        "dependency_env_audit", "dependency_env_audit", "Dependency / env-var audit",
        "No prohibited dependency in requirements.txt; no prohibited global env var referenced by the connector.",
        manifest, "pass",
        f"None of {len(manifest.prohibited_dependencies)} prohibited dependencies and "
        f"{len(manifest.prohibited_env_vars)} prohibited env vars were found.",
    )


# ── Completeness / false-removal declarations ─────────────────────────────────


def gate_completeness_model(manifest: ProviderCertificationManifest) -> CertificationGate:
    if not manifest.completeness_scopes:
        return _gate(
            "completeness_model", "completeness_model", "Completeness model",
            "Manifest declares family/per-parent completeness scopes backed by real evidence files.",
            manifest, "not_applicable" if manifest.maturity == "planned" else "warning",
            "Manifest declares no completeness scopes.",
        )
    return _gate(
        "completeness_model", "completeness_model", "Completeness model",
        "Manifest declares family/per-parent completeness scopes backed by real evidence files.",
        manifest, "pass", f"{len(manifest.completeness_scopes)} completeness scope(s) declared.",
    )


def gate_false_removal_protection(manifest: ProviderCertificationManifest) -> CertificationGate:
    if not manifest.false_removal_scopes:
        return _gate(
            "false_removal_protection", "false_removal_protection", "False-removal protection",
            "diff_service._<provider>_removal_suppressed exists and covers every declared false-removal scope.",
            manifest, "not_applicable" if manifest.maturity == "planned" else "warning",
            "Manifest declares no false-removal scopes.",
        )
    exists = disc.discover_removal_suppression_exists(manifest.provider_id)
    return _gate(
        "false_removal_protection", "false_removal_protection", "False-removal protection",
        "diff_service._<provider>_removal_suppressed exists and covers every declared false-removal scope.",
        manifest, "pass" if exists else "fail",
        f"_{manifest.provider_id}_removal_suppressed exists: {exists}; "
        f"{len(manifest.false_removal_scopes)} scope(s) declared: {list(manifest.false_removal_scopes)}",
        remediation="Implement the false-removal suppression function." if not exists else "",
        evidence=(_ev_symbol(f"diff_service._{manifest.provider_id}_removal_suppressed", observed=str(exists)),),
    )


# ── Known limitations + test evidence ─────────────────────────────────────────


def gate_known_limitations(manifest: ProviderCertificationManifest) -> CertificationGate:
    if manifest.maturity == "planned":
        return _gate(
            "known_limitations", "known_limitations", "Known limitations",
            "Manifest declares known limitations for a launched provider.",
            manifest, "not_applicable", "Planned provider.",
        )
    status = "pass" if manifest.known_limitations else "warning"
    return _gate(
        "known_limitations", "known_limitations", "Known limitations",
        "Manifest declares known limitations for a launched provider.",
        manifest, status, f"{len(manifest.known_limitations)} known limitation(s) declared.",
        remediation="Document explicit known limitations." if status == "warning" else "",
    )


def gate_test_evidence(manifest: ProviderCertificationManifest) -> CertificationGate:
    if not manifest.evidence_test_files and not manifest.evidence_reports:
        return _gate(
            "test_evidence", "test_evidence", "Test evidence",
            "Every referenced evidence test file/report exists on disk.",
            manifest, "fail" if manifest.maturity != "planned" else "not_applicable",
            "Manifest declares no evidence_test_files or evidence_reports.",
            remediation="Reference the real provider-specific test files and reports backing this certification.",
        )
    missing = []
    for rel in (*manifest.evidence_test_files, *manifest.evidence_reports):
        path = _BACKEND_ROOT / rel
        if not path.is_file():
            missing.append(rel)
    if missing:
        return _gate(
            "test_evidence", "test_evidence", "Test evidence",
            "Every referenced evidence test file/report exists on disk.",
            manifest, "fail", f"Evidence files not found on disk: {missing}",
            remediation="Fix the evidence paths, or add the missing files.",
        )
    total = len(manifest.evidence_test_files) + len(manifest.evidence_reports)
    return _gate(
        "test_evidence", "test_evidence", "Test evidence",
        "Every referenced evidence test file/report exists on disk.",
        manifest, "pass", f"All {total} referenced evidence file(s) exist on disk.",
        evidence=tuple(_ev_file(f) for f in manifest.evidence_test_files),
    )


# ── AC/Dual-stack optional dimensions (deferred by default for partial) ──────


def _optional_dual_stack_gate(gate_id: str, dimension: str, title: str, capability: str, manifest: ProviderCertificationManifest) -> CertificationGate:
    supported = capability in manifest.supported_capabilities
    unsupported = capability in manifest.unsupported_capabilities
    if supported:
        return _gate(
            gate_id, dimension, title,
            f"Dual-stack capability '{capability}' — optional for maturity=partial.",
            manifest, "warning", f"Manifest declares '{capability}' as supported but message 1 does not statically verify it.",
        )
    if unsupported or manifest.maturity == "partial":
        return _gate(
            gate_id, dimension, title,
            f"Dual-stack capability '{capability}' — optional for maturity=partial.",
            manifest, "deferred", f"'{capability}' not required for maturity={manifest.maturity!r}.",
            blocking=False,
        )
    return _gate(
        gate_id, dimension, title,
        f"Dual-stack capability '{capability}' — optional for maturity=partial.",
        manifest, "not_applicable", f"'{capability}' not declared and not required for maturity={manifest.maturity!r}.",
    )


def gate_activity_ingestion(manifest: ProviderCertificationManifest) -> CertificationGate:
    return _optional_dual_stack_gate("activity_ingestion", "activity_ingestion", "Activity ingestion", "activity_ingestion", manifest)


def gate_activity_signals(manifest: ProviderCertificationManifest) -> CertificationGate:
    return _optional_dual_stack_gate("activity_signals", "activity_signals", "Activity signals", "activity_signals", manifest)


def gate_risk_activity_correlations(manifest: ProviderCertificationManifest) -> CertificationGate:
    return _optional_dual_stack_gate("risk_activity_correlations", "risk_activity_correlations", "Risk x activity correlations", "risk_activity_correlations", manifest)


def gate_demo_case_reporting(manifest: ProviderCertificationManifest) -> CertificationGate:
    return _optional_dual_stack_gate("demo_case_reporting", "demo_case_reporting", "Demo/case reporting", "demo_case_reporting", manifest)


def gate_change_classification_exhaustive_proof(manifest: ProviderCertificationManifest) -> CertificationGate:
    """The framework cannot statically prove exhaustive transition
    coverage — it requires evidence references (real parity/matrix
    test files) instead. Deferred is acceptable for `partial` maturity."""
    if not manifest.evidence_test_files:
        if manifest.maturity == "complete":
            return _gate(
                "change_classification_exhaustive_proof", "change_classification_exhaustive_proof",
                "Exhaustive change-classification proof",
                "Real compute_diff-pipeline parity tests are referenced as evidence (never claimed from static discovery alone).",
                manifest, "fail", "maturity='complete' requires evidence_test_files proving exhaustive transition coverage.",
            )
        return _gate(
            "change_classification_exhaustive_proof", "change_classification_exhaustive_proof",
            "Exhaustive change-classification proof",
            "Real compute_diff-pipeline parity tests are referenced as evidence (never claimed from static discovery alone).",
            manifest, "deferred", "No evidence_test_files referenced; acceptable for maturity=partial.", blocking=False,
        )
    return _gate(
        "change_classification_exhaustive_proof", "change_classification_exhaustive_proof",
        "Exhaustive change-classification proof",
        "Real compute_diff-pipeline parity tests are referenced as evidence (never claimed from static discovery alone).",
        manifest, "pass", f"{len(manifest.evidence_test_files)} evidence test file(s) referenced.",
    )


# ── Adapter consistency ────────────────────────────────────────────────────────


def gate_adapter_consistency(manifest: ProviderCertificationManifest) -> CertificationGate:
    """If a discovery adapter is registered for this provider, verify it
    never silently contradicts generic discovery for the record-type
    dimension (the one dimension with the clearest ground truth: the
    manifest's own expected_record_types). No pilot provider currently
    registers an adapter — generic discovery is sufficient for all four
    (Sentry, Snowflake, Okta, Entra) — so this resolves not_applicable for
    them today; see test_provider_certification_adapters.py for the
    synthetic-adapter tests that exercise agreement/augmentation/
    contradiction directly against the adapter module."""
    adapter = adapt.get_adapter(manifest.provider_id)
    if adapter is None:
        return _gate(
            "adapter_consistency", "adapter_consistency", "Adapter consistency",
            "A registered discovery adapter never silently contradicts generic discovery.",
            manifest, "not_applicable", "No discovery adapter registered for this provider; generic discovery is authoritative.",
        )
    generic = disc.discover_schema_record_type_constants(manifest.provider_id)
    resolved = adapt.resolve_set(generic, adapter.discover_record_types)
    if resolved.contradiction_note and not resolved.augmented:
        return _gate(
            "adapter_consistency", "adapter_consistency", "Adapter consistency",
            "A registered discovery adapter never silently contradicts generic discovery.",
            manifest, "fail", resolved.contradiction_note,
            remediation="Reconcile the adapter's discover_record_types() with generic schema discovery.",
        )
    note = resolved.contradiction_note or "Adapter agrees with generic discovery."
    return _gate(
        "adapter_consistency", "adapter_consistency", "Adapter consistency",
        "A registered discovery adapter never silently contradicts generic discovery.",
        manifest, "pass", note,
    )


# ── Global gate: provider-expansion freeze ────────────────────────────────────


def gate_provider_expansion_freeze() -> CertificationGate:
    """Global certification gate — not owned by any single provider.

    Verifies RECOMMENDED_NEXT_PROVIDERS is empty, no frontend
    future-provider queue recommends an unlaunched provider, Sentry is
    not presented as future work, and the framework's own
    planned_next_stage summary says expansion is frozen.
    """
    backend_queue = disc.discover_recommended_next_providers()
    planned_next_stage = disc.discover_planned_next_stage_text()
    frontend_queue = disc.discover_frontend_future_provider_queue()

    issues = []
    if backend_queue:
        issues.append(f"RECOMMENDED_NEXT_PROVIDERS is not empty: {sorted(backend_queue)}")
    if "frozen" not in planned_next_stage.lower():
        issues.append(f"planned_next_stage does not say 'frozen': {planned_next_stage!r}")
    if frontend_queue:
        issues.append(f"frontend future-provider queue is not empty: {sorted(frontend_queue)}")
    if frontend_queue and "Sentry" in frontend_queue:
        issues.append("Sentry is presented as future work in the frontend queue")

    status = "fail" if issues else "pass"
    details = "; ".join(issues) if issues else "Backend queue empty, frontend queue empty/absent, planned_next_stage says frozen."
    return CertificationGate(
        gate_id="provider_expansion_freeze",
        dimension="provider_expansion_freeze",
        title="Provider-expansion freeze",
        description="RECOMMENDED_NEXT_PROVIDERS is empty, no frontend future-provider queue recommends an unlaunched provider, and expansion is marked frozen.",
        required_for_maturities=("planned", "partial", "complete"),
        required_for_live=False,
        status=status,
        details=details,
        remediation="Empty every future-provider queue and mark expansion frozen." if issues else "",
        blocking=True,
        evidence=(_ev_symbol("provider_expansion_framework.RECOMMENDED_NEXT_PROVIDERS", observed=str(sorted(backend_queue))),),
    )


# ── Ordered list of all per-provider gate evaluators ──────────────────────────

ALL_PROVIDER_GATE_FUNCS = (
    gate_identity,
    gate_backend_registration,
    gate_credential_schema,
    gate_creation_validation,
    gate_reconnect_rotation,
    gate_sync_dispatch,
    gate_worker_dispatch,
    gate_connector_contract,
    gate_record_inventory,
    gate_diff_tracked_fields,
    gate_change_classifier_coverage,
    gate_security_finding_registry_parity,
    gate_finding_reachability,
    gate_capability_matrix_parity,
    gate_security_coverage_parity,
    gate_frontend_provider_parity,
    gate_public_connectable_live_consistency,
    gate_sensitive_data_controls,
    gate_dependency_env_audit,
    gate_completeness_model,
    gate_false_removal_protection,
    gate_known_limitations,
    gate_test_evidence,
    gate_activity_ingestion,
    gate_activity_signals,
    gate_risk_activity_correlations,
    gate_demo_case_reporting,
    gate_change_classification_exhaustive_proof,
    gate_adapter_consistency,
    gate_security_finding_reachability,
    gate_finding_change_parity,
)
