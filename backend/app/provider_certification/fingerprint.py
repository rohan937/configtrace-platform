"""Provider contract fingerprint (message 7).

A deterministic, order-independent summary of everything a provider's
certification manifest CONTRACTUALLY promises — used to detect whether
a provider's certification-relevant contract changed, independent of
prose wording (limitations text, evidence notes, display names) that
carries no certification meaning.

Deliberately EXCLUDES: file modification times, display_name, category,
known_limitations text, evidence-note wording, test file paths/counts,
and any other purely descriptive field. Included fields are exactly the
ones enumerated in the message-7 task spec: record-type set, Finding
set, credential fields, supported/unsupported capabilities,
public/connectable/Live state, completeness declarations, reconnect
state, frontend form metadata, schema version.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.provider_certification.models import ProviderCertificationManifest


def contract_fingerprint(manifest: ProviderCertificationManifest) -> dict[str, Any]:
    """Deterministic, order-independent contract summary for one
    provider manifest. Two manifests with the same contract_fingerprint
    make identical certification promises, even if their prose
    (limitations, evidence notes, display names) differs."""
    completeness = [
        {
            "scope_id": s.scope_id,
            "record_types": sorted(s.record_types),
            "granularity": s.granularity,
            "parent_record_type": s.parent_record_type,
            "derived_dependents": sorted(s.derived_dependents),
        }
        for s in sorted(manifest.completeness_scope_declarations, key=lambda s: s.scope_id)
    ]

    return {
        "provider_id": manifest.provider_id,
        "schema_version": manifest.manifest_version,
        "maturity": manifest.maturity,
        "public": manifest.expected_public,
        "connectable": manifest.expected_connectable,
        "live": manifest.expected_live,
        "reconnect": manifest.expected_reconnect,
        "authentication_model": manifest.authentication_model,
        "credential_fields": sorted(manifest.credential_fields),
        "sensitive_credential_fields": sorted(manifest.sensitive_credential_fields),
        "record_types": sorted(manifest.expected_record_types),
        "derived_record_types": sorted(manifest.derived_record_types),
        "finding_ids": sorted(manifest.security_finding_rule_ids),
        "supported_capabilities": sorted(manifest.supported_capabilities),
        "unsupported_capabilities": sorted(manifest.unsupported_capabilities),
        "completeness_scopes": sorted(manifest.completeness_scopes),
        "false_removal_scopes": sorted(manifest.false_removal_scopes),
        "completeness_scope_declarations": completeness,
        "frontend_form": manifest.expected_frontend_form,
    }


def fingerprint_hash(manifest: ProviderCertificationManifest) -> str:
    """Stable SHA-256 hex digest of contract_fingerprint(), for compact
    before/after comparison. Deterministic across process runs and
    independent of dict insertion order (json.dumps sort_keys=True)."""
    payload = json.dumps(contract_fingerprint(manifest), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def fingerprints_equal(a: ProviderCertificationManifest, b: ProviderCertificationManifest) -> bool:
    return contract_fingerprint(a) == contract_fingerprint(b)


def diff_fingerprints(before: dict[str, Any], after: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Field-level diff between two contract_fingerprint() dicts.
    Returns only fields that differ, each as {"before": ..., "after": ...}."""
    changed: dict[str, dict[str, Any]] = {}
    keys = set(before) | set(after)
    for key in sorted(keys):
        b_val = before.get(key)
        a_val = after.get(key)
        if b_val != a_val:
            changed[key] = {"before": b_val, "after": a_val}
    return changed
