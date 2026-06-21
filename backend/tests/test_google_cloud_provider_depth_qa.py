"""Google Cloud provider depth QA.

Durable, mostly-static guardrails that pin the full Google Cloud rule
taxonomy across every registration surface and validate the privacy /
claim-discipline invariants for the Google Cloud provider:

  TestGoogleCloudRuleRegistration    — all 22 Google Cloud rule keys present
                                       in the module export, registry,
                                       confidence map, rule pack, and
                                       coverage service.
  TestGoogleCloudFrontendCatalogParity — all 22 keys appear in the TypeScript
                                       securityRuleCatalog.ts with matching
                                       severities.
  TestGoogleCloudEvidenceSafety      — fired-rule evidence is flat and carries
                                       no secret / token / PII / raw keys.
  TestGoogleCloudCopySafety          — rule copy carries no forbidden
                                       (breach-style) wording.
  TestGoogleCloudCanonicalProviderKey — the canonical provider key is
                                       "google_cloud"; "gcp" is never used as a
                                       provider key.
  TestGoogleCloudExpansionFramework  — expansion framework still points at
                                       M89A Kubernetes; Google Cloud is not the
                                       next stage.
  TestGoogleCloudProviderCapabilityMatrix — Google Cloud is implemented;
                                       Kubernetes is not yet implemented.

Pure unit tests: the registry / catalog / copy / severity checks read Python
dicts and the TypeScript catalog as text and require no database connection.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import Any

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend" / "app"
FRONTEND = REPO_ROOT / "frontend" / "src"

GOOGLE_CLOUD_RULES_FILE = BACKEND / "services" / "security_rules" / "google_cloud.py"
FE_RULE_CATALOG = FRONTEND / "lib" / "securityRuleCatalog.ts"

CANONICAL_PROVIDER = "google_cloud"

# ── Canonical Google Cloud rule set (the 22 shipped rules) ────────────────────

ALL_GOOGLE_CLOUD_RULE_KEYS: frozenset[str] = frozenset({
    # IAM
    "google_cloud_iam_public_member",
    "google_cloud_iam_broad_privileged_role",
    # Firewall
    "google_cloud_firewall_public_admin_ingress",
    "google_cloud_firewall_public_broad_ingress",
    "google_cloud_firewall_rule_no_targets",
    # Cloud Storage
    "google_cloud_storage_public_access_prevention_disabled",
    "google_cloud_storage_uniform_access_disabled",
    "google_cloud_storage_versioning_disabled",
    "google_cloud_storage_retention_not_locked",
    # Cloud SQL
    "google_cloud_sql_public_network_access",
    "google_cloud_sql_weak_tls",
    "google_cloud_sql_backups_disabled",
    "google_cloud_sql_deletion_protection_disabled",
    # Cloud Run
    "google_cloud_run_public_invoker",
    "google_cloud_run_all_ingress",
    # GKE
    "google_cloud_gke_public_control_plane",
    "google_cloud_gke_legacy_abac_enabled",
    "google_cloud_gke_network_policy_disabled",
    "google_cloud_gke_workload_identity_disabled",
    # Service account keys
    "google_cloud_service_account_user_managed_keys",
    "google_cloud_service_account_old_keys",
    # Secret Manager
    "google_cloud_secret_manager_auto_replication_without_cmek",
})

# Forbidden claim phrases — never in Google Cloud rule code or user-facing copy.
FORBIDDEN_PHRASES = [
    "breach confirmed",
    "compromise confirmed",
    "attacker found",
    "someone has access",
    "data leaked",
    "secret leaked",
    "customer data exposed",
    "unauthorized access confirmed",
    "payment fraud detected",
    "attack detected",
    "data exposure confirmed",
    "publicly exposed data",
]

# Evidence dicts must never carry secret-bearing / PII-bearing / raw keys.
FORBIDDEN_EVIDENCE_KEYS = [
    "private_key",
    "access_token",
    "refresh_token",
    "jwt",
    "api_key",
    "authorization",
    "headers",
    "payload",
    "request",
    "response",
    "raw",
    "secret_value",
    "connection_string",
    "user_email",
    "user_name",
    "ip_address",
    "caller_ip",
    "principal_email",
    "service_account_email",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rule_key(f: Any) -> str:
    return f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")


def _severity(f: Any) -> str:
    return f.severity if hasattr(f, "severity") else f.get("severity", "")


def _evidence(f: Any) -> dict:
    ev = f.evidence if hasattr(f, "evidence") else f.get("evidence", {})
    return ev if isinstance(ev, dict) else {}


def _title(f: Any) -> str:
    return (f.title if hasattr(f, "title") else f.get("title", "")) or ""


def _description(f: Any) -> str:
    return (f.description if hasattr(f, "description") else f.get("description", "")) or ""


def _gc_eval(record: dict) -> list[Any]:
    from app.services.security_rules.google_cloud import evaluate
    return evaluate(record)


def _all_google_cloud_findings() -> list[Any]:
    """Fire every Google Cloud rule across a set of representative risky records.

    Field names mirror the canonical connector-normalizer schema consumed by
    ``security_rules.google_cloud.evaluate`` (as exercised by the M78B/M78C
    unit tests).
    """
    from app.connectors.google_cloud_schema import (
        GOOGLE_CLOUD_FIREWALL_RULE,
        GOOGLE_CLOUD_GKE_CLUSTER,
        GOOGLE_CLOUD_IAM_POLICY_SUMMARY,
        GOOGLE_CLOUD_RUN_SERVICE,
        GOOGLE_CLOUD_SECRET_MANAGER_SUMMARY,
        GOOGLE_CLOUD_SERVICE_ACCOUNT_KEY_SUMMARY,
        GOOGLE_CLOUD_SQL_INSTANCE,
        GOOGLE_CLOUD_STORAGE_BUCKET,
    )

    records: list[dict] = [
        # IAM: public member (allUsers) + broad privileged role.
        {
            "record_type": GOOGLE_CLOUD_IAM_POLICY_SUMMARY,
            "record_id": "iam-summary-1",
            "project_id": "demo-proj-1",
            "binding_count": 3,
            "role_count": 3,
            "role_names": ["roles/owner", "roles/editor"],
            "broad_role_count": 2,
            "user_member_count": 1,
            "service_account_member_count": 2,
            "allusers_binding_present": True,
            "allauthenticatedusers_binding_present": True,
            "conditional_binding_count": 0,
        },
        # Firewall: public admin (22) ingress; broad (all ports) ingress; no
        # targets — three rules fire on one open-ingress record.
        {
            "record_type": GOOGLE_CLOUD_FIREWALL_RULE,
            "record_id": "fw-open",
            "firewall_name": "fw-open",
            "network_name": "vpc-1",
            "project_id": "demo-proj-1",
            "direction": "INGRESS",
            "priority": 1000,
            "disabled": False,
            "source_ranges_summary": ["0.0.0.0/0"],
            "destination_ranges_summary": [],
            "allowed_summary": [
                {"protocol": "tcp", "ports": ["22"]},
                {"protocol": "all", "ports": []},
            ],
            "denied_summary": [],
            "target_tag_count": 0,
            "target_service_account_count": 0,
            "has_log_config": False,
        },
        # Cloud Storage: PAP not enforced + uniform access off + versioning off
        # + retention policy present but not locked.
        {
            "record_type": GOOGLE_CLOUD_STORAGE_BUCKET,
            "record_id": "bucket-1",
            "bucket_name": "demo-bucket-1",
            "location": "US",
            "storage_class": "STANDARD",
            "uniform_bucket_level_access_enabled": False,
            "public_access_prevention": "inherited",
            "versioning_enabled": False,
            "retention_policy_seconds": "604800",
            "retention_policy_locked": False,
            "lifecycle_rule_count": 1,
            "encryption_default_kms_key_present": False,
        },
        # Cloud SQL: public network + weak TLS + backups off + no deletion prot.
        {
            "record_type": GOOGLE_CLOUD_SQL_INSTANCE,
            "record_id": "sql-1",
            "instance_name": "test-instance",
            "project_id": "demo-proj-1",
            "database_version": "POSTGRES_15",
            "region": "us-central1",
            "state": "RUNNABLE",
            "public_ip_enabled": True,
            "authorized_network_count": 2,
            "require_ssl": False,
            "ssl_mode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
            "backup_enabled": False,
            "deletion_protection_enabled": False,
        },
        # Cloud Run: public invoker + all ingress.
        {
            "record_type": GOOGLE_CLOUD_RUN_SERVICE,
            "record_id": "run-1",
            "service_name": "my-service",
            "project_id": "demo-proj-1",
            "region": "us-central1",
            "ingress": "INGRESS_TRAFFIC_ALL",
            "launch_stage": "GA",
            "public_invoker_allowed": True,
            "invoker_policy_summary": {"invoker_binding_count": 1},
            "environment_variable_count": 2,
            "secret_environment_variable_count": 1,
        },
        # GKE: public control plane + legacy ABAC + no network policy + no WI.
        {
            "record_type": GOOGLE_CLOUD_GKE_CLUSTER,
            "record_id": "gke-1",
            "cluster_name": "my-cluster",
            "project_id": "demo-proj-1",
            "location": "us-central1",
            "private_cluster_enabled": False,
            "master_authorized_networks_count": 0,
            "network_policy_enabled": False,
            "workload_identity_enabled": False,
            "shielded_nodes_enabled": False,
            "legacy_abac_enabled": True,
            "public_endpoint_enabled": True,
            "release_channel": "REGULAR",
        },
        # Service account keys: user-managed keys + old keys.
        {
            "record_type": GOOGLE_CLOUD_SERVICE_ACCOUNT_KEY_SUMMARY,
            "record_id": "sa-key-summary-1",
            "project_id": "demo-proj-1",
            "service_account_count": 5,
            "disabled_service_account_count": 0,
            "user_managed_key_count": 5,
            "old_user_managed_key_count": 2,
            "oldest_key_age_days": 400,
        },
        # Secret Manager: automatic replication without CMEK.
        {
            "record_type": GOOGLE_CLOUD_SECRET_MANAGER_SUMMARY,
            "record_id": "secret-mgr-summary-1",
            "project_id": "demo-proj-1",
            "secret_count": 5,
            "automatic_replication_count": 3,
            "user_managed_replication_count": 2,
            "customer_managed_encryption_count": 0,
        },
    ]
    out: list[Any] = []
    for r in records:
        out.extend(_gc_eval(r))
    return out


# ── TestGoogleCloudRuleRegistration ───────────────────────────────────────────

class TestGoogleCloudRuleRegistration:
    def test_rule_key_count_is_twenty_two(self) -> None:
        assert len(ALL_GOOGLE_CLOUD_RULE_KEYS) == 22

    def test_module_export_matches_canonical_set(self) -> None:
        from app.services.security_rules.google_cloud import GOOGLE_CLOUD_RULE_KEYS
        assert set(GOOGLE_CLOUD_RULE_KEYS) == ALL_GOOGLE_CLOUD_RULE_KEYS

    def test_all_keys_in_registry(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for key in ALL_GOOGLE_CLOUD_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS, f"{key!r} missing from KNOWN_RULE_KEYS"

    def test_all_keys_in_confidence(self) -> None:
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for key in ALL_GOOGLE_CLOUD_RULE_KEYS:
            assert key in RULE_CONFIDENCE, f"{key!r} missing from RULE_CONFIDENCE"

    def test_all_keys_in_rule_pack(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_GOOGLE_CLOUD_RULE_KEYS:
            assert key in _RULE_META, f"{key!r} missing from _RULE_META"
            provider, _sev, _cat = _RULE_META[key]
            assert provider == CANONICAL_PROVIDER, (
                f"{key!r} wrong provider: {provider!r}"
            )

    def test_all_keys_in_coverage(self) -> None:
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in ALL_GOOGLE_CLOUD_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, f"{key!r} missing from RULE_RECORD_TYPES"
            assert RULE_RECORD_TYPES[key], f"{key!r} has empty record-type tuple"

    def test_registry_has_no_unexpected_google_cloud_keys(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        reg = {k for k in KNOWN_RULE_KEYS if k.startswith("google_cloud")}
        extra = reg - ALL_GOOGLE_CLOUD_RULE_KEYS
        assert not extra, f"unexpected google_cloud keys in registry: {sorted(extra)}"


# ── TestGoogleCloudFrontendCatalogParity ──────────────────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
class TestGoogleCloudFrontendCatalogParity:
    def _catalog_text(self) -> str:
        return FE_RULE_CATALOG.read_text(encoding="utf-8")

    def test_all_keys_present_in_catalog(self) -> None:
        text = self._catalog_text()
        missing = [k for k in ALL_GOOGLE_CLOUD_RULE_KEYS if f'key: "{k}"' not in text]
        assert not missing, (
            f"Google Cloud rule keys missing from frontend catalog: {missing}"
        )

    def test_catalog_keys_match_via_regex(self) -> None:
        text = self._catalog_text()
        found = set(re.findall(r'key:\s*"(google_cloud_[a-z0-9_]+)"', text))
        missing = ALL_GOOGLE_CLOUD_RULE_KEYS - found
        assert not missing, (
            f"Regex did not find Google Cloud keys in catalog: {sorted(missing)}"
        )

    def test_catalog_has_no_unexpected_google_cloud_keys(self) -> None:
        text = self._catalog_text()
        found = set(re.findall(r'key:\s*"(google_cloud_[a-z0-9_]+)"', text))
        extra = found - ALL_GOOGLE_CLOUD_RULE_KEYS
        assert not extra, (
            f"Unexpected google_cloud keys in frontend catalog: {sorted(extra)}"
        )

    def test_catalog_severity_matches_backend_pack(self) -> None:
        text = self._catalog_text()
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_GOOGLE_CLOUD_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            assert idx != -1, f"Google Cloud rule {key!r} not found in frontend catalog"
            block = text[idx:idx + 900]
            _provider, expected_sev, _cat = _RULE_META[key]
            assert f'severity: "{expected_sev}"' in block, (
                f"Frontend severity for {key!r} does not match backend "
                f"({expected_sev!r})"
            )

    def test_catalog_provider_is_canonical(self) -> None:
        text = self._catalog_text()
        for key in ALL_GOOGLE_CLOUD_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            block = text[idx:idx + 900]
            assert 'provider: "google_cloud"' in block, (
                f"Frontend catalog entry for {key!r} must use provider "
                f'"google_cloud" (never "gcp")'
            )


# ── TestGoogleCloudEvidenceSafety ─────────────────────────────────────────────

class TestGoogleCloudEvidenceSafety:
    def test_synthetic_records_fire_every_rule(self) -> None:
        fired = {_rule_key(f) for f in _all_google_cloud_findings()}
        missing = ALL_GOOGLE_CLOUD_RULE_KEYS - fired
        assert not missing, f"Synthetic records did not fire rules: {sorted(missing)}"

    def test_evidence_has_no_forbidden_keys(self) -> None:
        findings = _all_google_cloud_findings()
        assert findings, "expected at least one finding across representative records"
        for f in findings:
            # Collect keys at the top level and one level of nested summary
            # dicts (e.g. invoker_policy_summary is a small counts-only dict).
            ev = _evidence(f)
            all_keys = {k.lower() for k in ev}
            for v in ev.values():
                if isinstance(v, dict):
                    all_keys |= {k.lower() for k in v}
            for forbidden in FORBIDDEN_EVIDENCE_KEYS:
                assert forbidden not in all_keys, (
                    f"Forbidden evidence key {forbidden!r} in finding "
                    f"{_rule_key(f)!r}: {sorted(all_keys)}"
                )

    def test_evidence_is_flat_safe_scalars(self) -> None:
        # Google Cloud evidence is metadata-only: scalars, lists of scalars, or
        # at most one level of nested counts-only summary dicts.
        def _is_safe_scalar(x: Any) -> bool:
            return isinstance(x, (str, int, float, bool, type(None)))

        for f in _all_google_cloud_findings():
            for k, v in _evidence(f).items():
                if _is_safe_scalar(v):
                    continue
                if isinstance(v, list):
                    for item in v:
                        assert _is_safe_scalar(item) or isinstance(item, dict), (
                            f"Unsafe list item in {_rule_key(f)!r} key {k!r}: "
                            f"{type(item).__name__}"
                        )
                        if isinstance(item, dict):
                            for iv in item.values():
                                assert _is_safe_scalar(iv) or isinstance(iv, list), (
                                    f"Nested non-scalar in {_rule_key(f)!r} key {k!r}"
                                )
                    continue
                if isinstance(v, dict):
                    for nv in v.values():
                        assert _is_safe_scalar(nv) or isinstance(nv, list), (
                            f"Nested non-scalar evidence value in "
                            f"{_rule_key(f)!r} key {k!r}: {type(nv).__name__}"
                        )
                    continue
                raise AssertionError(
                    f"Non-scalar evidence value in {_rule_key(f)!r} key {k!r}: "
                    f"{type(v).__name__}"
                )


# ── TestGoogleCloudCopySafety ─────────────────────────────────────────────────

class TestGoogleCloudCopySafety:
    def test_no_forbidden_wording_in_rules_module(self) -> None:
        from app.services.security_rules import google_cloud as gc_rules
        src = inspect.getsource(gc_rules).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in src, (
                f"forbidden phrase {phrase!r} present in security_rules.google_cloud"
            )

    def test_no_forbidden_wording_in_finding_copy(self) -> None:
        for f in _all_google_cloud_findings():
            blob = f"{_title(f)}\n{_description(f)}".lower()
            for phrase in FORBIDDEN_PHRASES:
                assert phrase not in blob, (
                    f"Finding {_rule_key(f)!r} copy contains forbidden phrase "
                    f"{phrase!r}"
                )


# ── TestGoogleCloudCanonicalProviderKey ───────────────────────────────────────

class TestGoogleCloudCanonicalProviderKey:
    def test_pack_uses_google_cloud_never_gcp(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        gcp_keys = [k for k, (p, _s, _c) in _RULE_META.items() if p == "gcp"]
        assert not gcp_keys, f"rule pack must not use provider 'gcp': {gcp_keys}"

    def test_all_google_cloud_findings_use_canonical_provider(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_GOOGLE_CLOUD_RULE_KEYS:
            provider, _sev, _cat = _RULE_META[key]
            assert provider == CANONICAL_PROVIDER, (
                f"{key!r} provider is {provider!r}, expected 'google_cloud'"
            )

    def test_capability_matrix_has_no_gcp_alias(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        assert get_provider_capability("gcp") is None, (
            "capability matrix must not register a 'gcp' alias provider"
        )


# ── TestGoogleCloudExpansionFramework ─────────────────────────────────────────

class TestGoogleCloudExpansionFramework:
    def test_planned_next_stage_points_at_kubernetes(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        stage = get_framework()["summary"]["planned_next_stage"]
        assert "M89A" in stage, f"planned_next_stage should contain M89A, got {stage!r}"
        assert "Kubernetes" in stage, (
            f"planned_next_stage should contain Kubernetes, got {stage!r}"
        )

    def test_google_cloud_is_not_the_next_stage(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        stage = get_framework()["summary"]["planned_next_stage"].lower()
        assert "google" not in stage and "google_cloud" not in stage, (
            f"Google Cloud must not be the planned_next_stage, got {stage!r}"
        )

    def test_google_cloud_not_in_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import (
            get_next_provider_recommendations,
        )
        providers = [r["provider"] for r in get_next_provider_recommendations()]
        assert CANONICAL_PROVIDER not in providers, (
            "Google Cloud has launched and must not be in the recommended queue"
        )

    def test_kubernetes_is_head_of_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import (
            RECOMMENDED_NEXT_PROVIDERS,
        )
        head = RECOMMENDED_NEXT_PROVIDERS[0]
        assert head.provider == "kubernetes"


# ── TestGoogleCloudProviderCapabilityMatrix ───────────────────────────────────

class TestGoogleCloudProviderCapabilityMatrix:
    def test_google_cloud_present_with_expected_capabilities(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability(CANONICAL_PROVIDER)
        assert cap is not None, "Google Cloud missing from provider capability matrix"
        assert cap.provider == CANONICAL_PROVIDER
        # security_rules capability present.
        assert cap.security.security_rules is True
        # drift detection (snapshots + diff + risk classification) present.
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True

    def test_kubernetes_is_not_yet_implemented(self) -> None:
        """Guard against accidental introduction of a Kubernetes provider."""
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        assert get_provider_capability("kubernetes") is None, (
            "Kubernetes must not be implemented yet — it is still in the "
            "recommended-next queue"
        )
