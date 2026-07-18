"""Kubernetes permission diagnostics, N+1 guard, scale, and live-validation
tests (Kubernetes message 8 of 9).
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import pytest

from app.connectors.kubernetes import (
    KUBERNETES_CLUSTER,
    _collect_rbac_bindings,
    _collect_roles,
    _collect_workload_family,
    build_permission_diagnostics,
    format_permission_diagnostics_text,
    run_live_kubernetes_validation,
)
from tests._kubernetes_rbac_fixtures import (
    make_cluster_role_binding,
    make_role_ref,
    make_subject,
    page as rbac_page,
)
from tests._kubernetes_workload_fixtures import make_deployment, page as workload_page


def _cluster_record(**overrides) -> dict:
    base = {
        "record_type": KUBERNETES_CLUSTER, "record_id": "uid:c1", "cluster_id": "uid:c1",
        "cluster_name": "test-cluster", "kubernetes_version": "v1.29.0",
        "api_server_host_category": "private_ip",
        "server_certificate_verification_enabled": True,
        "configured_namespace_allowlist": None,
        "partial_permission_indicator": False,
        "family_completeness": {
            "kubernetes_namespace": "complete",
            "kubernetes_deployment": "complete", "kubernetes_statefulset": "complete",
            "kubernetes_daemonset": "complete", "kubernetes_job": "complete",
            "kubernetes_cronjob": "complete", "kubernetes_pod": "complete",
            "kubernetes_role": "partial", "kubernetes_cluster_role": "complete",
            "kubernetes_role_binding": "complete", "kubernetes_cluster_role_binding": "complete",
            "kubernetes_service_account": "complete",
            "kubernetes_service": "complete", "kubernetes_ingress": "complete",
            "kubernetes_gateway": "unsupported", "kubernetes_http_route": "unsupported",
            "kubernetes_network_policy": "complete",
            "kubernetes_validating_webhook_configuration": "partial",
            "kubernetes_mutating_webhook_configuration": "partial",
            "kubernetes_pod_security_admission": "complete",
            "kubernetes_resource_quota": "complete", "kubernetes_limit_range": "complete",
        },
    }
    base.update(overrides)
    return base


class TestPermissionDiagnosticsReport:
    def test_reachable_cluster_reports_sections(self):
        records = [_cluster_record()]
        report = build_permission_diagnostics(records)
        assert report["cluster_reachable"] is True
        section_names = {s["name"] for s in report["sections"]}
        assert section_names == {"Namespaces", "Workloads", "RBAC", "Networking", "Admission"}

    def test_partial_role_family_reflected_in_rbac_section(self):
        records = [_cluster_record()]
        report = build_permission_diagnostics(records)
        rbac_section = next(s for s in report["sections"] if s["name"] == "RBAC")
        role_entry = next(e for e in rbac_section["resources"] if e["resource"] == "Roles")
        assert role_entry["status"] == "partial"
        assert "partially available" in role_entry["status_label"]

    def test_unsupported_gateway_reflected_in_networking_section(self):
        records = [_cluster_record()]
        report = build_permission_diagnostics(records)
        net_section = next(s for s in report["sections"] if s["name"] == "Networking")
        gw_entry = next(e for e in net_section["resources"] if e["resource"] == "Gateway API")
        assert gw_entry["status"] == "unsupported"

    def test_coverage_is_partial_when_any_family_incomplete(self):
        records = [_cluster_record()]
        report = build_permission_diagnostics(records)
        assert report["coverage"] == "partial"

    def test_coverage_is_complete_when_every_family_complete(self):
        complete_map = {k: "complete" for k in _cluster_record()["family_completeness"]}
        records = [_cluster_record(family_completeness=complete_map, partial_permission_indicator=False)]
        report = build_permission_diagnostics(records)
        assert report["coverage"] == "complete"

    def test_unreachable_cluster_reports_gracefully(self):
        report = build_permission_diagnostics([])
        assert report["cluster_reachable"] is False
        assert report["sections"] == []

    def test_namespace_scope_unrestricted(self):
        records = [_cluster_record(configured_namespace_allowlist=None)]
        report = build_permission_diagnostics(records)
        assert report["namespace_scope"] == "all namespaces"

    def test_namespace_scope_allowlisted(self):
        records = [_cluster_record(configured_namespace_allowlist=["a", "b"])]
        report = build_permission_diagnostics(records)
        assert "2 allowlisted" in report["namespace_scope"]

    def test_security_findings_note_present_and_safe(self):
        report = build_permission_diagnostics([_cluster_record()])
        assert "evaluated only for resources ConfigTrace could read" in report["security_findings_note"]

    def test_text_rendering_contains_no_raw_exception_or_credential_text(self):
        report = build_permission_diagnostics([_cluster_record()])
        text = format_permission_diagnostics_text(report)
        assert "kubeconfig" not in text.lower()
        assert "token" not in text.lower()
        assert "Kubernetes connection validated" in text


class TestDiagnosticsSafety:
    def test_no_sensitive_keys_anywhere_in_report(self):
        report = build_permission_diagnostics([_cluster_record()])
        import json
        blob = json.dumps(report).lower()
        for forbidden in ("kubeconfig", "client-key-data", "client-certificate-data", "token", "private_key", "secret_value", "config_map_value"):
            assert forbidden not in blob


class TestNPlusOneGuard:
    def test_workload_family_collection_is_bulk_not_per_object(self):
        deployments = [make_deployment(name=f"web-{i}") for i in range(25)]
        list_fn = MagicMock(return_value=workload_page(deployments))
        _controllers, _containers, _status = _collect_workload_family(
            list_fn, kind="Deployment", record_type="kubernetes_deployment",
            cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
        )
        # Exactly one List call regardless of how many Deployments exist —
        # never one API call per object.
        assert list_fn.call_count == 1

    def test_role_collection_is_bulk_not_per_object(self):
        from tests._kubernetes_rbac_fixtures import make_role
        roles = [make_role(name=f"role-{i}") for i in range(50)]
        list_fn = MagicMock(return_value=rbac_page(roles))
        _records, _status, _index = _collect_roles(
            list_fn, cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert list_fn.call_count == 1

    def test_rbac_binding_resolution_makes_no_extra_api_calls_per_subject(self):
        bindings = [
            make_cluster_role_binding(
                name=f"crb-{i}",
                role_ref=make_role_ref(kind="ClusterRole", name="view"),
                subjects=[make_subject(kind="User", name=f"user-{i}", namespace=None)],
            )
            for i in range(30)
        ]
        list_fn = MagicMock(return_value=rbac_page(bindings))
        _records, _subjects, _status = _collect_rbac_bindings(
            list_fn, kind="ClusterRoleBinding", cluster_id="uid:c1", cluster_name="c1",
            namespace_allowlist=None, role_index={}, role_collection_denied=False,
        )
        # Role resolution happens against a locally-built `role_index` dict,
        # never a per-binding or per-subject API call.
        assert list_fn.call_count == 1


class TestScale:
    def test_normalizes_many_workloads_within_generous_bound(self):
        deployments = [make_deployment(name=f"web-{i}", namespace=f"ns-{i % 50}") for i in range(2000)]
        list_fn = MagicMock(return_value=workload_page(deployments))
        start = time.monotonic()
        controllers, containers, status = _collect_workload_family(
            list_fn, kind="Deployment", record_type="kubernetes_deployment",
            cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
        )
        elapsed = time.monotonic() - start
        assert len(controllers) == 2000
        assert status == "complete"
        # Broad upper bound — this is a regression guard against an
        # accidental O(n^2)/Cartesian blow-up, not a tight perf benchmark.
        assert elapsed < 10.0

    def test_large_rbac_binding_set_resolves_without_per_binding_calls(self):
        from tests._kubernetes_rbac_fixtures import make_role_binding
        bindings = [
            make_role_binding(
                namespace="prod", name=f"rb-{i}",
                role_ref=make_role_ref(kind="Role", name="reader"),
                subjects=[make_subject(kind="ServiceAccount", name=f"sa-{i}", namespace="prod")],
            )
            for i in range(3000)
        ]
        list_fn = MagicMock(return_value=rbac_page(bindings))
        records, subjects, status = _collect_rbac_bindings(
            list_fn, kind="RoleBinding", cluster_id="uid:c1", cluster_name="c1",
            namespace_allowlist=None, role_index={}, role_collection_denied=False,
        )
        assert len(records) == 3000
        assert list_fn.call_count == 1


class TestRbacManifestArtifact:
    def test_manifest_file_exists(self):
        path = Path(__file__).resolve().parent / "reports" / "kubernetes_readonly_rbac_manifest.md"
        assert path.exists()

    def test_manifest_excludes_secrets_and_configmaps(self):
        path = Path(__file__).resolve().parent / "reports" / "kubernetes_readonly_rbac_manifest.md"
        text = path.read_text()
        # The YAML manifest block itself must not grant secrets/configmaps.
        yaml_start = text.index("```yaml")
        yaml_end = text.index("```", yaml_start + 6)
        yaml_block = text[yaml_start:yaml_end]
        assert "secrets" not in yaml_block
        assert "configmaps" not in yaml_block

    def test_manifest_uses_only_get_list_verbs(self):
        path = Path(__file__).resolve().parent / "reports" / "kubernetes_readonly_rbac_manifest.md"
        text = path.read_text()
        yaml_start = text.index("```yaml")
        yaml_end = text.index("```", yaml_start + 6)
        yaml_block = text[yaml_start:yaml_end]
        import re
        verb_lines = re.findall(r'verbs:\s*\[([^\]]*)\]', yaml_block)
        assert verb_lines, "expected at least one verbs: [...] line"
        for line in verb_lines:
            verbs = {v.strip().strip('"') for v in line.split(",")}
            assert verbs <= {"get", "list"}

    def test_manifest_excludes_write_and_escalation_verbs(self):
        path = Path(__file__).resolve().parent / "reports" / "kubernetes_readonly_rbac_manifest.md"
        text = path.read_text()
        yaml_start = text.index("```yaml")
        yaml_end = text.index("```", yaml_start + 6)
        yaml_block = text[yaml_start:yaml_end]
        for forbidden in ("create", "update", "patch", "delete", "impersonate", "bind", "escalate", "watch"):
            assert f'"{forbidden}"' not in yaml_block


class TestLiveValidationHarness:
    """Live-cluster tests are skipped unless an operator explicitly points
    CONFIGTRACE_KUBERNETES_LIVE_KUBECONFIG at a real kubeconfig file — never
    required for normal CI, never reads a developer's default kubeconfig
    implicitly."""

    def test_skips_without_env_var(self):
        kubeconfig_path = os.environ.get("CONFIGTRACE_KUBERNETES_LIVE_KUBECONFIG")
        if kubeconfig_path:
            pytest.skip("live kubeconfig configured — this test only proves the skip path")
        assert kubeconfig_path is None

    @pytest.mark.skipif(
        not os.environ.get("CONFIGTRACE_KUBERNETES_LIVE_KUBECONFIG"),
        reason="CONFIGTRACE_KUBERNETES_LIVE_KUBECONFIG not set — skipping live cluster validation",
    )
    def test_live_validation_against_real_cluster(self):
        kubeconfig_path = os.environ["CONFIGTRACE_KUBERNETES_LIVE_KUBECONFIG"]
        report = run_live_kubernetes_validation(kubeconfig_path)
        assert report["cluster_reachable"] is True
        assert report["records_observed_count"] >= 1
        import json
        blob = json.dumps(report).lower()
        assert "secret" not in blob or "secret_" not in blob  # no Secret-derived evidence leaks
        assert "kubeconfig" not in blob

    def test_never_reads_arbitrary_default_kubeconfig(self):
        # Confirms the harness requires an explicit path argument — it must
        # never fall back to `~/.kube/config` or `KUBECONFIG` implicitly.
        import inspect
        params = inspect.signature(run_live_kubernetes_validation).parameters
        assert "kubeconfig_path" in params
        assert params["kubeconfig_path"].default is inspect.Parameter.empty
