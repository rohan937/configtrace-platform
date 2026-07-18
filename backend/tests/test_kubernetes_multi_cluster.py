"""Kubernetes multi-cluster identity safety tests (Kubernetes message 8 of 9).

Verifies cluster identity is stable, collision-free across integrations,
immune to cosmetic changes (context rename, credential rotation for the
SAME cluster), and correctly treats a genuinely recreated cluster (same API
host, new kube-system UID) as a new identity — never merging or
cross-diffing two different clusters' records.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.connectors.kubernetes import compute_cluster_id, normalize_api_server_host
from app.services.diff_service import build_record_index, compute_diff


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


class TestClusterIdentityStability:
    def test_same_uid_same_host_gives_same_id(self):
        id1 = compute_cluster_id(api_server_host="https://api.example.com:6443", kube_system_uid="abc-123")
        id2 = compute_cluster_id(api_server_host="https://api.example.com:6443", kube_system_uid="abc-123")
        assert id1 == id2

    def test_context_name_never_affects_identity(self):
        # Only api_server_host + kube_system_uid feed compute_cluster_id;
        # context_name is a separate, cosmetic display field.
        id1 = compute_cluster_id(api_server_host="https://api.example.com:6443", kube_system_uid="abc-123")
        # No context_name parameter exists on compute_cluster_id at all —
        # this is itself the proof that renaming a kubeconfig context can
        # never change cluster identity.
        import inspect
        params = inspect.signature(compute_cluster_id).parameters
        assert "context_name" not in params
        assert id1.startswith("uid:")

    def test_kube_system_uid_is_primary_identity_not_host(self):
        # Two different hosts, same kube-system UID (e.g. a floating/HA
        # control-plane VIP changed) -> same identity, because the UID is
        # authoritative and the host is only a fallback.
        id1 = compute_cluster_id(api_server_host="https://10.0.0.1:6443", kube_system_uid="same-uid")
        id2 = compute_cluster_id(api_server_host="https://10.0.0.2:6443", kube_system_uid="same-uid")
        assert id1 == id2

    def test_host_fallback_used_only_when_uid_unavailable(self):
        id1 = compute_cluster_id(api_server_host="https://api.example.com:6443", kube_system_uid=None)
        id2 = compute_cluster_id(api_server_host="https://api.example.com:6443", kube_system_uid=None)
        assert id1 == id2
        assert id1.startswith("host:")

    def test_credential_rotation_for_same_cluster_preserves_identity(self):
        # Rotating the bearer token/client cert inside a kubeconfig does not
        # change api_server_host or kube_system_uid, so identity is stable
        # across a credential rotation for the same real cluster.
        id_before = compute_cluster_id(api_server_host="https://api.example.com:6443", kube_system_uid="stable-uid")
        id_after = compute_cluster_id(api_server_host="https://api.example.com:6443", kube_system_uid="stable-uid")
        assert id_before == id_after


class TestClusterRecreation:
    def test_new_kube_system_uid_is_a_new_identity(self):
        old_id = compute_cluster_id(api_server_host="https://api.example.com:6443", kube_system_uid="old-uid")
        new_id = compute_cluster_id(api_server_host="https://api.example.com:6443", kube_system_uid="new-uid")
        assert old_id != new_id

    def test_recreated_cluster_never_cross_diffs_with_old_cluster_records(self):
        # Same host, but the connector recomputes cluster_id from the NEW
        # kube-system UID, so every record_id (which embeds cluster_id) is
        # necessarily different -> compute_diff sees this as an entirely
        # disjoint record set (all "removed" for the old cluster's records,
        # all "added" for the new one), never a field-level diff across
        # clusters.
        old_cluster_id = compute_cluster_id(api_server_host="https://api.example.com:6443", kube_system_uid="old-uid")
        new_cluster_id = compute_cluster_id(api_server_host="https://api.example.com:6443", kube_system_uid="new-uid")

        prev = [{
            "record_type": "kubernetes_role", "record_id": f"{old_cluster_id}/role/prod/reader",
            "cluster_id": old_cluster_id, "cluster_name": "c1", "namespace": "prod", "name": "reader",
            "kind": "Role", "highest_severity_category": "low",
        }]
        new = [{
            "record_type": "kubernetes_role", "record_id": f"{new_cluster_id}/role/prod/reader",
            "cluster_id": new_cluster_id, "cluster_name": "c1", "namespace": "prod", "name": "reader",
            "kind": "Role", "highest_severity_category": "low",
        }]
        changes = compute_diff(_snap(prev), _snap(new))
        change_types = {c["change_type"] for c in changes}
        assert change_types == {"added", "removed"}
        assert not any(c["change_type"] == "modified" for c in changes)


class TestMultiClusterNameCollisionSafety:
    def test_same_namespace_and_resource_name_different_cluster_stay_distinct(self):
        cluster_a = compute_cluster_id(api_server_host="https://a.example.com:6443", kube_system_uid="uid-a")
        cluster_b = compute_cluster_id(api_server_host="https://b.example.com:6443", kube_system_uid="uid-b")
        assert cluster_a != cluster_b

        record_a = {
            "record_type": "kubernetes_service", "record_id": f"{cluster_a}/service/default/api",
            "cluster_id": cluster_a, "cluster_name": "cluster-a", "namespace": "default", "name": "api",
            "exposure_category": "cluster_internal",
        }
        record_b = {
            "record_type": "kubernetes_service", "record_id": f"{cluster_b}/service/default/api",
            "cluster_id": cluster_b, "cluster_name": "cluster-b", "namespace": "default", "name": "api",
            "exposure_category": "cluster_internal",
        }
        index = build_record_index([record_a, record_b])
        # Both must be present under distinct keys — no collision even
        # though namespace+name are identical.
        assert len(index) == 2
        assert record_a["record_id"] in index
        assert record_b["record_id"] in index

    def test_provider_metadata_always_includes_cluster_identity(self):
        from app.services.diff_service import _build_provider_metadata
        record = {
            "record_type": "kubernetes_service", "record_id": "uid:c1/service/default/api",
            "cluster_id": "uid:c1", "cluster_name": "c1", "namespace": "default", "name": "api",
        }
        metadata = _build_provider_metadata(record)
        assert metadata["cluster_id"] == "uid:c1"
        assert metadata["cluster_name"] == "c1"

    def test_diff_never_merges_records_across_clusters_even_with_identical_namespace(self):
        cluster_a = "uid:cluster-a"
        cluster_b = "uid:cluster-b"
        prev = [{
            "record_type": "kubernetes_role", "record_id": f"{cluster_a}/role/prod/reader",
            "cluster_id": cluster_a, "cluster_name": "a", "namespace": "prod", "name": "reader",
            "kind": "Role", "highest_severity_category": "low",
        }]
        new = [{
            "record_type": "kubernetes_role", "record_id": f"{cluster_b}/role/prod/reader",
            "cluster_id": cluster_b, "cluster_name": "b", "namespace": "prod", "name": "reader",
            "kind": "Role", "highest_severity_category": "low",
        }]
        changes = compute_diff(_snap(prev), _snap(new))
        # Distinct record_ids (different cluster prefix) -> one removed +
        # one added, never treated as the same record "modified".
        assert {c["change_type"] for c in changes} == {"added", "removed"}


class TestApiServerHostNormalization:
    def test_normalization_strips_scheme_and_credentials(self):
        assert normalize_api_server_host("https://user:pass@api.example.com:6443/") == "api.example.com:6443"

    def test_normalization_is_case_insensitive(self):
        assert normalize_api_server_host("HTTPS://API.EXAMPLE.COM:6443") == normalize_api_server_host("https://api.example.com:6443")
