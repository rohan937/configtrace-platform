"""Kubernetes workload collection tests (Kubernetes message 2 of 9).

Covers collection of Deployments, StatefulSets, DaemonSets, Jobs, CronJobs,
and standalone Pods: per-family fail-soft behavior, namespace allowlist
application, pagination reuse, deterministic ordering, stable record IDs,
malformed-object isolation, and the sensitive-data exclusion contract for
env values, command/args, Secret/ConfigMap references, arbitrary
labels/annotations, and image-pull-secret names.

All tests are pure-mock; no real Kubernetes cluster is contacted.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from kubernetes.client.rest import ApiException

from app.connectors.kubernetes import (
    KUBERNETES_CRONJOB,
    KUBERNETES_DAEMONSET,
    KUBERNETES_DEPLOYMENT,
    KUBERNETES_JOB,
    KUBERNETES_STATEFULSET,
    _collect_standalone_pods,
    _collect_workload_family,
)
from tests._kubernetes_workload_fixtures import (
    make_container,
    make_cronjob,
    make_daemonset,
    make_deployment,
    make_job,
    make_pod,
    make_pod_spec,
    make_sa_token_volume,
    make_security_context,
    make_statefulset,
    make_volume_mount,
    page,
)

_KIND_BUILDERS = {
    "Deployment": (make_deployment, KUBERNETES_DEPLOYMENT),
    "StatefulSet": (make_statefulset, KUBERNETES_STATEFULSET),
    "DaemonSet": (make_daemonset, KUBERNETES_DAEMONSET),
    "Job": (make_job, KUBERNETES_JOB),
    "CronJob": (make_cronjob, KUBERNETES_CRONJOB),
}


# ── Case A-E: safe baseline collection per family ────────────────────────────

class TestPerFamilyCollection:
    @pytest.mark.parametrize("kind", ["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"])
    def test_family_collects_and_normalizes(self, kind):
        builder, record_type = _KIND_BUILDERS[kind]
        obj = builder()
        list_fn = MagicMock(return_value=page([obj]))

        controllers, containers, status = _collect_workload_family(
            list_fn, kind=kind, record_type=record_type,
            cluster_id="uid:c1", cluster_name="test-cluster", namespace_allowlist=None,
        )

        assert status == "complete"
        assert len(controllers) == 1
        assert controllers[0]["record_type"] == record_type
        assert controllers[0]["kind"] == kind
        assert len(containers) == 1
        assert containers[0]["parent_record_id"] == controllers[0]["record_id"]


# ── Case F, G: standalone Pod policy ──────────────────────────────────────────

class TestPodEmissionPolicy:
    def test_standalone_pod_is_emitted(self):
        pod = make_pod(owner_references=[])
        list_fn = MagicMock(return_value=page([pod]))
        pods, containers, status = _collect_standalone_pods(
            list_fn, cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert len(pods) == 1
        assert pods[0]["record_type"] == "kubernetes_pod"
        assert len(containers) == 1

    def test_controller_owned_pod_is_not_emitted_as_its_own_record(self):
        # Owned by a ReplicaSet — the controller family's template already
        # covers this posture; emitting the Pod too would duplicate it.
        owned_pod = make_pod(
            owner_references=[type("Owner", (), {"kind": "ReplicaSet", "name": "web-abc123", "uid": "rs-1"})()]
        )
        list_fn = MagicMock(return_value=page([owned_pod]))
        pods, containers, _status = _collect_standalone_pods(
            list_fn, cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert pods == []
        assert containers == []


# ── Namespace allowlist ───────────────────────────────────────────────────────

class TestNamespaceAllowlist:
    def test_allowlist_restricts_workload_family_collection(self):
        objs = [make_deployment(namespace="prod", name="a"), make_deployment(namespace="staging", name="b")]
        list_fn = MagicMock(return_value=page(objs))
        controllers, _c, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=["prod"],
        )
        assert [c["namespace"] for c in controllers] == ["prod"]

    def test_allowlist_restricts_standalone_pod_collection(self):
        pods = [make_pod(namespace="prod", name="a"), make_pod(namespace="staging", name="b")]
        list_fn = MagicMock(return_value=page(pods))
        collected, _c, _s = _collect_standalone_pods(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=["prod"],
        )
        assert [p["namespace"] for p in collected] == ["prod"]


# ── Fail-soft: one family's failure never affects another ────────────────────

class TestFailSoftIsolation:
    def test_403_on_one_family_does_not_raise_and_reports_partial(self):
        denied = ApiException(status=403, reason="Forbidden")
        list_fn = MagicMock(side_effect=denied)
        controllers, containers, status = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "partial"
        assert controllers == []
        assert containers == []

    def test_absent_api_group_reports_unsupported_not_empty(self):
        not_found = ApiException(status=404, reason="Not Found")
        list_fn = MagicMock(side_effect=not_found)
        _controllers, _containers, status = _collect_workload_family(
            list_fn, kind="CronJob", record_type=KUBERNETES_CRONJOB,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "unsupported"

    def test_one_family_failure_does_not_affect_another(self):
        # Deployments fail; StatefulSets succeed. Each call is independent.
        deny_fn = MagicMock(side_effect=ApiException(status=403))
        ok_fn = MagicMock(return_value=page([make_statefulset()]))

        _dep_controllers, _dep_containers, dep_status = _collect_workload_family(
            deny_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        sts_controllers, _sts_containers, sts_status = _collect_workload_family(
            ok_fn, kind="StatefulSet", record_type=KUBERNETES_STATEFULSET,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert dep_status == "partial"
        assert sts_status == "complete"
        assert len(sts_controllers) == 1

    def test_malformed_one_object_does_not_abort_the_family(self):
        good = make_deployment(name="good")
        malformed = object()  # has no .metadata at all
        list_fn = MagicMock(return_value=page([malformed, good]))
        controllers, _containers, status = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert len(controllers) == 1
        assert controllers[0]["name"] == "good"

    def test_malformed_container_does_not_abort_the_workload(self):
        class _RaisingContainer:
            @property
            def name(self):
                raise ValueError("malformed container object")

        good_container = make_container(name="good")
        malformed_container = _RaisingContainer()
        spec = make_pod_spec(containers=[malformed_container, good_container])
        deployment = make_deployment(pod_spec=spec)
        list_fn = MagicMock(return_value=page([deployment]))

        controllers, containers, status = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert len(controllers) == 1
        assert len(containers) == 1
        assert containers[0]["container_name"] == "good"


# ── Pagination reuse ──────────────────────────────────────────────────────────

class TestPaginationReuse:
    def test_multiple_pages_are_collected(self):
        pages = [
            page([make_deployment(name="a")], continue_token="tok1"),
            page([make_deployment(name="b")], continue_token=None),
        ]
        list_fn = MagicMock(side_effect=pages)
        controllers, _c, status = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert {c["name"] for c in controllers} == {"a", "b"}

    def test_repeated_continuation_token_does_not_loop_forever(self):
        pages = [
            page([make_deployment(name="a")], continue_token="tok1"),
            page([make_deployment(name="b")], continue_token="tok1"),
        ]
        list_fn = MagicMock(side_effect=pages)
        controllers, _c, status = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "partial"
        assert {c["name"] for c in controllers} == {"a", "b"}  # no duplicates, no crash


# ── Deterministic ordering / stable IDs ──────────────────────────────────────

class TestDeterministicOrderingAndStableIds:
    def test_controller_records_sorted_by_namespace_then_name(self):
        objs = [
            make_deployment(namespace="z-ns", name="a"),
            make_deployment(namespace="a-ns", name="z"),
            make_deployment(namespace="a-ns", name="a"),
        ]
        list_fn = MagicMock(return_value=page(objs))
        controllers, _c, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        keys = [(c["namespace"], c["name"]) for c in controllers]
        assert keys == sorted(keys)

    def test_stable_id_prefers_uid(self):
        obj = make_deployment(namespace="ns", name="web", uid="uid-123")
        list_fn = MagicMock(return_value=page([obj]))
        controllers, _c, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert controllers[0]["record_id"] == "uid:c1/deployment/ns/uid-123"

    def test_name_reused_with_new_uid_is_a_different_record_id(self):
        old = make_deployment(namespace="ns", name="web", uid="uid-old")
        new = make_deployment(namespace="ns", name="web", uid="uid-new")
        list_fn_old = MagicMock(return_value=page([old]))
        list_fn_new = MagicMock(return_value=page([new]))
        old_controllers, _c, _s = _collect_workload_family(
            list_fn_old, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        new_controllers, _c2, _s2 = _collect_workload_family(
            list_fn_new, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert old_controllers[0]["record_id"] != new_controllers[0]["record_id"]

    def test_container_record_id_is_stable_and_namespaced_by_category(self):
        spec = make_pod_spec(
            containers=[make_container(name="app")],
            init_containers=[make_container(name="app")],  # same name, different category
        )
        obj = make_deployment(pod_spec=spec)
        list_fn = MagicMock(return_value=page([obj]))
        _controllers, containers, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        ids = {c["record_id"] for c in containers}
        assert len(ids) == 2  # application/app and init/app never collide


# ── Sensitive-data exclusion ──────────────────────────────────────────────────

class TestSensitiveDataExclusion:
    def _collect_one(self, container, extra_annotations=None, extra_labels=None, volumes=None, image_pull_secrets=None):
        spec = make_pod_spec(
            containers=[container],
            volumes=volumes or [],
            image_pull_secrets=image_pull_secrets or [],
        )
        deployment = make_deployment(pod_spec=spec)
        deployment.spec.template.metadata.annotations = extra_annotations or {}
        deployment.spec.template.metadata.labels = extra_labels or {}
        list_fn = MagicMock(return_value=page([deployment]))
        return _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )

    def test_env_values_never_persisted(self):
        container = make_container(env=[{"name": "DB_PASSWORD", "value": "super-secret-value-12345"}])
        controllers, containers, _s = self._collect_one(container)
        blob = json.dumps(controllers) + json.dumps(containers)
        assert "super-secret-value-12345" not in blob
        assert "DB_PASSWORD" not in blob

    def test_command_and_args_never_persisted(self):
        container = make_container(
            command=["/bin/sh", "-c", "curl secret-endpoint"],
            args=["--api-key=sk-live-abcdef123456"],
        )
        controllers, containers, _s = self._collect_one(container)
        blob = json.dumps(controllers) + json.dumps(containers)
        assert "curl secret-endpoint" not in blob
        assert "sk-live-abcdef123456" not in blob

    def test_secret_and_configmap_key_references_never_persisted(self):
        # Volume-level Secret/ConfigMap names are read only to categorize
        # the mount as "secret"/"configmap" — the referenced object name
        # itself must never appear in any output.
        from tests._kubernetes_workload_fixtures import make_configmap_volume, make_secret_volume

        secret_vol = make_secret_volume("app-secrets")
        cm_vol = make_configmap_volume("app-config")
        container = make_container(
            volume_mounts=[make_volume_mount("app-secrets"), make_volume_mount("app-config")]
        )
        controllers, containers, _s = self._collect_one(container, volumes=[secret_vol, cm_vol])
        blob = json.dumps(controllers) + json.dumps(containers)
        assert "app-secrets-secret" not in blob
        assert "app-config-cm" not in blob

    def test_arbitrary_annotations_never_persisted(self):
        container = make_container()
        controllers, containers, _s = self._collect_one(
            container, extra_annotations={"my-team.example.com/owner": "backend-team-secret-slack-webhook"}
        )
        blob = json.dumps(controllers) + json.dumps(containers)
        assert "backend-team-secret-slack-webhook" not in blob
        assert "my-team.example.com/owner" not in blob

    def test_arbitrary_labels_never_persisted(self):
        container = make_container()
        controllers, containers, _s = self._collect_one(
            container, extra_labels={"internal-build-id": "build-98765-do-not-leak"}
        )
        blob = json.dumps(controllers) + json.dumps(containers)
        assert "build-98765-do-not-leak" not in blob

    def test_image_pull_secret_names_never_persisted_only_count(self):
        pull_secret = type("Ref", (), {"name": "my-registry-credentials"})()
        controllers, _containers, _s = self._collect_one(
            make_container(), image_pull_secrets=[pull_secret]
        )
        assert controllers[0]["image_pull_secret_count"] == 1
        blob = json.dumps(controllers)
        assert "my-registry-credentials" not in blob

    def test_service_account_token_projection_source_path_not_persisted(self):
        sa_vol = make_sa_token_volume()
        container = make_container(volume_mounts=[make_volume_mount(sa_vol.name)])
        controllers, containers, _s = self._collect_one(container, volumes=[sa_vol])
        assert containers[0]["service_account_token_explicitly_mounted"] is True
        blob = json.dumps(containers)
        assert "/token" not in blob and '"path"' not in blob
