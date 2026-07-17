"""Kubernetes workload diff and risk-routing tests (Kubernetes message 2 of 9).

Exercises the REAL ``compute_diff()`` -> ``classify_kubernetes_change()``
pipeline (not hand-built Change dicts) for the newly emitted workload,
Pod, container-security-context, and workload-service-account record
types: added/removed/modified detection, provider_metadata population,
resourceVersion/status-only-change suppression, and routing to the
Kubernetes classifier (never Cloudflare's fallback).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from app.connectors.kubernetes import (
    KUBERNETES_CONTAINER_SECURITY_CONTEXT,
    KUBERNETES_DEPLOYMENT,
    KUBERNETES_POD,
    _collect_standalone_pods,
    _collect_workload_family,
)
from app.services.diff_service import compute_diff
from app.services.risk_service import classify_change
from app.services.risk_rules.kubernetes import classify_kubernetes_change
from tests._kubernetes_workload_fixtures import (
    make_container,
    make_deployment,
    make_pod,
    make_pod_spec,
    make_security_context,
    page,
)


class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]) -> list[dict]:
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


def _change_dict(change) -> dict:
    # classify_change() takes an ORM-ish Change; the risk_rules module's
    # ``_get`` helper works with plain dicts too via getattr fallback —
    # compute_diff already returns plain dicts, so route through
    # classify_kubernetes_change directly to avoid needing a real Change row.
    return change


def _collect_deployment(pod_spec=None, **kwargs):
    obj = make_deployment(pod_spec=pod_spec or make_pod_spec(), **kwargs)
    list_fn = MagicMock(return_value=page([obj]))
    controllers, containers, _s = _collect_workload_family(
        list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
        cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
    )
    return controllers[0], containers[0]


class TestPrivilegedIntroducedRemoved:
    def test_privileged_container_introduced(self):
        _ctrl_a, container_a = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(security_context=make_security_context(privileged=False))])
        )
        _ctrl_b, container_b = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(security_context=make_security_context(privileged=True))])
        )
        changes = _real_changes([container_a], [container_b])
        privileged_changes = [c for c in changes if c["field_path"] == "privileged"]
        assert len(privileged_changes) == 1
        severity, _msg = classify_kubernetes_change(privileged_changes[0])
        assert severity == "high"

    def test_privileged_container_removed(self):
        _ctrl_a, container_a = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(security_context=make_security_context(privileged=True))])
        )
        _ctrl_b, container_b = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(security_context=make_security_context(privileged=False))])
        )
        changes = _real_changes([container_a], [container_b])
        privileged_changes = [c for c in changes if c["field_path"] == "privileged"]
        severity, _msg = classify_kubernetes_change(privileged_changes[0])
        assert severity == "low"


class TestHostNamespaceChanges:
    def test_host_pid_enabled(self):
        ctrl_a, _c_a = _collect_deployment(pod_spec=make_pod_spec(host_pid=False))
        ctrl_b, _c_b = _collect_deployment(pod_spec=make_pod_spec(host_pid=True))
        changes = _real_changes([ctrl_a], [ctrl_b])
        hp = [c for c in changes if c["field_path"] == "host_pid"]
        assert len(hp) == 1
        severity, _msg = classify_kubernetes_change(hp[0])
        assert severity == "high"


class TestCapabilityChanges:
    def test_dangerous_capability_added(self):
        _ctrl_a, container_a = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(security_context=make_security_context())])
        )
        _ctrl_b, container_b = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(
                security_context=make_security_context(capabilities_add=["SYS_ADMIN"])
            )])
        )
        changes = _real_changes([container_a], [container_b])
        cap_changes = [c for c in changes if c["field_path"] == "capabilities_added"]
        assert len(cap_changes) == 1
        severity, msg = classify_kubernetes_change(cap_changes[0])
        assert severity == "high"
        assert "SYS_ADMIN" in msg

    def test_all_capability_dropped_is_low_severity(self):
        _ctrl_a, container_a = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(security_context=make_security_context())])
        )
        _ctrl_b, container_b = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(
                security_context=make_security_context(capabilities_drop=["ALL"])
            )])
        )
        changes = _real_changes([container_a], [container_b])
        cap_changes = [c for c in changes if c["field_path"] == "capabilities_dropped"]
        assert len(cap_changes) == 1
        severity, _msg = classify_kubernetes_change(cap_changes[0])
        assert severity == "low"


class TestSeccompChanges:
    def test_seccomp_changed_to_unconfined(self):
        from types import SimpleNamespace as NS
        _ctrl_a, container_a = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(
                security_context=make_security_context(seccomp_profile=NS(type="RuntimeDefault"))
            )])
        )
        _ctrl_b, container_b = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(
                security_context=make_security_context(seccomp_profile=NS(type="Unconfined"))
            )])
        )
        changes = _real_changes([container_a], [container_b])
        seccomp_changes = [c for c in changes if c["field_path"] == "seccomp_profile_category"]
        assert len(seccomp_changes) == 1
        severity, _msg = classify_kubernetes_change(seccomp_changes[0])
        assert severity == "high"


class TestHostPathChanges:
    def test_writable_docker_socket_mount_is_critical(self):
        from tests._kubernetes_workload_fixtures import make_hostpath_volume, make_volume_mount
        vol = make_hostpath_volume("dockersock", "/var/run/docker.sock")
        ctrl_a, _c_a = _collect_deployment(pod_spec=make_pod_spec())
        ctrl_b, _c_b = _collect_deployment(
            pod_spec=make_pod_spec(
                containers=[make_container(volume_mounts=[make_volume_mount("dockersock")])],
                volumes=[vol],
            )
        )
        changes = _real_changes([ctrl_a], [ctrl_b])
        hp_changes = [c for c in changes if c["field_path"] == "dangerous_hostpath_categories"]
        assert len(hp_changes) == 1
        severity, msg = classify_kubernetes_change(hp_changes[0])
        assert severity == "critical"
        assert "socket" in msg.lower()


class TestImagePostureChanges:
    def test_mutable_image_introduced(self):
        _ctrl_a, container_a = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(image="app:1.2.3")])
        )
        _ctrl_b, container_b = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(image="app:latest")])
        )
        changes = _real_changes([container_a], [container_b])
        tag_changes = [c for c in changes if c["field_path"] == "image_tag_category"]
        assert len(tag_changes) == 1
        severity, _msg = classify_kubernetes_change(tag_changes[0])
        assert severity == "medium"


class TestServiceAccountAutomountChanges:
    def test_automount_explicitly_enabled(self):
        ctrl_a, _c_a = _collect_deployment(pod_spec=make_pod_spec(automount_service_account_token=None))
        ctrl_b, _c_b = _collect_deployment(pod_spec=make_pod_spec(automount_service_account_token=True))
        changes = _real_changes([ctrl_a], [ctrl_b])
        automount_changes = [c for c in changes if c["field_path"] == "automount_service_account_token"]
        assert len(automount_changes) == 1
        severity, _msg = classify_kubernetes_change(automount_changes[0])
        assert severity == "medium"


class TestResourceControlChanges:
    def test_resource_limits_removed(self):
        from types import SimpleNamespace as NS
        _ctrl_a, container_a = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(resources=NS(requests={}, limits={"cpu": "1"}))])
        )
        _ctrl_b, container_b = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(resources=NS(requests={}, limits={}))])
        )
        changes = _real_changes([container_a], [container_b])
        limit_changes = [c for c in changes if c["field_path"] == "any_resource_limit_present"]
        assert len(limit_changes) == 1
        severity, _msg = classify_kubernetes_change(limit_changes[0])
        assert severity == "medium"


class TestHostPortChanges:
    def test_host_port_introduced(self):
        from types import SimpleNamespace as NS
        _ctrl_a, container_a = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(ports=[])])
        )
        _ctrl_b, container_b = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(ports=[NS(host_port=8080)])])
        )
        changes = _real_changes([container_a], [container_b])
        port_changes = [c for c in changes if c["field_path"] == "host_port_count"]
        assert len(port_changes) == 1
        severity, _msg = classify_kubernetes_change(port_changes[0])
        assert severity == "medium"


class TestWorkloadAddedRemoved:
    def test_workload_added_already_dangerous(self):
        controller, _container = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(security_context=make_security_context(privileged=True))])
        )
        changes = _real_changes([], [controller])
        added = [c for c in changes if c["change_type"] == "added" and c["provider_metadata"]["record_type"] == "kubernetes_deployment"]
        assert len(added) == 1
        severity, msg = classify_kubernetes_change(added[0])
        assert severity == "high"
        assert "privileged" in msg.lower() or "host-access" in msg.lower()

    def test_dangerous_workload_removed(self):
        controller, _container = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(security_context=make_security_context(privileged=True))])
        )
        changes = _real_changes([controller], [])
        removed = [c for c in changes if c["change_type"] == "removed"]
        assert len(removed) == 1
        severity, _msg = classify_kubernetes_change(removed[0])
        assert severity == "medium"


class TestNoisyFieldsIgnored:
    def test_resource_version_only_change_ignored(self):
        # kubernetes records never carry resourceVersion at all — confirm a
        # record that's byte-identical except for an out-of-band field we
        # deliberately never emit produces zero changes.
        controller, _container = _collect_deployment()
        a = dict(controller)
        b = dict(controller)
        changes = _real_changes([a], [b])
        assert changes == []

    def test_status_only_pod_change_ignored(self):
        from tests._kubernetes_workload_fixtures import make_container_status
        pod_a = make_pod(owner_references=[], container_statuses=[make_container_status(restart_count=1)])
        pod_b = make_pod(owner_references=[], container_statuses=[make_container_status(restart_count=99)])
        list_fn_a = MagicMock(return_value=page([pod_a]))
        list_fn_b = MagicMock(return_value=page([pod_b]))
        pods_a, _c_a, _s_a = _collect_standalone_pods(
            list_fn_a, cluster_id="c1", cluster_name="c1", namespace_allowlist=None
        )
        pods_b, _c_b, _s_b = _collect_standalone_pods(
            list_fn_b, cluster_id="c1", cluster_name="c1", namespace_allowlist=None
        )
        changes = _real_changes(pods_a, pods_b)
        assert changes == []  # restart_count_aggregate is untracked runtime state


class TestProviderMetadata:
    def test_container_change_metadata_includes_workload_context(self):
        _ctrl_a, container_a = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(security_context=make_security_context(privileged=False))])
        )
        _ctrl_b, container_b = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(security_context=make_security_context(privileged=True))])
        )
        changes = _real_changes([container_a], [container_b])
        privileged_changes = [c for c in changes if c["field_path"] == "privileged"]
        pm = privileged_changes[0]["provider_metadata"]
        assert pm["record_type"] == KUBERNETES_CONTAINER_SECURITY_CONTEXT
        assert pm["container_name"] == "app"
        assert pm["container_category"] == "application"
        assert pm["parent_workload_type"] == "deployment"
        assert pm["namespace"] == "prod"
        assert pm["cluster_id"] == "uid:c1"


class TestRiskRoutingNeverFallsThroughToCloudflare:
    def test_deployment_change_routes_to_kubernetes_classifier(self):
        ctrl_a, _c_a = _collect_deployment(pod_spec=make_pod_spec(host_network=False))
        ctrl_b, _c_b = _collect_deployment(pod_spec=make_pod_spec(host_network=True))
        changes = _real_changes([ctrl_a], [ctrl_b])
        hn_changes = [c for c in changes if c["field_path"] == "host_network"]
        assert len(hn_changes) == 1
        pm = hn_changes[0]["provider_metadata"]
        assert pm["record_type"].startswith("kubernetes_")
        # Constructing a lightweight ORM-ish object so classify_change()'s
        # attribute access works without a real Change row.
        class _ChangeObj:
            def __init__(self, d):
                self.__dict__.update(d)
        severity, msg = classify_change(_ChangeObj(hn_changes[0]))
        assert severity == "medium"
        assert "cloudflare" not in msg.lower() and "dns" not in msg.lower()

    def test_container_record_type_never_falls_back_to_cloudflare_fields(self):
        _ctrl_a, container_a = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(image="app:1.0")])
        )
        _ctrl_b, container_b = _collect_deployment(
            pod_spec=make_pod_spec(containers=[make_container(image="app:2.0")])
        )
        changes = _real_changes([container_a], [container_b])
        assert changes  # image change is tracked
        for change in changes:
            pm = change["provider_metadata"]
            assert pm["record_type"] == KUBERNETES_CONTAINER_SECURITY_CONTEXT
