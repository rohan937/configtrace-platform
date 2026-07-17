"""Kubernetes Pod-security normalization tests (Kubernetes message 2 of 9).

Covers the full security-posture normalization surface: privileged/root/
host-namespace flags, Linux capabilities, seccomp/AppArmor, hostPath
categorization (including runtime-socket detection), image tag/registry
categorization, resource/probe presence, init/ephemeral containers, and
mixed multi-container posture aggregation. Also verifies explicit/effective/
unknown semantics are never silently collapsed to a confirmed state.

All tests are pure-mock; no real Kubernetes cluster is contacted.
"""

from __future__ import annotations

from types import SimpleNamespace as NS
from unittest.mock import MagicMock

from app.connectors.kubernetes import (
    KUBERNETES_DEPLOYMENT,
    _collect_standalone_pods,
    _collect_workload_family,
    categorize_hostpath,
    categorize_image_registry,
    categorize_image_tag,
)
from app.connectors.kubernetes_schema import (
    HOSTPATH_CATEGORY_CONTAINERD_SOCKET,
    HOSTPATH_CATEGORY_DOCKER_SOCKET,
    HOSTPATH_CATEGORY_ETC,
    HOSTPATH_CATEGORY_KUBELET_DIR,
    HOSTPATH_CATEGORY_ROOT,
    IMAGE_TAG_EXPLICIT,
    IMAGE_TAG_LATEST_EXPLICIT,
    IMAGE_TAG_LATEST_IMPLICIT,
    IMAGE_TAG_PINNED_DIGEST,
    SECURITY_POSTURE_ELEVATED,
    SECURITY_POSTURE_PRIVILEGED_OR_HOST_ACCESS,
    SECURITY_POSTURE_STANDARD,
)
from tests._kubernetes_workload_fixtures import (
    make_container,
    make_container_status,
    make_deployment,
    make_hostpath_volume,
    make_pod,
    make_pod_spec,
    make_security_context,
    make_volume_mount,
    page,
)


def _normalize_one_container(security_context=None, **container_kwargs):
    container = make_container(security_context=security_context, **container_kwargs)
    spec = make_pod_spec(containers=[container])
    obj = make_deployment(pod_spec=spec)
    list_fn = MagicMock(return_value=page([obj]))
    controllers, containers, _status = _collect_workload_family(
        list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
        cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
    )
    return controllers[0], containers[0]


# ── H, I, J: privileged across container categories ─────────────────────────

class TestPrivilegedAcrossCategories:
    def test_privileged_application_container(self):
        controller, container = _normalize_one_container(
            security_context=make_security_context(privileged=True)
        )
        assert container["privileged"] is True
        assert controller["privileged_container_count"] == 1
        assert controller["security_posture_summary"] == SECURITY_POSTURE_PRIVILEGED_OR_HOST_ACCESS

    def test_privileged_init_container(self):
        init_container = make_container(name="init-setup", security_context=make_security_context(privileged=True))
        spec = make_pod_spec(containers=[make_container(name="app")], init_containers=[init_container])
        obj = make_deployment(pod_spec=spec)
        list_fn = MagicMock(return_value=page([obj]))
        controllers, containers, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        init_records = [c for c in containers if c["container_category"] == "init"]
        assert init_records[0]["privileged"] is True
        assert controllers[0]["privileged_container_count"] == 1

    def test_privileged_ephemeral_container(self):
        eph = make_container(name="debugger", security_context=make_security_context(privileged=True))
        spec = make_pod_spec(containers=[make_container(name="app")], ephemeral_containers=[eph])
        obj = make_deployment(pod_spec=spec)
        list_fn = MagicMock(return_value=page([obj]))
        controllers, containers, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        eph_records = [c for c in containers if c["container_category"] == "ephemeral"]
        assert eph_records[0]["privileged"] is True
        assert controllers[0]["ephemeral_container_count"] == 1


# ── K, L, M, N: privilege escalation, root posture, unknown run-as-user ─────

class TestRootAndPrivilegeEscalation:
    def test_allow_privilege_escalation_true(self):
        _controller, container = _normalize_one_container(
            security_context=make_security_context(allow_privilege_escalation=True)
        )
        assert container["allow_privilege_escalation"] is True

    def test_explicit_run_as_non_root_false(self):
        controller, container = _normalize_one_container(
            security_context=make_security_context(run_as_non_root=False)
        )
        assert container["run_as_non_root"] is False
        assert controller["root_container_count"] == 1

    def test_explicit_uid_zero(self):
        controller, container = _normalize_one_container(
            security_context=make_security_context(run_as_user=0)
        )
        assert container["run_as_uid"] == 0
        assert container["run_as_user_set"] is True
        assert controller["root_container_count"] == 1

    def test_unknown_run_as_user_is_none_not_a_claim(self):
        _controller, container = _normalize_one_container(security_context=make_security_context())
        assert container["run_as_uid"] is None
        assert container["run_as_user_set"] is False
        # Omission must never be silently treated as root or non-root.
        assert container["run_as_non_root"] is None


# ── O, P, Q, R: host namespace access ────────────────────────────────────────

class TestHostNamespaceAccess:
    def test_host_network(self):
        spec = make_pod_spec(host_network=True)
        obj = make_deployment(pod_spec=spec)
        list_fn = MagicMock(return_value=page([obj]))
        controllers, _c, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert controllers[0]["host_network"] is True
        assert controllers[0]["security_posture_summary"] == SECURITY_POSTURE_ELEVATED

    def test_host_pid(self):
        spec = make_pod_spec(host_pid=True)
        obj = make_deployment(pod_spec=spec)
        list_fn = MagicMock(return_value=page([obj]))
        controllers, _c, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert controllers[0]["host_pid"] is True
        assert controllers[0]["security_posture_summary"] == SECURITY_POSTURE_PRIVILEGED_OR_HOST_ACCESS

    def test_host_ipc(self):
        spec = make_pod_spec(host_ipc=True)
        obj = make_deployment(pod_spec=spec)
        list_fn = MagicMock(return_value=page([obj]))
        controllers, _c, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert controllers[0]["host_ipc"] is True

    def test_share_process_namespace_on_standalone_pod(self):
        spec = make_pod_spec()
        spec.share_process_namespace = True
        pod = make_pod(pod_spec=spec, owner_references=[])
        list_fn = MagicMock(return_value=page([pod]))
        pods, _c, _s = _collect_standalone_pods(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert pods[0]["share_process_namespace"] is True


# ── S-X: hostPath categorization ──────────────────────────────────────────────

class TestHostPathCategorization:
    def test_root_mounted(self):
        assert categorize_hostpath("/") == HOSTPATH_CATEGORY_ROOT

    def test_docker_socket(self):
        assert categorize_hostpath("/var/run/docker.sock") == HOSTPATH_CATEGORY_DOCKER_SOCKET

    def test_containerd_socket(self):
        assert categorize_hostpath("/run/containerd/containerd.sock") == HOSTPATH_CATEGORY_CONTAINERD_SOCKET

    def test_kubelet_dir(self):
        assert categorize_hostpath("/var/lib/kubelet/pods") == HOSTPATH_CATEGORY_KUBELET_DIR

    def test_etc(self):
        assert categorize_hostpath("/etc/kubernetes") == HOSTPATH_CATEGORY_ETC

    def test_writable_hostpath_mount_counted(self):
        vol = make_hostpath_volume("dockersock", "/var/run/docker.sock")
        container = make_container(volume_mounts=[make_volume_mount("dockersock", read_only=False)])
        spec = make_pod_spec(containers=[container], volumes=[vol])
        obj = make_deployment(pod_spec=spec)
        list_fn = MagicMock(return_value=page([obj]))
        controllers, containers, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert containers[0]["writable_hostpath_mount_count"] == 1
        assert HOSTPATH_CATEGORY_DOCKER_SOCKET in controllers[0]["dangerous_hostpath_categories"]

    def test_bidirectional_mount_propagation(self):
        vol = make_hostpath_volume("data", "/data")
        container = make_container(
            volume_mounts=[make_volume_mount("data", mount_propagation="Bidirectional")]
        )
        spec = make_pod_spec(containers=[container], volumes=[vol])
        obj = make_deployment(pod_spec=spec)
        list_fn = MagicMock(return_value=page([obj]))
        _controllers, containers, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert containers[0]["bidirectional_mount_propagation_present"] is True


# ── Y-AC: capabilities ─────────────────────────────────────────────────────────

class TestCapabilities:
    def test_sys_admin_added(self):
        _c, container = _normalize_one_container(
            security_context=make_security_context(capabilities_add=["SYS_ADMIN"])
        )
        assert "SYS_ADMIN" in container["capabilities_added"]
        assert "SYS_ADMIN" in container["dangerous_added_capability_categories"]

    def test_net_admin_added(self):
        _c, container = _normalize_one_container(
            security_context=make_security_context(capabilities_add=["NET_ADMIN"])
        )
        assert "NET_ADMIN" in container["dangerous_added_capability_categories"]

    def test_sys_ptrace_added(self):
        _c, container = _normalize_one_container(
            security_context=make_security_context(capabilities_add=["SYS_PTRACE"])
        )
        assert "SYS_PTRACE" in container["dangerous_added_capability_categories"]

    def test_all_capability_added(self):
        _c, container = _normalize_one_container(
            security_context=make_security_context(capabilities_add=["ALL"])
        )
        assert "ALL" in container["capabilities_added"]
        assert "ALL" in container["dangerous_added_capability_categories"]

    def test_all_capabilities_dropped(self):
        _c, container = _normalize_one_container(
            security_context=make_security_context(capabilities_drop=["ALL"])
        )
        assert container["capabilities_dropped"] == ["ALL"]
        assert container["dangerous_added_capability_categories"] == []

    def test_capability_case_normalized(self):
        _c, container = _normalize_one_container(
            security_context=make_security_context(capabilities_add=["sys_admin"])
        )
        assert container["capabilities_added"] == ["SYS_ADMIN"]


# ── AD-AF: seccomp ─────────────────────────────────────────────────────────────

class TestSeccomp:
    def test_runtime_default(self):
        _c, container = _normalize_one_container(
            security_context=make_security_context(seccomp_profile=NS(type="RuntimeDefault"))
        )
        assert container["seccomp_profile_category"] == "runtime_default"

    def test_unconfined(self):
        _c, container = _normalize_one_container(
            security_context=make_security_context(seccomp_profile=NS(type="Unconfined"))
        )
        assert container["seccomp_profile_category"] == "unconfined"

    def test_omitted_is_not_a_claim_of_protection(self):
        _c, container = _normalize_one_container(security_context=make_security_context())
        assert container["seccomp_profile_category"] == "omitted"

    def test_pod_level_seccomp_is_inherited_when_container_omits_it(self):
        pod_sc = NS(seccomp_profile=NS(type="RuntimeDefault"))
        spec = make_pod_spec(containers=[make_container(security_context=make_security_context())])
        spec.security_context = pod_sc
        obj = make_deployment(pod_spec=spec)
        list_fn = MagicMock(return_value=page([obj]))
        _controllers, containers, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert containers[0]["seccomp_profile_category"] == "runtime_default"


# ── AG, AH: AppArmor ───────────────────────────────────────────────────────────

class TestAppArmor:
    def test_structured_runtime_default(self):
        _c, container = _normalize_one_container(
            security_context=make_security_context(app_armor_profile=NS(type="RuntimeDefault"))
        )
        assert container["apparmor_profile_category"] == "runtime_default"

    def test_legacy_annotation_unconfined(self):
        container = make_container(name="app", security_context=make_security_context())
        spec = make_pod_spec(containers=[container])
        obj = make_deployment(pod_spec=spec)
        obj.spec.template.metadata.annotations = {
            "container.apparmor.security.beta.kubernetes.io/app": "unconfined"
        }
        list_fn = MagicMock(return_value=page([obj]))
        _controllers, containers, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert containers[0]["apparmor_profile_category"] == "unconfined"

    def test_no_other_annotation_is_ever_read(self):
        container = make_container(name="app", security_context=make_security_context())
        spec = make_pod_spec(containers=[container])
        obj = make_deployment(pod_spec=spec)
        obj.spec.template.metadata.annotations = {"some.other/annotation": "sensitive-value-xyz"}
        list_fn = MagicMock(return_value=page([obj]))
        _controllers, containers, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert containers[0]["apparmor_profile_category"] == "omitted"
        import json
        assert "sensitive-value-xyz" not in json.dumps(containers)


# ── AI, AJ: root filesystem ────────────────────────────────────────────────────

class TestRootFilesystem:
    def test_read_only_true(self):
        _c, container = _normalize_one_container(
            security_context=make_security_context(read_only_root_filesystem=True)
        )
        assert container["read_only_root_filesystem"] is True

    def test_writable(self):
        _c, container = _normalize_one_container(
            security_context=make_security_context(read_only_root_filesystem=False)
        )
        assert container["read_only_root_filesystem"] is False


# ── AK, AL: service-account automount ─────────────────────────────────────────

class TestAutomount:
    def test_explicit_automount(self):
        spec = make_pod_spec(automount_service_account_token=True)
        obj = make_deployment(pod_spec=spec)
        list_fn = MagicMock(return_value=page([obj]))
        controllers, _c, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert controllers[0]["automount_service_account_token"] is True

    def test_inherited_automount_is_none_not_false(self):
        spec = make_pod_spec(automount_service_account_token=None)
        obj = make_deployment(pod_spec=spec)
        list_fn = MagicMock(return_value=page([obj]))
        controllers, _c, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert controllers[0]["automount_service_account_token"] is None


# ── AM-AQ: image categorization ────────────────────────────────────────────────

class TestImageCategorization:
    def test_pinned_by_digest(self):
        assert categorize_image_tag("nginx@sha256:" + "a" * 64) == IMAGE_TAG_PINNED_DIGEST

    def test_explicit_immutable_tag(self):
        assert categorize_image_tag("nginx:1.25.3") == IMAGE_TAG_EXPLICIT

    def test_latest_explicit(self):
        assert categorize_image_tag("nginx:latest") == IMAGE_TAG_LATEST_EXPLICIT

    def test_implicit_latest(self):
        assert categorize_image_tag("nginx") == IMAGE_TAG_LATEST_IMPLICIT

    def test_pull_policy_always(self):
        _c, container = _normalize_one_container(image_pull_policy="Always")
        assert container["image_pull_policy"] == "Always"

    def test_registry_docker_hub_implicit(self):
        assert categorize_image_registry("nginx") == "docker_hub"

    def test_registry_private(self):
        assert categorize_image_registry("registry.internal.example.com/app:v1") == "private_or_unknown"

    def test_registry_gcr(self):
        assert categorize_image_registry("gcr.io/project/app:v1") == "gcr"


# ── AR-AU: resource controls ───────────────────────────────────────────────────

class TestResourceControls:
    def test_no_cpu_request(self):
        _c, container = _normalize_one_container(resources=NS(requests={"memory": "128Mi"}, limits={}))
        assert container["cpu_request_present"] is False
        assert container["memory_request_present"] is True

    def test_no_memory_request(self):
        _c, container = _normalize_one_container(resources=NS(requests={"cpu": "100m"}, limits={}))
        assert container["memory_request_present"] is False

    def test_no_cpu_limit(self):
        _c, container = _normalize_one_container(resources=NS(requests={}, limits={"memory": "256Mi"}))
        assert container["cpu_limit_present"] is False

    def test_no_memory_limit(self):
        _c, container = _normalize_one_container(resources=NS(requests={}, limits={"cpu": "200m"}))
        assert container["memory_limit_present"] is False
        assert container["any_resource_limit_present"] is True


# ── AV-AX: probes ───────────────────────────────────────────────────────────────

class TestProbes:
    def test_liveness_probe_presence(self):
        _c, container = _normalize_one_container(liveness_probe=NS(http_get=NS(path="/healthz")))
        assert container["liveness_probe_present"] is True
        assert container["readiness_probe_present"] is False

    def test_readiness_probe_presence(self):
        _c, container = _normalize_one_container(readiness_probe=NS(http_get=NS(path="/ready")))
        assert container["readiness_probe_present"] is True

    def test_startup_probe_presence(self):
        _c, container = _normalize_one_container(startup_probe=NS(http_get=NS(path="/startup")))
        assert container["startup_probe_present"] is True

    def test_probe_payload_never_persisted(self):
        _c, container = _normalize_one_container(
            liveness_probe=NS(http_get=NS(path="/healthz", http_headers=[NS(name="X-Secret", value="super-secret-header")]))
        )
        import json
        assert "super-secret-header" not in json.dumps(container)
        assert "X-Secret" not in json.dumps(container)


# ── AY: host ports ─────────────────────────────────────────────────────────────

class TestHostPorts:
    def test_host_port_present(self):
        _c, container = _normalize_one_container(ports=[NS(host_port=22)])
        assert container["host_port_count"] == 1
        assert 22 in container["dangerous_host_ports"]

    def test_non_sensitive_host_port_not_in_dangerous_list(self):
        _c, container = _normalize_one_container(ports=[NS(host_port=8080)])
        assert container["host_port_count"] == 1
        assert container["dangerous_host_ports"] == []


# ── AZ: mixed multi-container posture ─────────────────────────────────────────

class TestMixedMultiContainerPosture:
    def test_workload_aggregate_reflects_worst_case_container(self):
        safe = make_container(name="sidecar", security_context=make_security_context(read_only_root_filesystem=True))
        risky = make_container(name="main", security_context=make_security_context(privileged=True))
        spec = make_pod_spec(containers=[safe, risky])
        obj = make_deployment(pod_spec=spec)
        list_fn = MagicMock(return_value=page([obj]))
        controllers, containers, _s = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert controllers[0]["privileged_container_count"] == 1
        assert controllers[0]["read_only_root_filesystem_coverage"] == "partial"
        assert len(containers) == 2


# ── BA: malformed container security context ──────────────────────────────────

class TestMalformedSecurityContext:
    def test_missing_security_context_normalizes_to_unknown_not_a_crash(self):
        _controller, container = _normalize_one_container(security_context=None)
        assert container["privileged"] is None
        assert container["run_as_non_root"] is None
        assert container["capabilities_added"] == []

    def test_security_context_missing_capabilities_field(self):
        sc = NS(
            privileged=None, allow_privilege_escalation=None, run_as_user=None,
            run_as_group=None, run_as_non_root=None, read_only_root_filesystem=None,
            seccomp_profile=None, app_armor_profile=None, capabilities=None,
            se_linux_options=None, windows_options=None, proc_mount=None,
        )
        _controller, container = _normalize_one_container(security_context=sc)
        assert container["capabilities_added"] == []
        assert container["capabilities_dropped"] == []


# ── BN, BO: runtime-only fields never leak into declarative posture ─────────

class TestRuntimeVsDeclarativeSeparation:
    def test_pod_runtime_fields_are_present_but_separate(self):
        pod = make_pod(
            owner_references=[], phase="Running",
            container_statuses=[make_container_status(restart_count=7, waiting_reason="CrashLoopBackOff")],
        )
        list_fn = MagicMock(return_value=page([pod]))
        pods, _c, _s = _collect_standalone_pods(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        record = pods[0]
        assert record["restart_count_aggregate"] == 7
        assert record["container_waiting_reason_category"] == "crash_loop"
        assert record["phase_category"] == "running"
        # Declarative fields exist independently of runtime state.
        assert "host_network" in record
        assert "service_account_name" in record

    def test_pod_ip_and_node_name_are_not_persisted_verbatim(self):
        pod = make_pod(owner_references=[], host_ip="203.0.113.5")
        list_fn = MagicMock(return_value=page([pod]))
        pods, _c, _s = _collect_standalone_pods(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        record = pods[0]
        assert "node_name" not in record
        assert record["host_ip_present"] is True
        import json
        assert "203.0.113.5" not in json.dumps(record)
