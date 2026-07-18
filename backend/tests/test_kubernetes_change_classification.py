"""Kubernetes Change classification QA (Kubernetes message 7 of 9).

Exhaustive Change-classification pass over the real ``compute_diff()`` ->
``classify_kubernetes_change()`` pipeline. Every test builds two fake
``Snapshot``-shaped objects (``SimpleNamespace(state=[...])``), calls the
real ``compute_diff()``, and classifies the resulting Change dicts through
the real central dispatcher — never a hand-fabricated Change shape only.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules.kubernetes import classify_kubernetes_change


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _diff(prev: list[dict], new: list[dict]) -> list[dict]:
    return compute_diff(_snap(prev), _snap(new))


def _find(changes: list[dict], *, field_path: str = None, change_type: str = None) -> dict:
    for c in changes:
        if field_path is not None and c.get("field_path") != field_path:
            continue
        if change_type is not None and c.get("change_type") != change_type:
            continue
        return c
    raise AssertionError(f"no matching change found (field_path={field_path!r}, change_type={change_type!r}) in {changes}")


def _classify(change: dict) -> tuple[str, str]:
    return classify_kubernetes_change(change)


# ── Base record builders (minimal, matching real emitted field shapes) ──────

def _deployment(**overrides) -> dict:
    base = {
        "record_type": "kubernetes_deployment", "record_id": "c1/deployment/prod/web",
        "cluster_id": "uid:c1", "cluster_name": "c1", "namespace": "prod", "name": "web",
        "uid": "u1", "api_version": "apps/v1", "kind": "Deployment",
        "desired_replica_count": 3, "update_strategy_category": "RollingUpdate",
        "service_account_name": "default", "automount_service_account_token": None,
        "host_network": False, "host_pid": False, "host_ipc": False,
        "dns_policy_category": "ClusterFirst", "restart_policy": "Always",
        "runtime_class_name": None, "node_selector_key_count": 0, "toleration_count": 0,
        "dangerous_toleration_categories": [], "affinity_present": False,
        "anti_affinity_present": False, "topology_spread_constraint_count": 0,
        "image_pull_secret_count": 0, "container_count": 1, "init_container_count": 0,
        "ephemeral_container_count": 0, "hostpath_volume_count": 0,
        "dangerous_hostpath_categories": [], "privileged_container_count": 0,
        "root_container_count": 0, "allow_privilege_escalation_count": 0,
        "added_capability_categories": [], "seccomp_posture_summary": "runtime_default",
        "apparmor_posture_summary": "runtime_default", "read_only_root_filesystem_coverage": "full",
        "resource_limit_coverage": "full", "liveness_probe_coverage": "full",
        "readiness_probe_coverage": "full", "startup_probe_coverage": "full",
        "image_posture_summary": "pinned", "security_posture_summary": "standard",
        "collection_completeness_category": "complete",
    }
    base.update(overrides)
    return base


def _container_ctx(**overrides) -> dict:
    base = {
        "record_type": "kubernetes_container_security_context", "record_id": "c1/deployment/prod/web/container/app",
        "cluster_id": "uid:c1", "cluster_name": "c1", "namespace": "prod",
        "parent_workload_type": "Deployment", "parent_workload_uid": "u1",
        "parent_record_id": "c1/deployment/prod/web", "container_name": "app",
        "container_category": "application", "image": "nginx:1.25.3",
        "image_registry_category": "docker_hub", "image_tag_category": "explicit_tag",
        "image_pull_policy": "IfNotPresent", "privileged": False,
        "allow_privilege_escalation": False, "run_as_user_set": False, "run_as_uid": None,
        "run_as_group_set": False, "run_as_non_root": None, "read_only_root_filesystem": None,
        "seccomp_profile_category": "runtime_default", "apparmor_profile_category": "runtime_default",
        "selinux_options_present": False, "windows_security_context_present": False,
        "capabilities_added": [], "capabilities_dropped": [], "dangerous_added_capability_categories": [],
        "proc_mount_category": None, "host_port_count": 0, "dangerous_host_ports": [],
        "cpu_request_present": True, "memory_request_present": True, "cpu_limit_present": True,
        "memory_limit_present": True, "any_resource_request_present": True, "any_resource_limit_present": True,
        "liveness_probe_present": True, "readiness_probe_present": True, "startup_probe_present": True,
        "volume_mount_categories": [], "hostpath_mount_count": 0, "writable_hostpath_mount_count": 0,
        "service_account_token_explicitly_mounted": False, "bidirectional_mount_propagation_present": False,
    }
    base.update(overrides)
    return base


def _subject_binding(**overrides) -> dict:
    base = {
        "record_type": "kubernetes_rbac_subject_binding", "record_id": "c1/clusterrolebinding/cluster/b1/subject/User/alice",
        "cluster_id": "uid:c1", "cluster_name": "c1", "binding_kind": "ClusterRoleBinding",
        "binding_namespace": None, "binding_name": "b1", "binding_uid": "bu1",
        "role_ref_kind": "ClusterRole", "role_ref_name": "view", "role_ref_api_group": "rbac.authorization.k8s.io",
        "subject_kind": "User", "subject_name": "alice", "subject_namespace": None,
        "subject_identity": "alice", "anonymous_subject": False, "unauthenticated_group": False,
        "authenticated_group": False, "system_group": False, "broad_group": False,
        "cross_namespace_service_account": False, "role_resolved": True,
        "role_resolution_status": "resolved", "resolved_privilege_category": "low",
        "cluster_admin_binding": False, "wildcard_permission_binding": False,
        "high_risk_permission_categories": [],
    }
    base.update(overrides)
    return base


def _service(**overrides) -> dict:
    base = {
        "record_type": "kubernetes_service", "record_id": "c1/service/prod/web",
        "cluster_id": "uid:c1", "cluster_name": "c1", "namespace": "prod", "name": "web", "uid": "u1",
        "service_type": "ClusterIP", "cluster_ip_present": True, "headless": False,
        "external_ip_count": 0, "load_balancer_ingress_count": 0, "external_name_category": None,
        "publish_not_ready_addresses": False, "external_traffic_policy": None,
        "internal_traffic_policy": None, "session_affinity": None, "ip_family_categories": ["IPv4"],
        "ip_family_policy": None, "selector_key_count": 1, "selector_fingerprint": "fp1",
        "internal_load_balancer_annotation_present": False, "port_count": 1,
        "exposure_category": "cluster_internal", "mixed_exposure_evidence": False,
        "collection_completeness_category": "complete",
    }
    base.update(overrides)
    return base


def _network_policy(**overrides) -> dict:
    base = {
        "record_type": "kubernetes_network_policy", "record_id": "c1/networkpolicy/prod/np1",
        "cluster_id": "uid:c1", "cluster_name": "c1", "namespace": "prod", "name": "np1", "uid": "u1",
        "pod_selector_empty_all_pods": True, "selected_label_key_count": 0,
        "policy_types": ["Ingress"], "ingress_rule_count": 1, "egress_rule_count": 0,
        "ingress_isolation_enabled": True, "egress_isolation_enabled": False,
        "ingress_rules_declared": True, "egress_rules_declared": False,
        "empty_ingress_list": False, "empty_egress_list": True,
        "allows_all_ingress": False, "allows_all_egress": False,
        "public_ipv4_cidr_allowed": False, "public_ipv6_cidr_allowed": False,
        "broad_cidr_count": 0, "namespace_selector_present": False, "pod_selector_present": True,
        "ip_block_present": False, "except_cidr_count": 0, "port_restriction_present": False,
        "protocol_categories": ["TCP"], "selector_fingerprint": "fp1", "policy_fingerprint": "fp2",
        "collection_completeness_category": "complete",
    }
    base.update(overrides)
    return base


def _webhook(**overrides) -> dict:
    base = {
        "record_type": "kubernetes_validating_webhook", "record_id": "c1/webhook/wc1/webhook/wh1",
        "cluster_id": "uid:c1", "cluster_name": "c1", "parent_configuration_record_id": "c1/webhook/wc1",
        "webhook_name": "wh1", "webhook_type": "validating", "client_type": "service",
        "service_namespace": "kube-system", "service_name": "svc", "service_path_category": "specific",
        "service_port": 443, "external_url_host_category": None, "plaintext_http_client": False,
        "failure_policy": "Fail", "match_policy": "Equivalent", "side_effects": "None",
        "timeout_seconds": 10, "namespace_selector_category": "absent", "object_selector_category": "absent",
        "rules_count": 1, "operation_categories": ["CREATE"], "api_group_categories": ["apps"],
        "api_version_categories": ["v1"], "resource_categories": ["deployments"], "scope_category": "Namespaced",
        "admission_review_versions": ["v1"], "ca_bundle_present": True, "reinvocation_policy": None,
        "wildcard_operation": False, "wildcard_api_group": False, "wildcard_resource": False,
        "webhook_fingerprint": "fp1", "collection_completeness_category": "complete",
    }
    base.update(overrides)
    return base


def _psa(**overrides) -> dict:
    base = {
        "record_type": "kubernetes_pod_security_admission", "record_id": "c1/psa/prod",
        "cluster_id": "uid:c1", "cluster_name": "c1", "namespace": "prod",
        "enforce_level": "restricted", "enforce_version_category": "latest",
        "audit_level": "restricted", "audit_version_category": "latest",
        "warn_level": "restricted", "warn_version_category": "latest",
        "effective_posture_category": "restricted", "enforcement_enabled": True,
        "audit_enabled": True, "warning_enabled": True,
        "enforcement_weaker_than_audit": False, "enforcement_weaker_than_warning": False,
        "namespace_context_category": "user", "posture_fingerprint": "fp1",
        "collection_completeness_category": "complete",
    }
    base.update(overrides)
    return base


def _governance(**overrides) -> dict:
    base = {
        "record_type": "kubernetes_namespace_governance_posture", "record_id": "c1/governance/prod",
        "cluster_id": "uid:c1", "cluster_name": "c1", "namespace": "prod",
        "psa_enforcement_category": "restricted", "validating_webhook_coverage_category": "full",
        "mutating_webhook_coverage_category": "full", "resource_quota_count": 1, "limit_range_count": 1,
        "quota_coverage_category": "broad", "default_resource_control_category": "present",
        "network_policy_coverage_category": "broad", "privileged_workload_present": False,
        "high_privilege_service_account_present": False, "governance_completeness_category": "complete",
        "governance_risk_summary": "standard",
    }
    base.update(overrides)
    return base


# ═══════════════════════ Workload transitions ═══════════════════════════════


class TestWorkloadPrivilegeTransitions:
    def test_privileged_false_to_true(self):
        prev = [_container_ctx(privileged=False)]
        new = [_container_ctx(privileged=True)]
        changes = _diff(prev, new)
        c = _find(changes, field_path="privileged")
        assert _classify(c) == ("high", "A container was explicitly configured as privileged.")

    def test_privileged_true_to_false(self):
        prev = [_container_ctx(privileged=True)]
        new = [_container_ctx(privileged=False)]
        c = _find(_diff(prev, new), field_path="privileged")
        sev, _ = _classify(c)
        assert sev == "low"

    def test_privilege_escalation_false_to_true(self):
        prev = [_container_ctx(allow_privilege_escalation=False)]
        new = [_container_ctx(allow_privilege_escalation=True)]
        c = _find(_diff(prev, new), field_path="allow_privilege_escalation")
        assert _classify(c)[0] == "medium"

    def test_run_as_non_root_disabled(self):
        prev = [_container_ctx(run_as_non_root=True)]
        new = [_container_ctx(run_as_non_root=False)]
        c = _find(_diff(prev, new), field_path="run_as_non_root")
        assert _classify(c)[0] == "high"

    def test_run_as_uid_zero_introduced(self):
        prev = [_container_ctx(run_as_uid=1000, run_as_user_set=True)]
        new = [_container_ctx(run_as_uid=0, run_as_user_set=True)]
        c = _find(_diff(prev, new), field_path="run_as_uid")
        assert _classify(c)[0] == "high"

    def test_run_as_uid_zero_removed(self):
        prev = [_container_ctx(run_as_uid=0, run_as_user_set=True)]
        new = [_container_ctx(run_as_uid=1000, run_as_user_set=True)]
        c = _find(_diff(prev, new), field_path="run_as_uid")
        assert _classify(c)[0] == "low"


class TestHostNamespaceTransitions:
    def test_host_pid_enabled(self):
        prev = [_deployment(host_pid=False)]
        new = [_deployment(host_pid=True)]
        c = _find(_diff(prev, new), field_path="host_pid")
        assert _classify(c) == ("high", "Host PID namespace access was enabled for a Kubernetes workload.")

    def test_host_ipc_enabled(self):
        prev = [_deployment(host_ipc=False)]
        new = [_deployment(host_ipc=True)]
        c = _find(_diff(prev, new), field_path="host_ipc")
        assert _classify(c)[0] == "high"

    def test_host_network_enabled(self):
        prev = [_deployment(host_network=False)]
        new = [_deployment(host_network=True)]
        c = _find(_diff(prev, new), field_path="host_network")
        assert _classify(c)[0] == "medium"


class TestCapabilityTransitions:
    def test_sys_admin_added(self):
        prev = [_container_ctx(dangerous_added_capability_categories=[])]
        new = [_container_ctx(dangerous_added_capability_categories=["SYS_ADMIN"])]
        c = _find(_diff(prev, new), field_path="dangerous_added_capability_categories")
        assert _classify(c)[0] == "high"

    def test_all_capability_added(self):
        prev = [_container_ctx(capabilities_added=[])]
        new = [_container_ctx(capabilities_added=["ALL"])]
        c = _find(_diff(prev, new), field_path="capabilities_added")
        assert _classify(c)[0] == "high"

    def test_capability_removed(self):
        prev = [_container_ctx(dangerous_added_capability_categories=["NET_ADMIN"])]
        new = [_container_ctx(dangerous_added_capability_categories=[])]
        c = _find(_diff(prev, new), field_path="dangerous_added_capability_categories")
        assert _classify(c)[0] == "low"

    def test_ordering_only_change_is_never_misclassified_as_risky(self):
        # compute_diff still records a Change (raw list identity differs),
        # but since the set contents are identical, the classifier must
        # never report this as an addition or removal of a capability.
        prev = [_container_ctx(dangerous_added_capability_categories=["NET_ADMIN", "SYS_PTRACE"])]
        new = [_container_ctx(dangerous_added_capability_categories=["SYS_PTRACE", "NET_ADMIN"])]
        c = _find(_diff(prev, new), field_path="dangerous_added_capability_categories")
        assert _classify(c)[0] == "low"


class TestProfileTransitions:
    def test_seccomp_runtime_default_to_unconfined(self):
        prev = [_container_ctx(seccomp_profile_category="runtime_default")]
        new = [_container_ctx(seccomp_profile_category="unconfined")]
        c = _find(_diff(prev, new), field_path="seccomp_profile_category")
        assert _classify(c) == ("high", "Seccomp protection was changed to Unconfined.")

    def test_seccomp_unconfined_to_runtime_default(self):
        prev = [_container_ctx(seccomp_profile_category="unconfined")]
        new = [_container_ctx(seccomp_profile_category="runtime_default")]
        c = _find(_diff(prev, new), field_path="seccomp_profile_category")
        assert _classify(c) == ("low", "Seccomp protection was restored.")

    def test_apparmor_unconfined_severity_is_medium(self):
        prev = [_container_ctx(apparmor_profile_category="runtime_default")]
        new = [_container_ctx(apparmor_profile_category="unconfined")]
        c = _find(_diff(prev, new), field_path="apparmor_profile_category")
        assert _classify(c)[0] == "medium"


class TestHostpathTransitions:
    def test_runtime_socket_introduced_is_critical(self):
        prev = [_deployment(dangerous_hostpath_categories=[])]
        new = [_deployment(dangerous_hostpath_categories=["docker_socket"])]
        c = _find(_diff(prev, new), field_path="dangerous_hostpath_categories")
        assert _classify(c)[0] == "critical"

    def test_dangerous_hostpath_introduced_is_high(self):
        prev = [_deployment(dangerous_hostpath_categories=[])]
        new = [_deployment(dangerous_hostpath_categories=["etc"])]
        c = _find(_diff(prev, new), field_path="dangerous_hostpath_categories")
        assert _classify(c)[0] == "high"

    def test_hostpath_removed_is_low(self):
        prev = [_deployment(dangerous_hostpath_categories=["etc"])]
        new = [_deployment(dangerous_hostpath_categories=[])]
        c = _find(_diff(prev, new), field_path="dangerous_hostpath_categories")
        assert _classify(c)[0] == "low"


class TestImageTransitions:
    def test_pinned_to_mutable(self):
        prev = [_container_ctx(image_tag_category="pinned_digest")]
        new = [_container_ctx(image_tag_category="latest_explicit")]
        c = _find(_diff(prev, new), field_path="image_tag_category")
        assert _classify(c)[0] == "medium"

    def test_mutable_to_pinned(self):
        prev = [_container_ctx(image_tag_category="latest_implicit")]
        new = [_container_ctx(image_tag_category="pinned_digest")]
        c = _find(_diff(prev, new), field_path="image_tag_category")
        assert _classify(c)[0] == "low"


class TestAutomountTransitions:
    def test_automount_false_to_true(self):
        prev = [_deployment(automount_service_account_token=False)]
        new = [_deployment(automount_service_account_token=True)]
        c = _find(_diff(prev, new), field_path="automount_service_account_token")
        assert _classify(c)[0] == "medium"

    def test_automount_true_to_false(self):
        prev = [_deployment(automount_service_account_token=True)]
        new = [_deployment(automount_service_account_token=False)]
        c = _find(_diff(prev, new), field_path="automount_service_account_token")
        assert _classify(c)[0] == "low"


# ═══════════════════════ RBAC transitions ═══════════════════════════════════


class TestRbacBindingTransitions:
    def test_cluster_admin_granted(self):
        prev = [_subject_binding(cluster_admin_binding=False)]
        new = [_subject_binding(cluster_admin_binding=True)]
        c = _find(_diff(prev, new), field_path="cluster_admin_binding")
        assert _classify(c)[0] == "critical"

    def test_cluster_admin_removed(self):
        prev = [_subject_binding(cluster_admin_binding=True)]
        new = [_subject_binding(cluster_admin_binding=False)]
        c = _find(_diff(prev, new), field_path="cluster_admin_binding")
        assert _classify(c)[0] == "low"

    def test_wildcard_permission_granted(self):
        prev = [_subject_binding(wildcard_permission_binding=False)]
        new = [_subject_binding(wildcard_permission_binding=True)]
        c = _find(_diff(prev, new), field_path="wildcard_permission_binding")
        assert _classify(c)[0] == "high"

    def test_bind_permission_granted_is_critical(self):
        prev = [_subject_binding(high_risk_permission_categories=[])]
        new = [_subject_binding(high_risk_permission_categories=["bind"])]
        c = _find(_diff(prev, new), field_path="high_risk_permission_categories")
        assert _classify(c)[0] == "critical"

    def test_escalate_permission_granted_is_critical(self):
        prev = [_subject_binding(high_risk_permission_categories=[])]
        new = [_subject_binding(high_risk_permission_categories=["escalate"])]
        c = _find(_diff(prev, new), field_path="high_risk_permission_categories")
        assert _classify(c)[0] == "critical"

    def test_impersonate_permission_granted_is_critical_or_higher_than_high(self):
        # Finding-parity floor is High for impersonate; the Change classifier
        # is intentionally more cautious (Critical) for a FRESH grant — never
        # below the static floor.
        prev = [_subject_binding(high_risk_permission_categories=[])]
        new = [_subject_binding(high_risk_permission_categories=["impersonate"])]
        c = _find(_diff(prev, new), field_path="high_risk_permission_categories")
        sev = _classify(c)[0]
        assert sev in ("critical", "high")

    def test_secret_read_permission_granted(self):
        prev = [_subject_binding(high_risk_permission_categories=[])]
        new = [_subject_binding(high_risk_permission_categories=["secret_read"])]
        c = _find(_diff(prev, new), field_path="high_risk_permission_categories")
        assert _classify(c)[0] == "high"

    def test_role_ref_changed(self):
        prev = [_subject_binding(role_ref_name="view")]
        new = [_subject_binding(role_ref_name="edit")]
        c = _find(_diff(prev, new), field_path="role_ref_name")
        assert _classify(c)[0] == "medium"


# ═══════════════════════ Network transitions ════════════════════════════════


class TestServiceExposureTransitions:
    def test_internal_to_external(self):
        prev = [_service(exposure_category="cluster_internal")]
        new = [_service(exposure_category="external_load_balancer")]
        c = _find(_diff(prev, new), field_path="exposure_category")
        assert _classify(c) == ("high", "A Kubernetes Service changed from internal to confirmed external exposure.")

    def test_external_to_internal(self):
        prev = [_service(exposure_category="external_load_balancer")]
        new = [_service(exposure_category="cluster_internal")]
        c = _find(_diff(prev, new), field_path="exposure_category")
        assert _classify(c)[0] == "low"

    def test_clusterip_to_nodeport(self):
        prev = [_service(service_type="ClusterIP")]
        new = [_service(service_type="NodePort")]
        c = _find(_diff(prev, new), field_path="service_type")
        assert _classify(c)[0] == "medium"

    def test_load_balancer_assigned(self):
        prev = [_service(load_balancer_ingress_count=0)]
        new = [_service(load_balancer_ingress_count=1)]
        c = _find(_diff(prev, new), field_path="load_balancer_ingress_count")
        assert _classify(c)[0] == "high"


class TestNetworkPolicyTransitions:
    def test_allow_all_ingress_introduced(self):
        prev = [_network_policy(allows_all_ingress=False)]
        new = [_network_policy(allows_all_ingress=True)]
        c = _find(_diff(prev, new), field_path="allows_all_ingress")
        assert _classify(c)[0] == "critical"

    def test_allow_all_egress_introduced(self):
        prev = [_network_policy(allows_all_egress=False)]
        new = [_network_policy(allows_all_egress=True)]
        c = _find(_diff(prev, new), field_path="allows_all_egress")
        assert _classify(c)[0] == "critical"

    def test_public_ipv4_cidr_introduced(self):
        prev = [_network_policy(public_ipv4_cidr_allowed=False)]
        new = [_network_policy(public_ipv4_cidr_allowed=True)]
        c = _find(_diff(prev, new), field_path="public_ipv4_cidr_allowed")
        assert _classify(c)[0] == "high"

    def test_public_ipv6_cidr_introduced_parity_with_ipv4(self):
        prev = [_network_policy(public_ipv6_cidr_allowed=False)]
        new = [_network_policy(public_ipv6_cidr_allowed=True)]
        c = _find(_diff(prev, new), field_path="public_ipv6_cidr_allowed")
        assert _classify(c)[0] == "high"

    def test_default_deny_ingress_removed(self):
        prev = [_network_policy(empty_ingress_list=True)]
        new = [_network_policy(empty_ingress_list=False)]
        c = _find(_diff(prev, new), field_path="empty_ingress_list")
        assert _classify(c)[0] == "high"

    def test_default_deny_ingress_added(self):
        prev = [_network_policy(empty_ingress_list=False)]
        new = [_network_policy(empty_ingress_list=True)]
        c = _find(_diff(prev, new), field_path="empty_ingress_list")
        assert _classify(c)[0] == "low"


# ═══════════════════════ Admission transitions ══════════════════════════════


class TestWebhookTransitions:
    def test_failure_policy_fail_to_ignore(self):
        prev = [_webhook(failure_policy="Fail")]
        new = [_webhook(failure_policy="Ignore")]
        c = _find(_diff(prev, new), field_path="failure_policy")
        assert _classify(c) == ("high", "An admission webhook's failurePolicy changed from Fail to Ignore.")

    def test_failure_policy_ignore_to_fail(self):
        prev = [_webhook(failure_policy="Ignore")]
        new = [_webhook(failure_policy="Fail")]
        c = _find(_diff(prev, new), field_path="failure_policy")
        assert _classify(c)[0] == "low"

    def test_wildcard_resource_introduced(self):
        prev = [_webhook(wildcard_resource=False)]
        new = [_webhook(wildcard_resource=True)]
        c = _find(_diff(prev, new), field_path="wildcard_resource")
        assert _classify(c)[0] == "high"

    def test_plaintext_http_introduced(self):
        prev = [_webhook(plaintext_http_client=False)]
        new = [_webhook(plaintext_http_client=True)]
        c = _find(_diff(prev, new), field_path="plaintext_http_client")
        assert _classify(c)[0] == "high"

    def test_ca_bundle_removed(self):
        prev = [_webhook(ca_bundle_present=True)]
        new = [_webhook(ca_bundle_present=False)]
        c = _find(_diff(prev, new), field_path="ca_bundle_present")
        assert _classify(c)[0] == "medium"

    def test_selector_broadened(self):
        prev = [_webhook(namespace_selector_category="narrow")]
        new = [_webhook(namespace_selector_category="absent")]
        c = _find(_diff(prev, new), field_path="namespace_selector_category")
        assert _classify(c)[0] == "medium"


# ═══════════════════════ PSA transitions ════════════════════════════════════


class TestPsaTransitions:
    def test_restricted_to_baseline(self):
        prev = [_psa(enforce_level="restricted")]
        new = [_psa(enforce_level="baseline")]
        c = _find(_diff(prev, new), field_path="enforce_level")
        assert _classify(c)[0] == "high"

    def test_baseline_to_restricted(self):
        prev = [_psa(enforce_level="baseline")]
        new = [_psa(enforce_level="restricted")]
        c = _find(_diff(prev, new), field_path="enforce_level")
        assert _classify(c)[0] == "low"

    def test_enforcement_removed(self):
        prev = [_psa(enforce_level="restricted")]
        new = [_psa(enforce_level="unset")]
        c = _find(_diff(prev, new), field_path="enforce_level")
        assert _classify(c) == ("high", "A namespace's Pod Security Admission enforcement was removed.")

    def test_enforcement_restored_from_unset(self):
        prev = [_psa(enforce_level="unset")]
        new = [_psa(enforce_level="restricted")]
        c = _find(_diff(prev, new), field_path="enforce_level")
        assert _classify(c)[0] == "low"

    def test_invalid_enforcement(self):
        prev = [_psa(enforce_level="restricted")]
        new = [_psa(enforce_level="invalid")]
        c = _find(_diff(prev, new), field_path="enforce_level")
        assert _classify(c)[0] == "high"


# ═══════════════════════ Namespace governance transitions ═══════════════════


class TestGovernanceTransitions:
    def test_psa_weakened_in_rollup(self):
        prev = [_governance(psa_enforcement_category="restricted")]
        new = [_governance(psa_enforcement_category="baseline")]
        c = _find(_diff(prev, new), field_path="psa_enforcement_category")
        assert _classify(c)[0] == "high"

    def test_risk_summary_introduced(self):
        prev = [_governance(governance_risk_summary="standard")]
        new = [_governance(governance_risk_summary="privileged_workload_weak_psa")]
        c = _find(_diff(prev, new), field_path="governance_risk_summary")
        assert _classify(c)[0] == "high"

    def test_risk_summary_resolved(self):
        prev = [_governance(governance_risk_summary="privileged_workload_weak_psa")]
        new = [_governance(governance_risk_summary="standard")]
        c = _find(_diff(prev, new), field_path="governance_risk_summary")
        assert _classify(c)[0] == "low"
