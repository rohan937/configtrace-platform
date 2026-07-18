"""Kubernetes Security Finding tests (Kubernetes message 6 of 9).

For every one of the 59 Kubernetes rule keys: a positive test (constructs a
normalized record that should trigger the rule via ``evaluate_record()``),
a negative test (explicit safe evidence — rule must not fire), and, for
every tri-state field the rule reads, an unknown test (field is ``None`` or
the record's completeness category is partial — rule must not fire).

All tests build plain normalized-record dicts (the shape emitted by
app/connectors/kubernetes.py) and exercise the real central dispatch path
via ``security_finding_evaluator.evaluate_record()`` — never call the
per-rule functions in app/services/security_rules/kubernetes.py directly.
"""

from __future__ import annotations

from app.services.security_finding_evaluator import evaluate_record


def _keys(record):
    return {f.rule_key for f in evaluate_record(record, "kubernetes")}


def _find(record, rule_key):
    matches = [f for f in evaluate_record(record, "kubernetes") if f.rule_key == rule_key]
    return matches[0] if matches else None


def _base(record_type, defaults, extra):
    base = {
        "record_type": record_type,
        "cluster_id": "uid:c1",
        "cluster_name": "test-cluster",
        "record_id": f"{record_type}/1",
    }
    base.update(defaults)
    base.update(extra)
    return base


def _container(**extra):
    return _base("kubernetes_container_security_context", {
        "namespace": "prod", "container_name": "app", "parent_record_id": "c1/deployment/prod/web",
        "privileged": None, "run_as_user_set": False, "run_as_uid": None, "run_as_non_root": None,
        "allow_privilege_escalation": None, "dangerous_added_capability_categories": [],
        "capabilities_added": [], "seccomp_profile_category": "omitted",
        "apparmor_profile_category": "omitted", "read_only_root_filesystem": None,
        "image_tag_category": "explicit_tag", "dangerous_host_ports": [],
    }, extra)


def _workload(**extra):
    return _base("kubernetes_deployment", {
        "namespace": "prod", "name": "web", "kind": "Deployment",
        "host_pid": False, "host_ipc": False, "host_network": False,
        "privileged_container_count": 0, "dangerous_hostpath_categories": [],
        "added_capability_categories": [], "automount_service_account_token": None,
        "service_account_name": "default",
    }, extra)


def _subject_binding(**extra):
    return _base("kubernetes_rbac_subject_binding", {
        "binding_kind": "ClusterRoleBinding", "binding_name": "b1",
        "subject_kind": "ServiceAccount", "subject_identity": "prod/svc",
        "subject_name": "svc", "role_ref_name": "edit",
        "cluster_admin_binding": False, "anonymous_subject": False,
        "unauthenticated_group": False, "authenticated_group": False, "broad_group": False,
        "wildcard_permission_binding": False, "high_risk_permission_categories": [],
    }, extra)


def _service(**extra):
    return _base("kubernetes_service", {
        "namespace": "prod", "name": "web", "exposure_category": "cluster_internal",
    }, extra)


def _service_port(**extra):
    return _base("kubernetes_service_port", {
        "namespace": "prod", "parent_service_record_id": "x", "node_port": None,
        "sensitive_port": False, "port": 80, "protocol": "TCP",
    }, extra)


def _ingress_rule(**extra):
    return _base("kubernetes_ingress_rule", {
        "namespace": "prod", "parent_ingress_record_id": "x", "host_category": "exact",
        "public_exposure_category": "unknown", "tls_covered": True, "catch_all_route": False,
    }, extra)


def _gateway_listener(**extra):
    return _base("kubernetes_gateway_listener", {
        "namespace": "prod", "parent_gateway_record_id": "x", "listener_name": "https",
        "protocol": "HTTPS", "port": 443, "public_exposure_category": "unknown",
    }, extra)


def _network_policy(**extra):
    return _base("kubernetes_network_policy", {
        "namespace": "prod", "name": "np1",
        "allows_all_ingress": False, "allows_all_egress": False,
        "public_ipv4_cidr_allowed": False, "public_ipv6_cidr_allowed": False,
    }, extra)


def _namespace_network_posture(**extra):
    return _base("kubernetes_namespace_network_posture", {
        "namespace": "prod",
        "has_any_network_policy": True, "ingress_isolation_present": True,
        "egress_isolation_present": True, "collection_completeness_category": "complete",
    }, extra)


def _webhook(**extra):
    return _base("kubernetes_validating_webhook", {
        "webhook_name": "wh1", "webhook_type": "validating",
        "parent_configuration_record_id": "x", "failure_policy": "Fail",
        "wildcard_operation": False, "wildcard_api_group": False, "wildcard_resource": False,
        "plaintext_http_client": False,
    }, extra)


def _psa(**extra):
    return _base("kubernetes_pod_security_admission", {
        "namespace": "prod",
        "enforce_level": "restricted", "collection_completeness_category": "complete",
    }, extra)


def _governance(**extra):
    return _base("kubernetes_namespace_governance_posture", {
        "namespace": "prod",
        "psa_enforcement_category": "restricted", "network_policy_coverage_category": "broad",
        "privileged_workload_present": False, "high_privilege_service_account_present": False,
        "governance_risk_summary": "standard", "governance_completeness_category": "complete",
        "resource_quota_count": 1, "limit_range_count": 1, "quota_coverage_category": "broad",
    }, extra)


# ═══════════════════════ Workload / Pod security ═══════════════════════════


class TestPrivilegedContainer:
    def test_positive(self):
        assert "kubernetes_privileged_container" in _keys(_container(privileged=True))

    def test_negative(self):
        assert "kubernetes_privileged_container" not in _keys(_container(privileged=False))

    def test_unknown(self):
        assert "kubernetes_privileged_container" not in _keys(_container(privileged=None))


class TestPrivilegedHostAccess:
    def test_positive_host_pid(self):
        w = _workload(privileged_container_count=1, host_pid=True)
        assert "kubernetes_privileged_host_access" in _keys(w)

    def test_positive_runtime_socket(self):
        w = _workload(privileged_container_count=1, dangerous_hostpath_categories=["docker_socket"])
        assert "kubernetes_privileged_host_access" in _keys(w)

    def test_negative_privileged_alone(self):
        w = _workload(privileged_container_count=1, host_pid=False, host_ipc=False)
        assert "kubernetes_privileged_host_access" not in _keys(w)

    def test_negative_host_access_alone(self):
        w = _workload(privileged_container_count=0, host_pid=True)
        assert "kubernetes_privileged_host_access" not in _keys(w)

    def test_unknown_zero_count(self):
        w = _workload(privileged_container_count=0, host_pid=True, host_ipc=True)
        assert "kubernetes_privileged_host_access" not in _keys(w)


class TestRootContainer:
    def test_positive(self):
        assert "kubernetes_root_container" in _keys(_container(run_as_user_set=True, run_as_uid=0))

    def test_negative(self):
        assert "kubernetes_root_container" not in _keys(_container(run_as_user_set=True, run_as_uid=1000))

    def test_unknown(self):
        assert "kubernetes_root_container" not in _keys(_container(run_as_user_set=False, run_as_uid=None))


class TestRunAsNonRootDisabled:
    def test_positive(self):
        assert "kubernetes_run_as_non_root_disabled" in _keys(_container(run_as_non_root=False))

    def test_negative(self):
        assert "kubernetes_run_as_non_root_disabled" not in _keys(_container(run_as_non_root=True))

    def test_unknown(self):
        assert "kubernetes_run_as_non_root_disabled" not in _keys(_container(run_as_non_root=None))


class TestPrivilegeEscalationAllowed:
    def test_positive(self):
        assert "kubernetes_privilege_escalation_allowed" in _keys(_container(allow_privilege_escalation=True))

    def test_negative(self):
        assert "kubernetes_privilege_escalation_allowed" not in _keys(_container(allow_privilege_escalation=False))

    def test_unknown(self):
        assert "kubernetes_privilege_escalation_allowed" not in _keys(_container(allow_privilege_escalation=None))


class TestDangerousLinuxCapability:
    def test_positive_high_tier(self):
        f = _find(_container(dangerous_added_capability_categories=["SYS_ADMIN"]), "kubernetes_dangerous_linux_capability")
        assert f is not None and f.severity == "high"

    def test_positive_medium_tier(self):
        f = _find(_container(dangerous_added_capability_categories=["MKNOD"]), "kubernetes_dangerous_linux_capability")
        assert f is not None and f.severity == "medium"

    def test_negative(self):
        assert "kubernetes_dangerous_linux_capability" not in _keys(_container(dangerous_added_capability_categories=[]))


class TestAllCapabilitiesAdded:
    def test_positive(self):
        assert "kubernetes_all_capabilities_added" in _keys(_container(capabilities_added=["ALL"]))

    def test_negative(self):
        assert "kubernetes_all_capabilities_added" not in _keys(_container(capabilities_added=["NET_BIND_SERVICE"]))

    def test_unknown_empty(self):
        assert "kubernetes_all_capabilities_added" not in _keys(_container(capabilities_added=[]))


class TestHostPid:
    def test_positive(self):
        assert "kubernetes_host_pid_enabled" in _keys(_workload(host_pid=True))

    def test_negative(self):
        assert "kubernetes_host_pid_enabled" not in _keys(_workload(host_pid=False))


class TestHostIpc:
    def test_positive(self):
        assert "kubernetes_host_ipc_enabled" in _keys(_workload(host_ipc=True))

    def test_negative(self):
        assert "kubernetes_host_ipc_enabled" not in _keys(_workload(host_ipc=False))


class TestHostNetwork:
    def test_positive(self):
        assert "kubernetes_host_network_enabled" in _keys(_workload(host_network=True))

    def test_negative(self):
        assert "kubernetes_host_network_enabled" not in _keys(_workload(host_network=False))


class TestDangerousHostpath:
    def test_positive(self):
        assert "kubernetes_dangerous_hostpath" in _keys(_workload(dangerous_hostpath_categories=["etc"]))

    def test_negative(self):
        assert "kubernetes_dangerous_hostpath" not in _keys(_workload(dangerous_hostpath_categories=[]))

    def test_socket_only_does_not_double_fire_this_rule(self):
        keys = _keys(_workload(dangerous_hostpath_categories=["docker_socket"]))
        assert "kubernetes_dangerous_hostpath" not in keys
        assert "kubernetes_container_runtime_socket_mounted" in keys


class TestRuntimeSocketMounted:
    def test_positive_docker(self):
        assert "kubernetes_container_runtime_socket_mounted" in _keys(_workload(dangerous_hostpath_categories=["docker_socket"]))

    def test_positive_containerd(self):
        assert "kubernetes_container_runtime_socket_mounted" in _keys(_workload(dangerous_hostpath_categories=["containerd_socket"]))

    def test_negative(self):
        assert "kubernetes_container_runtime_socket_mounted" not in _keys(_workload(dangerous_hostpath_categories=["proc"]))


class TestSeccompUnconfined:
    def test_positive(self):
        assert "kubernetes_seccomp_unconfined" in _keys(_container(seccomp_profile_category="unconfined"))

    def test_negative(self):
        assert "kubernetes_seccomp_unconfined" not in _keys(_container(seccomp_profile_category="runtime_default"))

    def test_unknown(self):
        assert "kubernetes_seccomp_unconfined" not in _keys(_container(seccomp_profile_category="omitted"))


class TestApparmorUnconfined:
    def test_positive(self):
        assert "kubernetes_apparmor_unconfined" in _keys(_container(apparmor_profile_category="unconfined"))

    def test_negative(self):
        assert "kubernetes_apparmor_unconfined" not in _keys(_container(apparmor_profile_category="runtime_default"))

    def test_unknown(self):
        assert "kubernetes_apparmor_unconfined" not in _keys(_container(apparmor_profile_category="omitted"))


class TestWritableRootFilesystem:
    def test_positive(self):
        assert "kubernetes_writable_root_filesystem" in _keys(_container(read_only_root_filesystem=False))

    def test_negative(self):
        assert "kubernetes_writable_root_filesystem" not in _keys(_container(read_only_root_filesystem=True))

    def test_unknown(self):
        assert "kubernetes_writable_root_filesystem" not in _keys(_container(read_only_root_filesystem=None))


class TestMutableImageTag:
    def test_positive_explicit_latest(self):
        assert "kubernetes_mutable_image_tag" in _keys(_container(image_tag_category="latest_explicit"))

    def test_positive_implicit_latest(self):
        assert "kubernetes_mutable_image_tag" in _keys(_container(image_tag_category="latest_implicit"))

    def test_negative(self):
        assert "kubernetes_mutable_image_tag" not in _keys(_container(image_tag_category="pinned_digest"))


class TestServiceAccountTokenAutomount:
    def test_positive(self):
        assert "kubernetes_service_account_token_automount" in _keys(_workload(automount_service_account_token=True))

    def test_negative(self):
        assert "kubernetes_service_account_token_automount" not in _keys(_workload(automount_service_account_token=False))

    def test_unknown(self):
        assert "kubernetes_service_account_token_automount" not in _keys(_workload(automount_service_account_token=None))


class TestSensitiveHostPort:
    def test_positive(self):
        assert "kubernetes_sensitive_host_port" in _keys(_container(dangerous_host_ports=[6443]))

    def test_negative(self):
        assert "kubernetes_sensitive_host_port" not in _keys(_container(dangerous_host_ports=[]))


# ═══════════════════════ RBAC / identity ════════════════════════════════════


class TestClusterAdminBinding:
    def test_positive(self):
        assert "kubernetes_cluster_admin_binding" in _keys(_subject_binding(cluster_admin_binding=True))

    def test_negative(self):
        assert "kubernetes_cluster_admin_binding" not in _keys(_subject_binding(cluster_admin_binding=False))


class TestUnauthenticatedClusterAdmin:
    def test_positive(self):
        r = _subject_binding(cluster_admin_binding=True, anonymous_subject=True)
        assert "kubernetes_unauthenticated_cluster_admin" in _keys(r)

    def test_positive_unauthenticated_group(self):
        r = _subject_binding(cluster_admin_binding=True, unauthenticated_group=True)
        assert "kubernetes_unauthenticated_cluster_admin" in _keys(r)

    def test_negative_authenticated_subject(self):
        r = _subject_binding(cluster_admin_binding=True, anonymous_subject=False, unauthenticated_group=False)
        assert "kubernetes_unauthenticated_cluster_admin" not in _keys(r)

    def test_negative_not_cluster_admin(self):
        r = _subject_binding(cluster_admin_binding=False, anonymous_subject=True)
        assert "kubernetes_unauthenticated_cluster_admin" not in _keys(r)


class TestAuthenticatedGroupClusterAdmin:
    def test_positive(self):
        r = _subject_binding(cluster_admin_binding=True, authenticated_group=True, subject_kind="Group")
        assert "kubernetes_authenticated_group_cluster_admin" in _keys(r)

    def test_negative(self):
        r = _subject_binding(cluster_admin_binding=True, authenticated_group=False)
        assert "kubernetes_authenticated_group_cluster_admin" not in _keys(r)


class TestAllServiceAccountsClusterAdmin:
    def test_positive(self):
        r = _subject_binding(cluster_admin_binding=True, subject_kind="Group", subject_name="system:serviceaccounts")
        assert "kubernetes_all_service_accounts_cluster_admin" in _keys(r)

    def test_negative_different_group(self):
        r = _subject_binding(cluster_admin_binding=True, subject_kind="Group", subject_name="system:masters")
        assert "kubernetes_all_service_accounts_cluster_admin" not in _keys(r)


class TestWildcardRbacPermissions:
    def test_positive(self):
        r = _subject_binding(wildcard_permission_binding=True, cluster_admin_binding=False)
        assert "kubernetes_wildcard_rbac_permissions" in _keys(r)

    def test_negative(self):
        r = _subject_binding(wildcard_permission_binding=False)
        assert "kubernetes_wildcard_rbac_permissions" not in _keys(r)

    def test_suppressed_when_already_cluster_admin(self):
        r = _subject_binding(wildcard_permission_binding=True, cluster_admin_binding=True)
        assert "kubernetes_wildcard_rbac_permissions" not in _keys(r)


_PERMISSION_RULES = [
    ("bind", "kubernetes_rbac_bind_permission"),
    ("escalate", "kubernetes_rbac_escalate_permission"),
    ("impersonate", "kubernetes_rbac_impersonate_permission"),
    ("token_creation", "kubernetes_service_account_token_creation"),
    ("secret_read", "kubernetes_secret_read_permission"),
    ("secret_write", "kubernetes_secret_write_permission"),
    ("pod_exec", "kubernetes_pod_exec_permission"),
    ("pod_attach", "kubernetes_pod_attach_permission"),
    ("workload_write", "kubernetes_broad_workload_creation"),
    ("role_or_cluster_role_write", "kubernetes_rbac_modification_permission"),
    ("admission_webhook_write", "kubernetes_admission_webhook_modification_permission"),
    ("crd_write", "kubernetes_crd_modification_permission"),
]


class TestPermissionCategoryRules:
    def test_all_permission_rules_positive(self):
        for category, rule_key in _PERMISSION_RULES:
            r = _subject_binding(high_risk_permission_categories=[category])
            assert rule_key in _keys(r), f"{rule_key} did not fire for category={category}"

    def test_all_permission_rules_negative(self):
        r = _subject_binding(high_risk_permission_categories=[])
        keys = _keys(r)
        for _category, rule_key in _PERMISSION_RULES:
            assert rule_key not in keys

    def test_secret_read_broad_scope_variant_also_fires(self):
        r = _subject_binding(high_risk_permission_categories=["secret_read_broad_scope"])
        assert "kubernetes_secret_read_permission" in _keys(r)

    def test_cluster_role_binding_write_maps_to_modification_rule(self):
        r = _subject_binding(high_risk_permission_categories=["cluster_role_binding_write"])
        assert "kubernetes_rbac_modification_permission" in _keys(r)


# ═══════════════════════ Network exposure ═══════════════════════════════════


class TestPublicLoadBalancer:
    def test_positive(self):
        assert "kubernetes_public_load_balancer" in _keys(_service(exposure_category="external_load_balancer"))

    def test_negative_pending(self):
        assert "kubernetes_public_load_balancer" not in _keys(_service(exposure_category="pending_load_balancer"))

    def test_negative_internal(self):
        assert "kubernetes_public_load_balancer" not in _keys(_service(exposure_category="internal_load_balancer"))

    def test_unknown(self):
        assert "kubernetes_public_load_balancer" not in _keys(_service(exposure_category="unknown"))


class TestSensitiveNodeport:
    def test_positive(self):
        r = _service_port(node_port=6443, sensitive_port=True)
        assert "kubernetes_sensitive_nodeport" in _keys(r)

    def test_negative_not_sensitive(self):
        r = _service_port(node_port=31234, sensitive_port=False)
        assert "kubernetes_sensitive_nodeport" not in _keys(r)

    def test_negative_no_nodeport(self):
        r = _service_port(node_port=None, sensitive_port=True)
        assert "kubernetes_sensitive_nodeport" not in _keys(r)


class TestPublicIngressWithoutTls:
    def test_positive(self):
        r = _ingress_rule(public_exposure_category="external_load_balancer", tls_covered=False)
        assert "kubernetes_public_ingress_without_tls" in _keys(r)

    def test_negative_tls_covered(self):
        r = _ingress_rule(public_exposure_category="external_load_balancer", tls_covered=True)
        assert "kubernetes_public_ingress_without_tls" not in _keys(r)

    def test_negative_not_public(self):
        r = _ingress_rule(public_exposure_category="unknown", tls_covered=False)
        assert "kubernetes_public_ingress_without_tls" not in _keys(r)


class TestHostlessCatchallIngress:
    def test_positive(self):
        r = _ingress_rule(catch_all_route=True, host_category="hostless")
        assert "kubernetes_hostless_catchall_ingress" in _keys(r)

    def test_negative_hosted_catchall(self):
        r = _ingress_rule(catch_all_route=True, host_category="exact")
        assert "kubernetes_hostless_catchall_ingress" not in _keys(r)

    def test_negative_not_catchall(self):
        r = _ingress_rule(catch_all_route=False, host_category="hostless")
        assert "kubernetes_hostless_catchall_ingress" not in _keys(r)


class TestPublicGatewayListener:
    def test_positive(self):
        assert "kubernetes_public_gateway_listener" in _keys(_gateway_listener(public_exposure_category="external_load_balancer"))

    def test_negative(self):
        assert "kubernetes_public_gateway_listener" not in _keys(_gateway_listener(public_exposure_category="internal_load_balancer"))

    def test_unknown(self):
        assert "kubernetes_public_gateway_listener" not in _keys(_gateway_listener(public_exposure_category="unknown"))


# ═══════════════════════ NetworkPolicy isolation ════════════════════════════


class TestNetworkPolicyAllowsAllIngress:
    def test_positive(self):
        assert "kubernetes_network_policy_allows_all_ingress" in _keys(_network_policy(allows_all_ingress=True))

    def test_negative(self):
        assert "kubernetes_network_policy_allows_all_ingress" not in _keys(_network_policy(allows_all_ingress=False))


class TestNetworkPolicyAllowsAllEgress:
    def test_positive(self):
        assert "kubernetes_network_policy_allows_all_egress" in _keys(_network_policy(allows_all_egress=True))

    def test_negative(self):
        assert "kubernetes_network_policy_allows_all_egress" not in _keys(_network_policy(allows_all_egress=False))


class TestPublicIpv4CidrAllowed:
    def test_positive(self):
        assert "kubernetes_public_ipv4_cidr_allowed" in _keys(_network_policy(public_ipv4_cidr_allowed=True))

    def test_negative(self):
        assert "kubernetes_public_ipv4_cidr_allowed" not in _keys(_network_policy(public_ipv4_cidr_allowed=False))


class TestPublicIpv6CidrAllowed:
    def test_positive(self):
        assert "kubernetes_public_ipv6_cidr_allowed" in _keys(_network_policy(public_ipv6_cidr_allowed=True))

    def test_negative(self):
        assert "kubernetes_public_ipv6_cidr_allowed" not in _keys(_network_policy(public_ipv6_cidr_allowed=False))

    def test_ipv4_ipv6_parity_both_fire_independently(self):
        r = _network_policy(public_ipv4_cidr_allowed=True, public_ipv6_cidr_allowed=True)
        keys = _keys(r)
        assert "kubernetes_public_ipv4_cidr_allowed" in keys
        assert "kubernetes_public_ipv6_cidr_allowed" in keys


class TestNamespaceNoNetworkPolicy:
    def test_positive(self):
        r = _namespace_network_posture(has_any_network_policy=False)
        assert "kubernetes_namespace_no_network_policy" in _keys(r)

    def test_negative(self):
        r = _namespace_network_posture(has_any_network_policy=True)
        assert "kubernetes_namespace_no_network_policy" not in _keys(r)

    def test_unknown_partial_collection(self):
        r = _namespace_network_posture(has_any_network_policy=False, collection_completeness_category="partial")
        assert "kubernetes_namespace_no_network_policy" not in _keys(r)


class TestNamespaceNoIngressIsolation:
    def test_positive(self):
        r = _namespace_network_posture(ingress_isolation_present=False)
        assert "kubernetes_namespace_no_ingress_isolation" in _keys(r)

    def test_negative(self):
        r = _namespace_network_posture(ingress_isolation_present=True)
        assert "kubernetes_namespace_no_ingress_isolation" not in _keys(r)

    def test_unknown_partial_collection(self):
        r = _namespace_network_posture(ingress_isolation_present=False, collection_completeness_category="partial")
        assert "kubernetes_namespace_no_ingress_isolation" not in _keys(r)


class TestNamespaceNoEgressIsolation:
    def test_positive(self):
        r = _namespace_network_posture(egress_isolation_present=False)
        assert "kubernetes_namespace_no_egress_isolation" in _keys(r)

    def test_negative(self):
        r = _namespace_network_posture(egress_isolation_present=True)
        assert "kubernetes_namespace_no_egress_isolation" not in _keys(r)

    def test_unknown_partial_collection(self):
        r = _namespace_network_posture(egress_isolation_present=False, collection_completeness_category="partial")
        assert "kubernetes_namespace_no_egress_isolation" not in _keys(r)


# ═══════════════════════ Admission webhooks ═════════════════════════════════


class TestValidatingWebhookFailOpen:
    def test_positive(self):
        r = _webhook(webhook_type="validating", failure_policy="Ignore")
        assert "kubernetes_validating_webhook_fail_open" in _keys(r)

    def test_negative(self):
        r = _webhook(webhook_type="validating", failure_policy="Fail")
        assert "kubernetes_validating_webhook_fail_open" not in _keys(r)

    def test_unknown(self):
        r = _webhook(webhook_type="validating", failure_policy="unknown")
        assert "kubernetes_validating_webhook_fail_open" not in _keys(r)


class TestMutatingWebhookFailOpen:
    def test_positive(self):
        r = _webhook(record_type="kubernetes_mutating_webhook", webhook_type="mutating", failure_policy="Ignore")
        assert "kubernetes_mutating_webhook_fail_open" in _keys(r)

    def test_negative(self):
        r = _webhook(record_type="kubernetes_mutating_webhook", webhook_type="mutating", failure_policy="Fail")
        assert "kubernetes_mutating_webhook_fail_open" not in _keys(r)


class TestBroadAdmissionWebhook:
    def test_positive_wildcard_resource(self):
        assert "kubernetes_broad_admission_webhook" in _keys(_webhook(wildcard_resource=True))

    def test_positive_wildcard_operation(self):
        assert "kubernetes_broad_admission_webhook" in _keys(_webhook(wildcard_operation=True))

    def test_negative(self):
        r = _webhook(wildcard_operation=False, wildcard_api_group=False, wildcard_resource=False)
        assert "kubernetes_broad_admission_webhook" not in _keys(r)


class TestAdmissionWebhookExternalHttp:
    def test_positive(self):
        assert "kubernetes_admission_webhook_external_http" in _keys(_webhook(plaintext_http_client=True))

    def test_negative_https(self):
        assert "kubernetes_admission_webhook_external_http" not in _keys(_webhook(plaintext_http_client=False))


# ═══════════════════════ Pod Security Admission ═════════════════════════════


class TestPsaPrivilegedEnforcement:
    def test_positive(self):
        assert "kubernetes_psa_privileged_enforcement" in _keys(_psa(enforce_level="privileged"))

    def test_negative(self):
        assert "kubernetes_psa_privileged_enforcement" not in _keys(_psa(enforce_level="restricted"))

    def test_unknown_partial(self):
        r = _psa(enforce_level="privileged", collection_completeness_category="partial")
        assert "kubernetes_psa_privileged_enforcement" not in _keys(r)


class TestPsaEnforcementMissing:
    def test_positive(self):
        assert "kubernetes_psa_enforcement_missing" in _keys(_psa(enforce_level="unset"))

    def test_negative(self):
        assert "kubernetes_psa_enforcement_missing" not in _keys(_psa(enforce_level="restricted"))

    def test_unknown_partial(self):
        r = _psa(enforce_level="unset", collection_completeness_category="partial")
        assert "kubernetes_psa_enforcement_missing" not in _keys(r)


class TestPsaInvalidEnforcement:
    def test_positive(self):
        assert "kubernetes_psa_invalid_enforcement" in _keys(_psa(enforce_level="invalid"))

    def test_negative(self):
        assert "kubernetes_psa_invalid_enforcement" not in _keys(_psa(enforce_level="baseline"))


class TestPsaWeakWithPrivilegedWorkloads:
    def test_positive(self):
        r = _governance(privileged_workload_present=True, psa_enforcement_category="unset",
                         governance_risk_summary="privileged_workload_weak_psa")
        assert "kubernetes_psa_weak_with_privileged_workloads" in _keys(r)

    def test_negative(self):
        r = _governance(privileged_workload_present=False, governance_risk_summary="standard")
        assert "kubernetes_psa_weak_with_privileged_workloads" not in _keys(r)

    def test_unknown_partial(self):
        r = _governance(
            privileged_workload_present=True, psa_enforcement_category="unset",
            governance_risk_summary="privileged_workload_weak_psa",
            governance_completeness_category="partial",
        )
        assert "kubernetes_psa_weak_with_privileged_workloads" not in _keys(r)


# ═══════════════════════ Namespace governance ═══════════════════════════════


class TestNamespaceWeakGovernance:
    def test_positive(self):
        r = _governance(
            psa_enforcement_category="unset", network_policy_coverage_category="none",
            quota_coverage_category="none", privileged_workload_present=True,
            governance_risk_summary="privileged_workload_weak_psa",
        )
        assert "kubernetes_namespace_weak_governance" in _keys(r)

    def test_negative_only_one_weak_signal(self):
        r = _governance(
            psa_enforcement_category="unset", network_policy_coverage_category="broad",
            quota_coverage_category="broad", privileged_workload_present=False,
            governance_risk_summary="standard",
        )
        assert "kubernetes_namespace_weak_governance" not in _keys(r)

    def test_unknown_partial(self):
        r = _governance(
            psa_enforcement_category="unset", network_policy_coverage_category="none",
            quota_coverage_category="none", privileged_workload_present=True,
            governance_completeness_category="partial",
        )
        assert "kubernetes_namespace_weak_governance" not in _keys(r)


class TestPrivilegedIdentityInWeakNamespace:
    def test_positive(self):
        r = _governance(
            high_privilege_service_account_present=True, network_policy_coverage_category="none",
            quota_coverage_category="none", governance_risk_summary="high_privilege_identity_weak_governance",
        )
        assert "kubernetes_privileged_identity_in_weak_namespace" in _keys(r)

    def test_negative(self):
        r = _governance(high_privilege_service_account_present=False, governance_risk_summary="standard")
        assert "kubernetes_privileged_identity_in_weak_namespace" not in _keys(r)


class TestPrivilegedWorkloadWithoutIsolation:
    def test_positive(self):
        r = _governance(
            privileged_workload_present=True, network_policy_coverage_category="none",
            governance_risk_summary="standard",
        )
        assert "kubernetes_privileged_workload_without_isolation" in _keys(r)

    def test_negative_isolated(self):
        r = _governance(
            privileged_workload_present=True, network_policy_coverage_category="broad",
            governance_risk_summary="standard",
        )
        assert "kubernetes_privileged_workload_without_isolation" not in _keys(r)

    def test_unknown_coverage(self):
        r = _governance(
            privileged_workload_present=True, network_policy_coverage_category="unknown",
            governance_risk_summary="standard",
        )
        assert "kubernetes_privileged_workload_without_isolation" not in _keys(r)


class TestNamespaceResourceGovernanceMissing:
    def test_positive(self):
        r = _governance(resource_quota_count=0, limit_range_count=0, quota_coverage_category="none")
        assert "kubernetes_namespace_resource_governance_missing" in _keys(r)

    def test_negative(self):
        r = _governance(resource_quota_count=1, limit_range_count=1, quota_coverage_category="broad")
        assert "kubernetes_namespace_resource_governance_missing" not in _keys(r)

    def test_unknown_partial(self):
        r = _governance(resource_quota_count=0, limit_range_count=0, quota_coverage_category="unknown")
        assert "kubernetes_namespace_resource_governance_missing" not in _keys(r)


# ═══════════════════════ Evidence safety ════════════════════════════════════


class TestEvidenceSafety:
    def test_no_forbidden_keys_across_all_rules(self):
        forbidden_substrings = [
            "secret_value", "config_map_value", "client-key-data", "token_value",
            "private_key", "ca_bundle_data", "environment_value", "command", "args",
            "pod_log", "audit_event", "request_body", "response_body",
        ]
        samples = [
            _container(privileged=True, dangerous_added_capability_categories=["SYS_ADMIN"], capabilities_added=["ALL"]),
            _workload(privileged_container_count=1, host_pid=True, dangerous_hostpath_categories=["docker_socket"]),
            _subject_binding(cluster_admin_binding=True, anonymous_subject=True, high_risk_permission_categories=["secret_read", "bind"]),
            _service(exposure_category="external_load_balancer"),
            _network_policy(allows_all_ingress=True, public_ipv4_cidr_allowed=True, public_ipv6_cidr_allowed=True),
            _webhook(failure_policy="Ignore", plaintext_http_client=True, wildcard_resource=True),
            _psa(enforce_level="privileged"),
            _governance(
                privileged_workload_present=True, psa_enforcement_category="unset",
                network_policy_coverage_category="none", high_privilege_service_account_present=True,
                governance_risk_summary="privileged_workload_weak_psa,high_privilege_identity_weak_governance",
            ),
        ]
        for record in samples:
            for finding in evaluate_record(record, "kubernetes"):
                import json
                blob = json.dumps(finding.evidence).lower()
                for bad in forbidden_substrings:
                    assert bad not in blob, f"{finding.rule_key} evidence leaked '{bad}': {finding.evidence}"

    def test_no_claim_discipline_violations(self):
        forbidden_phrases = [
            "compromised", "attacker has access", "secrets were stolen", "data was exposed",
            "container escaped", "internet attackers can reach", "credentials leaked",
            "bypassed", "breach", "exploit",
        ]
        samples = [
            _container(privileged=True),
            _workload(privileged_container_count=1, host_pid=True),
            _subject_binding(cluster_admin_binding=True, anonymous_subject=True),
            _service(exposure_category="external_load_balancer"),
        ]
        for record in samples:
            for finding in evaluate_record(record, "kubernetes"):
                text = f"{finding.title} {finding.description}".lower()
                for phrase in forbidden_phrases:
                    assert phrase not in text, f"{finding.rule_key} used forbidden phrase '{phrase}'"
