"""Kubernetes Security Finding connector-shape reachability tests
(Kubernetes message 6 of 9).

For at least one representative rule from every category, proves the full
path: a real Kubernetes API-shaped fake object -> the connector's actual
normalize/collect function -> a real normalized record -> evaluate_record()
-> a Finding with the expected rule key. This is not testing hand-fabricated
dictionaries — it exercises the same normalization code the live connector
uses (app/connectors/kubernetes.py).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from app.connectors.kubernetes import (
    KUBERNETES_DEPLOYMENT,
    _collect_rbac_bindings,
    _collect_workload_family,
    _normalize_network_policy,
    _normalize_pod_security_admission,
    _normalize_service,
    _normalize_webhook_configuration,
)
from app.services.security_finding_evaluator import evaluate_record
from tests._kubernetes_admission_fixtures import (
    make_client_config,
    make_rule as make_webhook_rule,
    make_service_ref,
    make_webhook,
    make_webhook_configuration,
    page as admission_page,
)
from tests._kubernetes_network_fixtures import (
    make_ingress_rule_np,
    make_ip_block,
    make_network_policy,
    make_peer,
    make_service,
)
from tests._kubernetes_rbac_fixtures import (
    make_cluster_role_binding,
    make_role_ref,
    make_subject,
    page as rbac_page,
)
from tests._kubernetes_workload_fixtures import (
    make_container,
    make_deployment,
    make_pod_spec,
    make_security_context,
    page as workload_page,
)


def _rule_keys(record):
    return {f.rule_key for f in evaluate_record(record, "kubernetes")}


class TestWorkloadReachability:
    """Real Deployment -> _collect_workload_family() -> Finding."""

    def test_privileged_container_reachable_from_real_collection(self):
        sc = make_security_context(privileged=True)
        container = make_container(security_context=sc)
        pod_spec = make_pod_spec(containers=[container])
        deployment = make_deployment(pod_spec=pod_spec)
        list_fn = MagicMock(return_value=workload_page([deployment]))

        _controllers, containers, status = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
        )

        assert status == "complete"
        assert len(containers) == 1
        assert containers[0]["privileged"] is True
        assert "kubernetes_privileged_container" in _rule_keys(containers[0])

    def test_host_pid_reachable_from_real_collection(self):
        pod_spec = make_pod_spec(host_pid=True)
        deployment = make_deployment(pod_spec=pod_spec)
        list_fn = MagicMock(return_value=workload_page([deployment]))

        controllers, _containers, status = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
        )

        assert status == "complete"
        assert controllers[0]["host_pid"] is True
        assert "kubernetes_host_pid_enabled" in _rule_keys(controllers[0])

    def test_privileged_host_access_combo_reachable(self):
        sc = make_security_context(privileged=True)
        container = make_container(security_context=sc)
        pod_spec = make_pod_spec(containers=[container], host_pid=True)
        deployment = make_deployment(pod_spec=pod_spec)
        list_fn = MagicMock(return_value=workload_page([deployment]))

        controllers, _containers, _status = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
        )

        assert "kubernetes_privileged_host_access" in _rule_keys(controllers[0])

    def test_safe_deployment_yields_no_workload_findings(self):
        deployment = make_deployment()
        list_fn = MagicMock(return_value=workload_page([deployment]))

        controllers, containers, _status = _collect_workload_family(
            list_fn, kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
            cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
        )

        assert _rule_keys(controllers[0]) == set()
        assert _rule_keys(containers[0]) == set()


class TestRbacReachability:
    """Real ClusterRoleBinding -> _collect_rbac_bindings() -> Finding."""

    def test_cluster_admin_binding_reachable_from_real_collection(self):
        crb = make_cluster_role_binding(
            role_ref=make_role_ref(kind="ClusterRole", name="cluster-admin"),
            subjects=[make_subject(kind="User", name="alice", namespace=None)],
        )
        list_fn = MagicMock(return_value=rbac_page([crb]))

        _bindings, subjects, status = _collect_rbac_bindings(
            list_fn, kind="ClusterRoleBinding", cluster_id="uid:c1", cluster_name="c1",
            namespace_allowlist=None, role_index={}, role_collection_denied=False,
        )

        assert status == "complete"
        assert len(subjects) == 1
        assert subjects[0]["cluster_admin_binding"] is True
        assert "kubernetes_cluster_admin_binding" in _rule_keys(subjects[0])

    def test_unauthenticated_cluster_admin_reachable(self):
        crb = make_cluster_role_binding(
            role_ref=make_role_ref(kind="ClusterRole", name="cluster-admin"),
            subjects=[make_subject(kind="Group", name="system:unauthenticated", namespace=None)],
        )
        list_fn = MagicMock(return_value=rbac_page([crb]))

        _bindings, subjects, _status = _collect_rbac_bindings(
            list_fn, kind="ClusterRoleBinding", cluster_id="uid:c1", cluster_name="c1",
            namespace_allowlist=None, role_index={}, role_collection_denied=False,
        )

        assert "kubernetes_unauthenticated_cluster_admin" in _rule_keys(subjects[0])

    def test_safe_binding_yields_no_rbac_findings(self):
        crb = make_cluster_role_binding(
            role_ref=make_role_ref(kind="ClusterRole", name="view"),
            subjects=[make_subject(kind="User", name="alice", namespace=None)],
        )
        list_fn = MagicMock(return_value=rbac_page([crb]))

        _bindings, subjects, _status = _collect_rbac_bindings(
            list_fn, kind="ClusterRoleBinding", cluster_id="uid:c1", cluster_name="c1",
            namespace_allowlist=None, role_index={}, role_collection_denied=False,
        )

        assert _rule_keys(subjects[0]) == set()


class TestNetworkReachability:
    """Real Service -> _normalize_service() -> Finding."""

    def test_public_load_balancer_reachable(self):
        svc = make_service(
            service_type="LoadBalancer",
            lb_ingress=["203.0.113.10"],
        )
        record, _ports = _normalize_service(svc, cluster_id="uid:c1", cluster_name="c1")
        assert record["exposure_category"] == "external_load_balancer"
        assert "kubernetes_public_load_balancer" in _rule_keys(record)

    def test_cluster_ip_service_yields_no_exposure_finding(self):
        svc = make_service(service_type="ClusterIP")
        record, _ports = _normalize_service(svc, cluster_id="uid:c1", cluster_name="c1")
        assert "kubernetes_public_load_balancer" not in _rule_keys(record)


class TestNetworkPolicyReachability:
    """Real NetworkPolicy -> _normalize_network_policy() -> Finding."""

    def test_allow_all_ingress_reachable(self):
        np = make_network_policy(ingress=[make_ingress_rule_np(peers=[])])
        record = _normalize_network_policy(np, cluster_id="uid:c1", cluster_name="c1")
        assert record["allows_all_ingress"] is True
        assert "kubernetes_network_policy_allows_all_ingress" in _rule_keys(record)

    def test_public_ipv4_cidr_reachable(self):
        np = make_network_policy(
            ingress=[make_ingress_rule_np(peers=[make_peer(ip_block=make_ip_block(cidr="0.0.0.0/0"))])],
        )
        record = _normalize_network_policy(np, cluster_id="uid:c1", cluster_name="c1")
        assert record["public_ipv4_cidr_allowed"] is True
        assert "kubernetes_public_ipv4_cidr_allowed" in _rule_keys(record)

    def test_scoped_policy_yields_no_findings(self):
        np = make_network_policy(
            ingress=[make_ingress_rule_np(peers=[make_peer(ip_block=make_ip_block(cidr="10.0.0.0/8"))])],
        )
        record = _normalize_network_policy(np, cluster_id="uid:c1", cluster_name="c1")
        assert _rule_keys(record) == set()


class TestAdmissionReachability:
    """Real ValidatingWebhookConfiguration -> _normalize_webhook_configuration() -> Finding."""

    def test_fail_open_webhook_reachable(self):
        webhook = make_webhook(
            name="wh1", failure_policy="Ignore",
            client_config=make_client_config(service=make_service_ref()),
            rules=[make_webhook_rule()],
        )
        config = make_webhook_configuration(webhooks=[webhook])
        _config_record, webhooks = _normalize_webhook_configuration(
            config, kind="validating", cluster_id="uid:c1", cluster_name="c1",
        )
        assert webhooks[0]["failure_policy"] == "Ignore"
        assert "kubernetes_validating_webhook_fail_open" in _rule_keys(webhooks[0])

    def test_fail_closed_webhook_yields_no_finding(self):
        webhook = make_webhook(
            name="wh1", failure_policy="Fail",
            client_config=make_client_config(service=make_service_ref()),
            rules=[make_webhook_rule()],
        )
        config = make_webhook_configuration(webhooks=[webhook])
        _config_record, webhooks = _normalize_webhook_configuration(
            config, kind="validating", cluster_id="uid:c1", cluster_name="c1",
        )
        assert "kubernetes_validating_webhook_fail_open" not in _rule_keys(webhooks[0])


class TestPodSecurityAdmissionReachability:
    """Real namespace record -> _normalize_pod_security_admission() -> Finding."""

    def test_privileged_enforcement_reachable(self):
        ns_record = {"name": "prod", "psa_enforce": "privileged", "psa_enforce_version": None,
                     "psa_audit": None, "psa_audit_version": None, "psa_warn": None, "psa_warn_version": None}
        record = _normalize_pod_security_admission(
            ns_record, cluster_id="uid:c1", cluster_name="c1", cluster_major_minor="1.29",
        )
        assert record["enforce_level"] == "privileged"
        assert "kubernetes_psa_privileged_enforcement" in _rule_keys(record)

    def test_restricted_enforcement_yields_no_finding(self):
        ns_record = {"name": "prod", "psa_enforce": "restricted", "psa_enforce_version": None,
                     "psa_audit": None, "psa_audit_version": None, "psa_warn": None, "psa_warn_version": None}
        record = _normalize_pod_security_admission(
            ns_record, cluster_id="uid:c1", cluster_name="c1", cluster_major_minor="1.29",
        )
        assert "kubernetes_psa_privileged_enforcement" not in _rule_keys(record)


class TestGovernanceRollupUsesRealRecordShape:
    """The namespace governance record shape from the connector's TypedDict
    is exercised end-to-end via the pure-dict path already covered in
    test_kubernetes_security_findings.py; here we confirm the exact field
    names the connector emits are the ones the rule reads."""

    def test_governance_record_typed_fields_match_rule_expectations(self):
        from app.connectors import kubernetes_schema as ks

        # Every field the kubernetes.py rule module reads on a governance
        # record must be declared on the TypedDict — this catches silent
        # renames between the connector and the rule module.
        annotations = ks.KubernetesNamespaceGovernancePostureRecord.__annotations__
        required_fields = {
            "psa_enforcement_category", "network_policy_coverage_category",
            "privileged_workload_present", "high_privilege_service_account_present",
            "governance_risk_summary", "governance_completeness_category",
            "resource_quota_count", "limit_range_count", "quota_coverage_category",
        }
        missing = required_fields - set(annotations)
        assert not missing, f"governance TypedDict missing fields the rule module reads: {missing}"
