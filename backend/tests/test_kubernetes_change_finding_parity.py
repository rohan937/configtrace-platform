"""Kubernetes Change vs static Security Finding severity-parity tests
(Kubernetes message 7 of 9).

For every piece of evidence that both a static Finding (message 6,
app/services/security_rules/kubernetes.py) and a Change classifier
(app/services/risk_rules/kubernetes.py) can observe, a FRESH transition
into the bad state must never rank below the static Finding's severity
without a documented reason. Restoration/improvement transitions may
legitimately be low and are not required to match.
"""

from __future__ import annotations

from app.services import security_rule_pack
from app.services.risk_rules.kubernetes import classify_kubernetes_change

from tests.test_kubernetes_change_classification import (
    _container_ctx,
    _deployment,
    _diff,
    _find,
    _network_policy,
    _psa,
    _service,
    _subject_binding,
    _webhook,
)

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _classify(change: dict) -> tuple[str, str]:
    return classify_kubernetes_change(change)


def _static_severity(rule_key: str) -> str:
    _provider, severity, _category = security_rule_pack._RULE_META[rule_key]
    return severity


def _assert_not_below(change_severity: str, rule_key: str) -> None:
    static_sev = _static_severity(rule_key)
    assert _SEVERITY_RANK[change_severity] >= _SEVERITY_RANK[static_sev], (
        f"Change severity {change_severity!r} ranks below static Finding "
        f"{rule_key!r}'s severity {static_sev!r}"
    )


class TestWorkloadParity:
    def test_privileged_container_introduced(self):
        prev = [_container_ctx(privileged=False)]
        new = [_container_ctx(privileged=True)]
        c = _find(_diff(prev, new), field_path="privileged")
        _assert_not_below(_classify(c)[0], "kubernetes_privileged_container")

    def test_privileged_host_access_combo_added_workload(self):
        new_workload = _deployment(privileged_container_count=1, host_pid=True)
        c = _find(_diff([], [new_workload]), change_type="added")
        _assert_not_below(_classify(c)[0], "kubernetes_privileged_host_access")

    def test_runtime_socket_introduced(self):
        prev = [_deployment(dangerous_hostpath_categories=[])]
        new = [_deployment(dangerous_hostpath_categories=["docker_socket"])]
        c = _find(_diff(prev, new), field_path="dangerous_hostpath_categories")
        _assert_not_below(_classify(c)[0], "kubernetes_container_runtime_socket_mounted")

    def test_seccomp_unconfined_introduced(self):
        prev = [_container_ctx(seccomp_profile_category="runtime_default")]
        new = [_container_ctx(seccomp_profile_category="unconfined")]
        c = _find(_diff(prev, new), field_path="seccomp_profile_category")
        _assert_not_below(_classify(c)[0], "kubernetes_seccomp_unconfined")

    def test_dangerous_capability_introduced(self):
        prev = [_container_ctx(dangerous_added_capability_categories=[])]
        new = [_container_ctx(dangerous_added_capability_categories=["SYS_ADMIN"])]
        c = _find(_diff(prev, new), field_path="dangerous_added_capability_categories")
        _assert_not_below(_classify(c)[0], "kubernetes_dangerous_linux_capability")

    def test_automount_enabled(self):
        prev = [_deployment(automount_service_account_token=False)]
        new = [_deployment(automount_service_account_token=True)]
        c = _find(_diff(prev, new), field_path="automount_service_account_token")
        _assert_not_below(_classify(c)[0], "kubernetes_service_account_token_automount")


class TestRbacParity:
    def test_cluster_admin_granted(self):
        prev = [_subject_binding(cluster_admin_binding=False)]
        new = [_subject_binding(cluster_admin_binding=True)]
        c = _find(_diff(prev, new), field_path="cluster_admin_binding")
        _assert_not_below(_classify(c)[0], "kubernetes_cluster_admin_binding")

    def test_unauthenticated_cluster_admin_added(self):
        new_subject = _subject_binding(
            cluster_admin_binding=True, unauthenticated_group=True, resolved_privilege_category="critical",
        )
        c = _find(_diff([], [new_subject]), change_type="added")
        _assert_not_below(_classify(c)[0], "kubernetes_unauthenticated_cluster_admin")

    def test_wildcard_rbac_granted(self):
        prev = [_subject_binding(wildcard_permission_binding=False)]
        new = [_subject_binding(wildcard_permission_binding=True)]
        c = _find(_diff(prev, new), field_path="wildcard_permission_binding")
        _assert_not_below(_classify(c)[0], "kubernetes_wildcard_rbac_permissions")

    def test_bind_permission_granted(self):
        prev = [_subject_binding(high_risk_permission_categories=[])]
        new = [_subject_binding(high_risk_permission_categories=["bind"])]
        c = _find(_diff(prev, new), field_path="high_risk_permission_categories")
        _assert_not_below(_classify(c)[0], "kubernetes_rbac_bind_permission")

    def test_escalate_permission_granted(self):
        prev = [_subject_binding(high_risk_permission_categories=[])]
        new = [_subject_binding(high_risk_permission_categories=["escalate"])]
        c = _find(_diff(prev, new), field_path="high_risk_permission_categories")
        _assert_not_below(_classify(c)[0], "kubernetes_rbac_escalate_permission")

    def test_impersonate_permission_granted(self):
        prev = [_subject_binding(high_risk_permission_categories=[])]
        new = [_subject_binding(high_risk_permission_categories=["impersonate"])]
        c = _find(_diff(prev, new), field_path="high_risk_permission_categories")
        _assert_not_below(_classify(c)[0], "kubernetes_rbac_impersonate_permission")

    def test_secret_read_granted(self):
        prev = [_subject_binding(high_risk_permission_categories=[])]
        new = [_subject_binding(high_risk_permission_categories=["secret_read"])]
        c = _find(_diff(prev, new), field_path="high_risk_permission_categories")
        _assert_not_below(_classify(c)[0], "kubernetes_secret_read_permission")

    def test_pod_exec_granted(self):
        prev = [_subject_binding(high_risk_permission_categories=[])]
        new = [_subject_binding(high_risk_permission_categories=["pod_exec"])]
        c = _find(_diff(prev, new), field_path="high_risk_permission_categories")
        _assert_not_below(_classify(c)[0], "kubernetes_pod_exec_permission")


class TestNetworkParity:
    def test_public_load_balancer_assigned(self):
        prev = [_service(exposure_category="cluster_internal")]
        new = [_service(exposure_category="external_load_balancer")]
        c = _find(_diff(prev, new), field_path="exposure_category")
        _assert_not_below(_classify(c)[0], "kubernetes_public_load_balancer")

    def test_network_policy_allow_all_ingress(self):
        prev = [_network_policy(allows_all_ingress=False)]
        new = [_network_policy(allows_all_ingress=True)]
        c = _find(_diff(prev, new), field_path="allows_all_ingress")
        _assert_not_below(_classify(c)[0], "kubernetes_network_policy_allows_all_ingress")

    def test_unrestricted_ipv4_cidr(self):
        prev = [_network_policy(public_ipv4_cidr_allowed=False)]
        new = [_network_policy(public_ipv4_cidr_allowed=True)]
        c = _find(_diff(prev, new), field_path="public_ipv4_cidr_allowed")
        _assert_not_below(_classify(c)[0], "kubernetes_public_ipv4_cidr_allowed")

    def test_unrestricted_ipv6_cidr(self):
        prev = [_network_policy(public_ipv6_cidr_allowed=False)]
        new = [_network_policy(public_ipv6_cidr_allowed=True)]
        c = _find(_diff(prev, new), field_path="public_ipv6_cidr_allowed")
        _assert_not_below(_classify(c)[0], "kubernetes_public_ipv6_cidr_allowed")

    def test_ipv4_ipv6_change_parity(self):
        # The Change classifier itself must treat IPv4/IPv6 identically.
        prev4 = [_network_policy(public_ipv4_cidr_allowed=False)]
        new4 = [_network_policy(public_ipv4_cidr_allowed=True)]
        c4 = _find(_diff(prev4, new4), field_path="public_ipv4_cidr_allowed")
        prev6 = [_network_policy(public_ipv6_cidr_allowed=False)]
        new6 = [_network_policy(public_ipv6_cidr_allowed=True)]
        c6 = _find(_diff(prev6, new6), field_path="public_ipv6_cidr_allowed")
        assert _classify(c4)[0] == _classify(c6)[0]


class TestAdmissionParity:
    def test_validating_webhook_fail_open(self):
        prev = [_webhook(webhook_type="validating", failure_policy="Fail")]
        new = [_webhook(webhook_type="validating", failure_policy="Ignore")]
        c = _find(_diff(prev, new), field_path="failure_policy")
        _assert_not_below(_classify(c)[0], "kubernetes_validating_webhook_fail_open")

    def test_plaintext_webhook_introduced(self):
        prev = [_webhook(plaintext_http_client=False)]
        new = [_webhook(plaintext_http_client=True)]
        c = _find(_diff(prev, new), field_path="plaintext_http_client")
        _assert_not_below(_classify(c)[0], "kubernetes_admission_webhook_external_http")

    def test_wildcard_webhook_introduced(self):
        prev = [_webhook(wildcard_resource=False)]
        new = [_webhook(wildcard_resource=True)]
        c = _find(_diff(prev, new), field_path="wildcard_resource")
        _assert_not_below(_classify(c)[0], "kubernetes_broad_admission_webhook")


class TestPsaParity:
    def test_privileged_enforcement_introduced(self):
        prev = [_psa(enforce_level="restricted")]
        new = [_psa(enforce_level="privileged")]
        c = _find(_diff(prev, new), field_path="enforce_level")
        _assert_not_below(_classify(c)[0], "kubernetes_psa_privileged_enforcement")

    def test_enforcement_missing_introduced(self):
        prev = [_psa(enforce_level="restricted")]
        new = [_psa(enforce_level="unset")]
        c = _find(_diff(prev, new), field_path="enforce_level")
        _assert_not_below(_classify(c)[0], "kubernetes_psa_enforcement_missing")

    def test_invalid_enforcement_introduced(self):
        prev = [_psa(enforce_level="restricted")]
        new = [_psa(enforce_level="invalid")]
        c = _find(_diff(prev, new), field_path="enforce_level")
        _assert_not_below(_classify(c)[0], "kubernetes_psa_invalid_enforcement")


class TestRestorationMayBeLow:
    """Restoration/improvement transitions are explicitly allowed to be
    low/improvement severity and do NOT need to match the static Finding's
    (bad-state) severity — this is the documented exception in message 7's
    Finding-parity requirement."""

    def test_cluster_admin_removed_is_low_not_critical(self):
        prev = [_subject_binding(cluster_admin_binding=True)]
        new = [_subject_binding(cluster_admin_binding=False)]
        c = _find(_diff(prev, new), field_path="cluster_admin_binding")
        assert _classify(c)[0] == "low"

    def test_psa_restored_is_low_not_high(self):
        prev = [_psa(enforce_level="baseline")]
        new = [_psa(enforce_level="restricted")]
        c = _find(_diff(prev, new), field_path="enforce_level")
        assert _classify(c)[0] == "low"

    def test_webhook_failure_policy_restored_to_fail_is_low(self):
        prev = [_webhook(failure_policy="Ignore")]
        new = [_webhook(failure_policy="Fail")]
        c = _find(_diff(prev, new), field_path="failure_policy")
        assert _classify(c)[0] == "low"
