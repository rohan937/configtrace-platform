"""Kubernetes Change added/removed posture tests (Kubernetes message 7 of 9).

For every emitted family: an added/removed Change must inspect the FULL
new/previous record (never a scalar ``field_path``), and a newly-added
risky record must be classified according to its actual posture — not a
flat generic "resource added" — while a removed protective record may
itself be a weakening.
"""

from __future__ import annotations

from app.services.risk_rules.kubernetes import classify_kubernetes_change

from tests.test_kubernetes_change_classification import (
    _container_ctx,
    _deployment,
    _diff,
    _find,
    _governance,
    _network_policy,
    _psa,
    _service,
    _subject_binding,
    _webhook,
)


def _classify(change: dict) -> tuple[str, str]:
    return classify_kubernetes_change(change)


class TestWorkloadAddedRemoved:
    def test_new_workload_already_privileged_and_host_pid_is_critical(self):
        # Exact match to the static kubernetes_privileged_host_access combo —
        # Finding-severity parity requires Critical here, not a flat generic.
        new_workload = _deployment(privileged_container_count=1, host_pid=True)
        c = _find(_diff([], [new_workload]), change_type="added")
        assert _classify(c)[0] == "critical"

    def test_new_workload_already_has_runtime_socket_and_privileged_is_critical(self):
        new_workload = _deployment(privileged_container_count=1, dangerous_hostpath_categories=["docker_socket"])
        c = _find(_diff([], [new_workload]), change_type="added")
        assert _classify(c)[0] == "critical"

    def test_new_workload_privileged_alone_is_high_not_critical(self):
        new_workload = _deployment(privileged_container_count=1, security_posture_summary="privileged_or_host_access")
        c = _find(_diff([], [new_workload]), change_type="added")
        assert _classify(c)[0] == "high"

    def test_new_safe_workload_is_low(self):
        new_workload = _deployment()
        c = _find(_diff([], [new_workload]), change_type="added")
        assert _classify(c)[0] == "low"

    def test_dangerous_workload_removed_is_medium_not_high(self):
        # Removal is an availability/visibility concern, not itself a new
        # danger — must not rank as high as introducing the same posture.
        old_workload = _deployment(privileged_container_count=1, host_pid=True)
        c = _find(_diff([old_workload], []), change_type="removed")
        assert _classify(c)[0] == "medium"

    def test_safe_workload_removed_is_low(self):
        old_workload = _deployment()
        c = _find(_diff([old_workload], []), change_type="removed")
        assert _classify(c)[0] == "low"

    def test_added_branch_uses_whole_record_not_scalar_field(self):
        # An "added" Change's new_value must be the complete record dict
        # (not a bare scalar) — the classifier's whole-record inspection
        # depends on this.
        new_workload = _deployment(privileged_container_count=1, host_pid=True)
        c = _find(_diff([], [new_workload]), change_type="added")
        assert isinstance(c["new_value"], dict)
        assert c["field_path"] is None
        assert c["prev_value"] is None


class TestContainerAddedRemoved:
    def test_new_privileged_container_is_high(self):
        new_container = _container_ctx(privileged=True)
        c = _find(_diff([], [new_container]), change_type="added")
        assert _classify(c)[0] == "high"

    def test_new_safe_container_is_low(self):
        new_container = _container_ctx()
        c = _find(_diff([], [new_container]), change_type="added")
        assert _classify(c)[0] == "low"

    def test_removed_branch_uses_whole_record(self):
        old_container = _container_ctx(privileged=True)
        c = _find(_diff([old_container], []), change_type="removed")
        assert isinstance(c["prev_value"], dict)
        assert c["new_value"] is None


class TestRbacAddedRemoved:
    def test_new_cluster_admin_binding_is_critical(self):
        new_subject = _subject_binding(cluster_admin_binding=True, resolved_privilege_category="critical")
        c = _find(_diff([], [new_subject]), change_type="added")
        assert _classify(c)[0] == "critical"

    def test_new_anonymous_subject_with_meaningful_access_is_critical(self):
        new_subject = _subject_binding(anonymous_subject=True, resolved_privilege_category="high")
        c = _find(_diff([], [new_subject]), change_type="added")
        assert _classify(c)[0] == "critical"

    def test_new_unauthenticated_group_with_meaningful_access_is_critical(self):
        new_subject = _subject_binding(unauthenticated_group=True, resolved_privilege_category="critical")
        c = _find(_diff([], [new_subject]), change_type="added")
        assert _classify(c)[0] == "critical"

    def test_new_safe_read_only_subject_is_low(self):
        new_subject = _subject_binding(resolved_privilege_category="low")
        c = _find(_diff([], [new_subject]), change_type="added")
        assert _classify(c)[0] == "low"

    def test_new_subject_with_unresolved_role_is_medium(self):
        new_subject = _subject_binding(role_resolved=False, role_resolution_status="unresolved", resolved_privilege_category="unknown")
        c = _find(_diff([], [new_subject]), change_type="added")
        assert _classify(c)[0] == "medium"

    def test_cluster_admin_binding_removed_is_medium(self):
        old_subject = _subject_binding(cluster_admin_binding=True)
        c = _find(_diff([old_subject], []), change_type="removed")
        assert _classify(c)[0] == "medium"

    def test_low_privilege_binding_removed_is_low(self):
        old_subject = _subject_binding(resolved_privilege_category="low")
        c = _find(_diff([old_subject], []), change_type="removed")
        assert _classify(c)[0] == "low"


class TestNetworkAddedRemoved:
    def test_new_externally_exposed_service_is_high(self):
        new_service = _service(exposure_category="external_load_balancer")
        c = _find(_diff([], [new_service]), change_type="added")
        assert _classify(c)[0] == "high"

    def test_new_nodeport_service_is_medium(self):
        new_service = _service(exposure_category="node_port", service_type="NodePort")
        c = _find(_diff([], [new_service]), change_type="added")
        assert _classify(c)[0] == "medium"

    def test_new_internal_service_is_low(self):
        new_service = _service()
        c = _find(_diff([], [new_service]), change_type="added")
        assert _classify(c)[0] == "low"

    def test_removed_external_service_is_low_not_high(self):
        # Removal of exposure is an improvement direction, not itself risky.
        old_service = _service(exposure_category="external_load_balancer")
        c = _find(_diff([old_service], []), change_type="removed")
        assert _classify(c)[0] == "low"


class TestNetworkPolicyAddedRemoved:
    def test_new_policy_already_allow_all_for_all_pods_is_high(self):
        new_policy = _network_policy(
            allows_all_ingress=True, pod_selector_empty_all_pods=True,
        )
        c = _find(_diff([], [new_policy]), change_type="added")
        assert _classify(c)[0] == "high"

    def test_new_policy_already_default_deny_is_low(self):
        new_policy = _network_policy(empty_ingress_list=True, empty_egress_list=True)
        c = _find(_diff([], [new_policy]), change_type="added")
        assert _classify(c)[0] == "low"

    def test_removed_default_deny_policy_for_all_pods_is_high(self):
        old_policy = _network_policy(
            pod_selector_empty_all_pods=True, empty_ingress_list=True,
        )
        c = _find(_diff([old_policy], []), change_type="removed")
        assert _classify(c)[0] == "high"

    def test_removed_narrow_policy_is_low(self):
        old_policy = _network_policy(pod_selector_empty_all_pods=False)
        c = _find(_diff([old_policy], []), change_type="removed")
        assert _classify(c)[0] == "low"


class TestWebhookAddedRemoved:
    def test_new_fail_open_webhook_is_medium(self):
        new_webhook = _webhook(failure_policy="Ignore")
        c = _find(_diff([], [new_webhook]), change_type="added")
        assert _classify(c)[0] == "medium"

    def test_new_wildcard_webhook_is_high(self):
        new_webhook = _webhook(wildcard_operation=True, wildcard_api_group=True, wildcard_resource=True)
        c = _find(_diff([], [new_webhook]), change_type="added")
        assert _classify(c)[0] == "high"

    def test_new_safe_narrow_webhook_is_low(self):
        new_webhook = _webhook()
        c = _find(_diff([], [new_webhook]), change_type="added")
        assert _classify(c)[0] == "low"

    def test_removed_fail_closed_validating_webhook_is_high(self):
        old_webhook = _webhook(webhook_type="validating", failure_policy="Fail")
        c = _find(_diff([old_webhook], []), change_type="removed")
        assert _classify(c)[0] == "high"

    def test_removed_fail_open_webhook_is_not_high(self):
        # A fail-open webhook provided little protection to begin with —
        # its removal must not rank as high as removing fail-closed coverage.
        old_webhook = _webhook(webhook_type="validating", failure_policy="Ignore")
        c = _find(_diff([old_webhook], []), change_type="removed")
        assert _classify(c)[0] != "high"

    def test_removed_mutating_webhook_is_medium(self):
        old_webhook = _webhook(webhook_type="mutating", failure_policy="Fail")
        c = _find(_diff([old_webhook], []), change_type="removed")
        assert _classify(c)[0] == "medium"


class TestPsaAddedRemoved:
    def test_new_namespace_with_invalid_psa_is_high(self):
        new_psa = _psa(enforce_level="invalid")
        c = _find(_diff([], [new_psa]), change_type="added")
        assert _classify(c)[0] == "high"

    def test_new_namespace_with_unset_psa_is_low(self):
        new_psa = _psa(enforce_level="unset")
        c = _find(_diff([], [new_psa]), change_type="added")
        assert _classify(c)[0] == "low"


class TestGovernanceAddedRemoved:
    def test_new_governance_rollup_is_low(self):
        new_rollup = _governance()
        c = _find(_diff([], [new_rollup]), change_type="added")
        assert _classify(c)[0] == "low"

    def test_removed_governance_rollup_is_low(self):
        old_rollup = _governance()
        c = _find(_diff([old_rollup], []), change_type="removed")
        assert _classify(c)[0] == "low"
