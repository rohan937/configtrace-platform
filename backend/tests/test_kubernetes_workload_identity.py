"""Kubernetes workload identity resolution tests (Kubernetes message 3 of 9).

Covers the identity graph: workload -> ServiceAccount -> RoleBinding/
ClusterRoleBinding -> Role/ClusterRole -> permission categories. Verifies
ServiceAccount enrichment, workload-service-account rollup enrichment,
the RBAC permission-summary rollup, missing/denied ServiceAccount
handling, and aggregate privilege across multiple bindings.

All tests are pure-mock; no real Kubernetes cluster is contacted.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from app.connectors.kubernetes import (
    _aggregate_workload_service_accounts,
    _build_rbac_permission_summaries,
    _collect_cluster_roles,
    _collect_rbac_bindings,
    _collect_roles,
    _collect_service_accounts,
    _enrich_service_accounts,
    _enrich_workload_service_accounts,
)
from tests._kubernetes_rbac_fixtures import (
    make_cluster_role,
    make_cluster_role_binding,
    make_policy_rule,
    make_role,
    make_role_binding,
    make_role_ref,
    make_service_account,
    make_subject,
    page,
)


def _setup_cluster_admin_binding():
    """A ClusterRole 'cluster-admin' bound to ServiceAccount prod/deployer."""
    cr = make_cluster_role(
        name="cluster-admin",
        rules=[make_policy_rule(api_groups=["*"], resources=["*"], verbs=["*"])],
    )
    cr_records, _s, cr_index = _collect_cluster_roles(MagicMock(return_value=page([cr])), cluster_id="c1", cluster_name="c1")

    crb = make_cluster_role_binding(
        role_ref=make_role_ref(kind="ClusterRole", name="cluster-admin"),
        subjects=[make_subject(kind="ServiceAccount", name="deployer", namespace="prod")],
    )
    crb_records, subjects, _status = _collect_rbac_bindings(
        MagicMock(return_value=page([crb])), kind="ClusterRoleBinding", cluster_id="c1", cluster_name="c1",
        namespace_allowlist=None, role_index=cr_index, role_collection_denied=False,
    )
    return cr_records, crb_records, subjects


class TestServiceAccountEnrichment:
    def test_service_account_gains_cluster_admin_from_binding(self):
        _cr, _crb, subjects = _setup_cluster_admin_binding()
        sa = make_service_account(namespace="prod", name="deployer")
        sa_records, _status = _collect_service_accounts(
            MagicMock(return_value=page([sa])), cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        _enrich_service_accounts(sa_records, subjects, [])
        assert sa_records[0]["cluster_admin_bound"] is True
        assert sa_records[0]["highest_privilege_category"] == "critical"

    def test_service_account_without_bindings_stays_low(self):
        sa = make_service_account(namespace="prod", name="unbound")
        sa_records, _status = _collect_service_accounts(
            MagicMock(return_value=page([sa])), cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        _enrich_service_accounts(sa_records, [], [])
        assert sa_records[0]["cluster_admin_bound"] is False
        assert sa_records[0]["highest_privilege_category"] == "low"

    def test_workload_reference_count_from_workload_records(self):
        sa = make_service_account(namespace="prod", name="deployer")
        sa_records, _status = _collect_service_accounts(
            MagicMock(return_value=page([sa])), cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        workload_records = [
            {"namespace": "prod", "service_account_name": "deployer"},
            {"namespace": "prod", "service_account_name": "deployer"},
            {"namespace": "prod", "service_account_name": "other"},
        ]
        _enrich_service_accounts(sa_records, [], workload_records)
        assert sa_records[0]["workload_reference_count"] == 2

    def test_aggregate_privilege_across_multiple_bindings(self):
        # Role granting secret_read (RoleBinding) + ClusterRole granting
        # pod_exec (ClusterRoleBinding) both bound to the same SA.
        role = make_role(namespace="prod", name="secret-reader", rules=[make_policy_rule(resources=["secrets"], verbs=["get"])])
        _r, _s, role_index = _collect_roles(
            MagicMock(return_value=page([role])), cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        rb = make_role_binding(
            namespace="prod", role_ref=make_role_ref(kind="Role", name="secret-reader"),
            subjects=[make_subject(kind="ServiceAccount", name="multi", namespace="prod")],
        )
        rb_records, rb_subjects, _s1 = _collect_rbac_bindings(
            MagicMock(return_value=page([rb])), kind="RoleBinding", cluster_id="c1", cluster_name="c1",
            namespace_allowlist=None, role_index=role_index, role_collection_denied=False,
        )

        cr = make_cluster_role(name="exec-role", rules=[make_policy_rule(resources=["pods/exec"], verbs=["create"])])
        cr_records, _s2, cr_index = _collect_cluster_roles(MagicMock(return_value=page([cr])), cluster_id="c1", cluster_name="c1")
        crb = make_cluster_role_binding(
            role_ref=make_role_ref(kind="ClusterRole", name="exec-role"),
            subjects=[make_subject(kind="ServiceAccount", name="multi", namespace="prod")],
        )
        crb_records, crb_subjects, _s3 = _collect_rbac_bindings(
            MagicMock(return_value=page([crb])), kind="ClusterRoleBinding", cluster_id="c1", cluster_name="c1",
            namespace_allowlist=None, role_index=cr_index, role_collection_denied=False,
        )

        all_subjects = rb_subjects + crb_subjects
        sa = make_service_account(namespace="prod", name="multi")
        sa_records, _status = _collect_service_accounts(
            MagicMock(return_value=page([sa])), cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        _enrich_service_accounts(sa_records, all_subjects, [])

        assert sa_records[0]["secret_read_permission_bound"] is True
        assert sa_records[0]["pod_exec_permission_bound"] is True
        assert sa_records[0]["bound_role_binding_count"] == 1
        assert sa_records[0]["bound_cluster_role_binding_count"] == 1

        summaries = _build_rbac_permission_summaries(all_subjects, cluster_id="c1", cluster_name="c1")
        assert len(summaries) == 1
        assert summaries[0]["secret_read_bound"] is True
        assert summaries[0]["pod_exec_bound"] is True
        assert summaries[0]["role_binding_count"] == 1
        assert summaries[0]["cluster_role_binding_count"] == 1


class TestWorkloadServiceAccountEnrichment:
    def test_effective_automount_resolved_when_sa_found(self):
        workload_records = [{"namespace": "prod", "service_account_name": "deployer", "automount_service_account_token": None}]
        rollups = _aggregate_workload_service_accounts(workload_records, cluster_id="c1", cluster_name="c1")
        sa = make_service_account(namespace="prod", name="deployer", automount_service_account_token=False)
        sa_records, _status = _collect_service_accounts(
            MagicMock(return_value=page([sa])), cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        _enrich_service_accounts(sa_records, [], workload_records)
        _enrich_workload_service_accounts(rollups, sa_records, "complete")
        assert rollups[0]["service_account_found"] is True
        assert rollups[0]["effective_automount_state"] == "inherited_service_account_false"
        assert rollups[0]["automount_source_category"] == "service_account_explicit"

    def test_missing_service_account_marked_unknown_not_default_true(self):
        workload_records = [{"namespace": "prod", "service_account_name": "ghost", "automount_service_account_token": None}]
        rollups = _aggregate_workload_service_accounts(workload_records, cluster_id="c1", cluster_name="c1")
        _enrich_workload_service_accounts(rollups, [], "complete")
        assert rollups[0]["service_account_found"] is False
        assert rollups[0]["effective_automount_state"] == "unknown_service_account_missing"
        assert rollups[0]["collection_completeness_category"] == "complete"  # genuinely absent, not denied

    def test_permission_denied_service_account_collection_marks_partial(self):
        workload_records = [{"namespace": "prod", "service_account_name": "ghost", "automount_service_account_token": None}]
        rollups = _aggregate_workload_service_accounts(workload_records, cluster_id="c1", cluster_name="c1")
        _enrich_workload_service_accounts(rollups, [], "partial")
        assert rollups[0]["effective_automount_state"] == "unknown_permission_denied"
        assert rollups[0]["collection_completeness_category"] == "partial"

    def test_risky_permission_categories_propagate_to_rollup(self):
        workload_records = [{"namespace": "prod", "service_account_name": "deployer", "automount_service_account_token": None}]
        rollups = _aggregate_workload_service_accounts(workload_records, cluster_id="c1", cluster_name="c1")
        _cr, _crb, subjects = _setup_cluster_admin_binding()
        sa = make_service_account(namespace="prod", name="deployer")
        sa_records, _status = _collect_service_accounts(
            MagicMock(return_value=page([sa])), cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        _enrich_service_accounts(sa_records, subjects, workload_records)
        _enrich_workload_service_accounts(rollups, sa_records, "complete")
        assert rollups[0]["service_account_privilege_summary"] == "critical"
        assert rollups[0]["bound_cluster_role_binding_count"] == 1
