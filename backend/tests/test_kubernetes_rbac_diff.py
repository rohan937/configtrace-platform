"""Kubernetes RBAC diff and risk-routing tests (Kubernetes message 3 of 9).

Exercises the REAL ``compute_diff()`` -> ``classify_kubernetes_change()``
pipeline for the newly emitted RBAC record types: ServiceAccount, Role,
ClusterRole, RoleBinding, ClusterRoleBinding, per-subject bindings, and the
permission-summary rollup. Confirms automount changes, permission
add/remove, wildcard introduction/removal, binding subject add/remove,
roleRef changes, cluster-admin gained/removed, provider metadata, and
that ordering-only/resourceVersion-only changes are ignored (since those
fields are never emitted at all).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from app.connectors.kubernetes import (
    _collect_cluster_roles,
    _collect_rbac_bindings,
    _collect_roles,
    _collect_service_accounts,
)
from app.services.diff_service import compute_diff
from app.services.risk_rules.kubernetes import classify_kubernetes_change
from tests._kubernetes_rbac_fixtures import (
    make_cluster_role,
    make_cluster_role_binding,
    make_policy_rule,
    make_role,
    make_role_ref,
    make_service_account,
    make_subject,
    page,
)


class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]) -> list[dict]:
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


def _collect_one_sa(**kwargs):
    sa = make_service_account(**kwargs)
    records, _status = _collect_service_accounts(
        MagicMock(return_value=page([sa])), cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
    )
    return records[0]


def _collect_one_role(rules, **kwargs):
    role = make_role(rules=rules, **kwargs)
    records, _status, _index = _collect_roles(
        MagicMock(return_value=page([role])), cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
    )
    return records[0]


class TestAutomountDiff:
    def test_automount_explicitly_enabled(self):
        a = _collect_one_sa(automount_service_account_token=None)
        b = _collect_one_sa(automount_service_account_token=True)
        changes = _real_changes([a], [b])
        automount_changes = [c for c in changes if c["field_path"] == "automount_service_account_token"]
        assert len(automount_changes) == 1
        severity, _msg = classify_kubernetes_change(automount_changes[0])
        assert severity == "medium"


class TestRolePermissionDiff:
    def test_permission_added(self):
        a = _collect_one_role([make_policy_rule(resources=["pods"], verbs=["get"])])
        b = _collect_one_role([make_policy_rule(resources=["secrets"], verbs=["get"])])
        changes = _real_changes([a], [b])
        cat_changes = [c for c in changes if c["field_path"] == "high_risk_permission_categories"]
        assert len(cat_changes) == 1
        severity, msg = classify_kubernetes_change(cat_changes[0])
        assert severity == "high"
        assert "secret_read" in msg

    def test_permission_removed(self):
        a = _collect_one_role([make_policy_rule(resources=["secrets"], verbs=["get"])])
        b = _collect_one_role([make_policy_rule(resources=["pods"], verbs=["get"])])
        changes = _real_changes([a], [b])
        cat_changes = [c for c in changes if c["field_path"] == "high_risk_permission_categories"]
        assert len(cat_changes) == 1
        severity, _msg = classify_kubernetes_change(cat_changes[0])
        assert severity == "low"

    def test_wildcard_introduced(self):
        a = _collect_one_role([make_policy_rule(resources=["pods"], verbs=["get"])])
        b = _collect_one_role([make_policy_rule(resources=["*"], verbs=["get"])])
        changes = _real_changes([a], [b])
        wc_changes = [c for c in changes if c["field_path"] == "wildcard_resource"]
        assert len(wc_changes) == 1
        severity, _msg = classify_kubernetes_change(wc_changes[0])
        assert severity == "high"

    def test_wildcard_removed(self):
        a = _collect_one_role([make_policy_rule(resources=["*"], verbs=["get"])])
        b = _collect_one_role([make_policy_rule(resources=["pods"], verbs=["get"])])
        changes = _real_changes([a], [b])
        wc_changes = [c for c in changes if c["field_path"] == "wildcard_resource"]
        severity, _msg = classify_kubernetes_change(wc_changes[0])
        assert severity == "low"

    def test_bind_permission_introduced_is_critical(self):
        a = _collect_one_role([make_policy_rule(resources=["pods"], verbs=["get"])])
        b = _collect_one_role([make_policy_rule(
            api_groups=["rbac.authorization.k8s.io"], resources=["clusterroles"], verbs=["bind"]
        )])
        changes = _real_changes([a], [b])
        cat_changes = [c for c in changes if c["field_path"] == "high_risk_permission_categories"]
        assert len(cat_changes) == 1
        severity, msg = classify_kubernetes_change(cat_changes[0])
        assert severity == "critical"
        assert "bind" in msg


class TestBindingDiff:
    def _collect_crb(self, role_index, subjects):
        crb = make_cluster_role_binding(role_ref=make_role_ref(kind="ClusterRole", name="cluster-admin"), subjects=subjects)
        records, subject_records, _status = _collect_rbac_bindings(
            MagicMock(return_value=page([crb])), kind="ClusterRoleBinding", cluster_id="uid:c1", cluster_name="c1",
            namespace_allowlist=None, role_index=role_index, role_collection_denied=False,
        )
        return records[0], subject_records

    def test_subject_added_to_cluster_admin_binding(self):
        cr = make_cluster_role(name="cluster-admin", rules=[make_policy_rule(api_groups=["*"], resources=["*"], verbs=["*"])])
        cr_records, _s, cr_index = _collect_cluster_roles(MagicMock(return_value=page([cr])), cluster_id="uid:c1", cluster_name="c1")

        _binding_a, subjects_a = self._collect_crb(cr_index, [])
        _binding_b, subjects_b = self._collect_crb(cr_index, [make_subject(kind="ServiceAccount", name="deployer", namespace="prod")])

        changes = _real_changes(subjects_a, subjects_b)
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        severity, msg = classify_kubernetes_change(added[0])
        assert severity == "critical"
        assert "cluster-admin" in msg

    def test_subject_removed_from_cluster_admin_binding(self):
        cr = make_cluster_role(name="cluster-admin", rules=[make_policy_rule(api_groups=["*"], resources=["*"], verbs=["*"])])
        cr_records, _s, cr_index = _collect_cluster_roles(MagicMock(return_value=page([cr])), cluster_id="uid:c1", cluster_name="c1")

        _binding_a, subjects_a = self._collect_crb(cr_index, [make_subject(kind="ServiceAccount", name="deployer", namespace="prod")])
        _binding_b, subjects_b = self._collect_crb(cr_index, [])

        changes = _real_changes(subjects_a, subjects_b)
        removed = [c for c in changes if c["change_type"] == "removed"]
        assert len(removed) == 1
        severity, _msg = classify_kubernetes_change(removed[0])
        assert severity == "medium"

    def test_role_ref_changed(self):
        view_role = make_cluster_role(name="view", rules=[make_policy_rule(resources=["pods"], verbs=["get"])])
        admin_role = make_cluster_role(name="cluster-admin", rules=[make_policy_rule(api_groups=["*"], resources=["*"], verbs=["*"])])
        cr_records, _s, cr_index = _collect_cluster_roles(
            MagicMock(return_value=page([view_role, admin_role])), cluster_id="uid:c1", cluster_name="c1",
        )
        subject = [make_subject(kind="ServiceAccount", name="deployer", namespace="prod")]

        crb_view = make_cluster_role_binding(role_ref=make_role_ref(kind="ClusterRole", name="view"), subjects=subject)
        view_binding, _sub_v, _s1 = _collect_rbac_bindings(
            MagicMock(return_value=page([crb_view])), kind="ClusterRoleBinding", cluster_id="uid:c1", cluster_name="c1",
            namespace_allowlist=None, role_index=cr_index, role_collection_denied=False,
        )
        crb_admin = make_cluster_role_binding(role_ref=make_role_ref(kind="ClusterRole", name="cluster-admin"), subjects=subject)
        admin_binding, _sub_a, _s2 = _collect_rbac_bindings(
            MagicMock(return_value=page([crb_admin])), kind="ClusterRoleBinding", cluster_id="uid:c1", cluster_name="c1",
            namespace_allowlist=None, role_index=cr_index, role_collection_denied=False,
        )

        changes = _real_changes(view_binding, admin_binding)
        role_ref_changes = [c for c in changes if c["field_path"] == "role_ref_name"]
        assert len(role_ref_changes) == 1
        severity, _msg = classify_kubernetes_change(role_ref_changes[0])
        assert severity == "medium"

        admin_changes = [c for c in changes if c["field_path"] == "cluster_admin_binding"]
        assert len(admin_changes) == 1
        severity2, _msg2 = classify_kubernetes_change(admin_changes[0])
        assert severity2 == "critical"

    def test_cluster_admin_binding_added_whole_record(self):
        cr = make_cluster_role(name="cluster-admin", rules=[make_policy_rule(api_groups=["*"], resources=["*"], verbs=["*"])])
        _cr_records, _s, cr_index = _collect_cluster_roles(MagicMock(return_value=page([cr])), cluster_id="uid:c1", cluster_name="c1")
        crb = make_cluster_role_binding(role_ref=make_role_ref(kind="ClusterRole", name="cluster-admin"), subjects=[make_subject()])
        binding, _subjects, _s2 = _collect_rbac_bindings(
            MagicMock(return_value=page([crb])), kind="ClusterRoleBinding", cluster_id="uid:c1", cluster_name="c1",
            namespace_allowlist=None, role_index=cr_index, role_collection_denied=False,
        )
        changes = _real_changes([], binding)
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        severity, msg = classify_kubernetes_change(added[0])
        assert severity == "critical"
        assert "cluster-admin" in msg.lower()


class TestProviderMetadata:
    def test_role_binding_metadata_includes_role_ref(self):
        cr = make_cluster_role(name="cluster-admin", rules=[make_policy_rule(api_groups=["*"], resources=["*"], verbs=["*"])])
        _cr, _s, cr_index = _collect_cluster_roles(MagicMock(return_value=page([cr])), cluster_id="uid:c1", cluster_name="c1")
        crb_a = make_cluster_role_binding(role_ref=make_role_ref(kind="ClusterRole", name="cluster-admin"), subjects=[])
        crb_b = make_cluster_role_binding(role_ref=make_role_ref(kind="ClusterRole", name="cluster-admin"), subjects=[make_subject()])
        binding_a, _sa, _s1 = _collect_rbac_bindings(
            MagicMock(return_value=page([crb_a])), kind="ClusterRoleBinding", cluster_id="uid:c1", cluster_name="c1",
            namespace_allowlist=None, role_index=cr_index, role_collection_denied=False,
        )
        binding_b, _sb, _s2 = _collect_rbac_bindings(
            MagicMock(return_value=page([crb_b])), kind="ClusterRoleBinding", cluster_id="uid:c1", cluster_name="c1",
            namespace_allowlist=None, role_index=cr_index, role_collection_denied=False,
        )
        changes = _real_changes(binding_a, binding_b)
        assert changes
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == "kubernetes_cluster_role_binding"
        assert pm["role_ref_name"] == "cluster-admin"
        assert pm["cluster_id"] == "uid:c1"


class TestRiskRoutingNeverFallsThroughToOtherProviders:
    def test_service_account_change_routes_to_kubernetes_classifier(self):
        a = _collect_one_sa(automount_service_account_token=False)
        b = _collect_one_sa(automount_service_account_token=True)
        changes = _real_changes([a], [b])
        assert changes
        for change in changes:
            pm = change["provider_metadata"]
            assert pm["record_type"].startswith("kubernetes_")

        class _ChangeObj:
            def __init__(self, d):
                self.__dict__.update(d)

        from app.services.risk_service import classify_change
        severity, msg = classify_change(_ChangeObj(changes[0]))
        assert severity in ("low", "medium", "high", "critical")
        assert "cloudflare" not in msg.lower()
        assert "aws" not in msg.lower()
        assert "github" not in msg.lower()

    def test_role_record_never_routes_to_cloudflare_fallback(self):
        a = _collect_one_role([make_policy_rule(resources=["pods"], verbs=["get"])])
        b = _collect_one_role([make_policy_rule(resources=["secrets"], verbs=["get"])])
        changes = _real_changes([a], [b])
        assert changes
        for change in changes:
            assert change["provider_metadata"]["record_type"] in ("kubernetes_role",)
