"""Kubernetes RBAC collection tests (Kubernetes message 3 of 9).

Covers collection of ServiceAccounts, Roles, ClusterRoles, RoleBindings,
and ClusterRoleBindings: namespace allowlist application, pagination,
independent per-family fail-soft behavior, and malformed-object isolation.

All tests are pure-mock; no real Kubernetes cluster is contacted.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from kubernetes.client.rest import ApiException

from app.connectors.kubernetes import (
    _collect_cluster_roles,
    _collect_rbac_bindings,
    _collect_roles,
    _collect_service_accounts,
)
from tests._kubernetes_rbac_fixtures import (
    make_cluster_role,
    make_cluster_role_binding,
    make_role,
    make_role_binding,
    make_service_account,
    page,
)


class TestServiceAccountCollection:
    def test_collects_and_normalizes(self):
        sa = make_service_account()
        list_fn = MagicMock(return_value=page([sa]))
        records, status = _collect_service_accounts(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert len(records) == 1
        assert records[0]["record_type"] == "kubernetes_service_account"
        assert records[0]["name"] == "deployer"

    def test_namespace_allowlist(self):
        sas = [make_service_account(namespace="prod", name="a"), make_service_account(namespace="staging", name="b")]
        list_fn = MagicMock(return_value=page(sas))
        records, _status = _collect_service_accounts(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=["prod"],
        )
        assert [r["namespace"] for r in records] == ["prod"]

    def test_403_reports_partial_without_raising(self):
        list_fn = MagicMock(side_effect=ApiException(status=403))
        records, status = _collect_service_accounts(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "partial"
        assert records == []

    def test_malformed_object_isolated(self):
        good = make_service_account(name="good")
        malformed = object()
        list_fn = MagicMock(return_value=page([malformed, good]))
        records, status = _collect_service_accounts(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert len(records) == 1
        assert records[0]["name"] == "good"


class TestRoleCollection:
    def test_collects_and_normalizes(self):
        role = make_role()
        list_fn = MagicMock(return_value=page([role]))
        records, status, index = _collect_roles(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert len(records) == 1
        assert records[0]["record_type"] == "kubernetes_role"
        assert ("Role", "prod", "reader") in index

    def test_namespace_allowlist(self):
        roles = [make_role(namespace="prod", name="a"), make_role(namespace="staging", name="b")]
        list_fn = MagicMock(return_value=page(roles))
        records, _status, _index = _collect_roles(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=["prod"],
        )
        assert [r["namespace"] for r in records] == ["prod"]

    def test_403_reports_partial(self):
        list_fn = MagicMock(side_effect=ApiException(status=403))
        records, status, index = _collect_roles(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "partial"
        assert records == []
        assert index == {}


class TestClusterRoleCollection:
    def test_collects_and_normalizes(self):
        cr = make_cluster_role()
        list_fn = MagicMock(return_value=page([cr]))
        records, status, index = _collect_cluster_roles(list_fn, cluster_id="c1", cluster_name="c1")
        assert status == "complete"
        assert len(records) == 1
        assert ("ClusterRole", None, "custom-role") in index

    def test_absent_api_group_reports_unsupported(self):
        list_fn = MagicMock(side_effect=ApiException(status=404))
        _records, status, _index = _collect_cluster_roles(list_fn, cluster_id="c1", cluster_name="c1")
        assert status == "unsupported"

    def test_malformed_object_isolated(self):
        good = make_cluster_role(name="good")
        malformed = object()
        list_fn = MagicMock(return_value=page([malformed, good]))
        records, status, _index = _collect_cluster_roles(list_fn, cluster_id="c1", cluster_name="c1")
        assert status == "complete"
        assert len(records) == 1
        assert records[0]["name"] == "good"


class TestBindingCollection:
    def test_role_binding_collects_and_resolves(self):
        role = make_role()
        _r, _s, role_index = _collect_roles(
            MagicMock(return_value=page([role])), cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        rb = make_role_binding()
        list_fn = MagicMock(return_value=page([rb]))
        bindings, subjects, status = _collect_rbac_bindings(
            list_fn, kind="RoleBinding", cluster_id="c1", cluster_name="c1",
            namespace_allowlist=None, role_index=role_index, role_collection_denied=False,
        )
        assert status == "complete"
        assert len(bindings) == 1
        assert bindings[0]["role_resolved"] is True
        assert len(subjects) == 1

    def test_cluster_role_binding_collects(self):
        crb = make_cluster_role_binding()
        list_fn = MagicMock(return_value=page([crb]))
        bindings, subjects, status = _collect_rbac_bindings(
            list_fn, kind="ClusterRoleBinding", cluster_id="c1", cluster_name="c1",
            namespace_allowlist=None, role_index={}, role_collection_denied=False,
        )
        assert status == "complete"
        assert len(bindings) == 1
        assert bindings[0]["role_resolved"] is False  # empty role_index
        assert len(subjects) == 1

    def test_namespace_allowlist_applies_to_role_bindings(self):
        bindings_raw = [make_role_binding(namespace="prod", name="a"), make_role_binding(namespace="staging", name="b")]
        list_fn = MagicMock(return_value=page(bindings_raw))
        bindings, _subjects, _status = _collect_rbac_bindings(
            list_fn, kind="RoleBinding", cluster_id="c1", cluster_name="c1",
            namespace_allowlist=["prod"], role_index={}, role_collection_denied=False,
        )
        assert [b["namespace"] for b in bindings] == ["prod"]

    def test_403_on_one_family_does_not_affect_another(self):
        deny_fn = MagicMock(side_effect=ApiException(status=403))
        ok_fn = MagicMock(return_value=page([make_cluster_role_binding()]))

        _b1, _s1, denied_status = _collect_rbac_bindings(
            deny_fn, kind="RoleBinding", cluster_id="c1", cluster_name="c1",
            namespace_allowlist=None, role_index={}, role_collection_denied=False,
        )
        b2, _s2, ok_status = _collect_rbac_bindings(
            ok_fn, kind="ClusterRoleBinding", cluster_id="c1", cluster_name="c1",
            namespace_allowlist=None, role_index={}, role_collection_denied=False,
        )
        assert denied_status == "partial"
        assert ok_status == "complete"
        assert len(b2) == 1

    def test_malformed_subject_isolated(self):
        from types import SimpleNamespace as NS

        class _RaisingSubject:
            @property
            def kind(self):
                raise ValueError("malformed subject")

        good_subject = NS(kind="User", name="alice", namespace=None)
        malformed_subject = _RaisingSubject()
        rb = make_role_binding(subjects=[malformed_subject, good_subject])
        list_fn = MagicMock(return_value=page([rb]))
        bindings, subjects, status = _collect_rbac_bindings(
            list_fn, kind="RoleBinding", cluster_id="c1", cluster_name="c1",
            namespace_allowlist=None, role_index={}, role_collection_denied=False,
        )
        assert status == "complete"
        assert len(bindings) == 1
        assert bindings[0]["subject_count"] == 1
        assert len(subjects) == 1
        assert subjects[0]["subject_name"] == "alice"

    def test_missing_role_ref_does_not_abort_collection(self):
        rb = make_role_binding(role_ref=None)
        list_fn = MagicMock(return_value=page([rb]))
        bindings, _subjects, status = _collect_rbac_bindings(
            list_fn, kind="RoleBinding", cluster_id="c1", cluster_name="c1",
            namespace_allowlist=None, role_index={}, role_collection_denied=False,
        )
        assert status == "complete"
        assert len(bindings) == 1
        assert bindings[0]["role_resolved"] is False
        assert bindings[0]["role_resolution_status"] == "malformed"  # no roleRef at all


class TestPaginationAndOrdering:
    def test_multiple_pages_collected(self):
        pages = [
            page([make_service_account(name="a")], continue_token="tok1"),
            page([make_service_account(name="b")], continue_token=None),
        ]
        list_fn = MagicMock(side_effect=pages)
        records, status = _collect_service_accounts(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert {r["name"] for r in records} == {"a", "b"}

    def test_deterministic_ordering(self):
        sas = [make_service_account(name="z"), make_service_account(name="a")]
        list_fn = MagicMock(return_value=page(sas))
        records, _status = _collect_service_accounts(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert [r["name"] for r in records] == ["a", "z"]

    def test_stable_uid_based_id(self):
        sa = make_service_account(uid="stable-uid")
        list_fn = MagicMock(return_value=page([sa]))
        records, _status = _collect_service_accounts(
            list_fn, cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert records[0]["record_id"] == "uid:c1/service_account/prod/stable-uid"

    def test_repeated_continuation_token_does_not_loop_forever(self):
        pages = [
            page([make_service_account(name="a")], continue_token="tok1"),
            page([make_service_account(name="b")], continue_token="tok1"),
        ]
        list_fn = MagicMock(side_effect=pages)
        records, status = _collect_service_accounts(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "partial"
        assert {r["name"] for r in records} == {"a", "b"}
