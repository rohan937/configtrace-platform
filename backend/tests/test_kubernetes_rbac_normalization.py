"""Kubernetes RBAC normalization tests (Kubernetes message 3 of 9).

Covers rule categorization (API groups/resources/verbs/non-resource URLs),
wildcard detection, the dangerous-permission taxonomy, built-in role
recognition, subject-type normalization, role resolution, aggregation
handling (including cycle protection), permission fingerprints, and
deterministic ordering.

All tests are pure-mock; no real Kubernetes cluster is contacted.
"""

from __future__ import annotations

from app.connectors.kubernetes import (
    _categorize_subject,
    _normalize_role_object,
    _resolve_aggregated_rules,
    _resolve_role_ref,
    _summarize_rbac_rules,
    resolve_effective_automount,
)
from app.connectors.kubernetes_schema import (
    BUILTIN_ROLE_ADMIN,
    BUILTIN_ROLE_CLUSTER_ADMIN,
    BUILTIN_ROLE_EDIT,
    BUILTIN_ROLE_NONE,
    BUILTIN_ROLE_SYSTEM,
    BUILTIN_ROLE_VIEW,
    ROLE_RESOLUTION_MALFORMED,
    ROLE_RESOLUTION_MISSING,
    ROLE_RESOLUTION_RESOLVED,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    categorize_api_group,
    categorize_builtin_role,
    categorize_non_resource_url,
    categorize_resource,
)
from tests._kubernetes_rbac_fixtures import (
    make_aggregation_rule,
    make_cluster_role,
    make_policy_rule,
    make_role,
    make_role_ref,
    make_subject,
)


# ── H-X: rule categorization / dangerous permission taxonomy ────────────────

class TestRuleCategorization:
    def test_narrow_read_only_pods(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["pods"], verbs=["get", "list"])])
        assert summary["pod_read"] is True
        assert summary["pod_write"] is False
        assert summary["highest_severity_category"] == SEVERITY_LOW

    def test_read_configmaps(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["configmaps"], verbs=["get"])])
        assert summary["configmap_read"] is True

    def test_read_secrets(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["secrets"], verbs=["get", "list"])])
        assert summary["secret_read"] is True
        assert "secret_read" in summary["high_risk_permission_categories"]
        assert summary["highest_severity_category"] == SEVERITY_HIGH

    def test_write_secrets(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["secrets"], verbs=["create", "update"])])
        assert summary["secret_write"] is True

    def test_pod_exec(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["pods/exec"], verbs=["create"])])
        assert summary["pod_exec"] is True
        assert summary["highest_severity_category"] == SEVERITY_HIGH

    def test_pod_attach(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["pods/attach"], verbs=["create"])])
        assert summary["pod_attach"] is True

    def test_pod_port_forward(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["pods/portforward"], verbs=["create"])])
        assert summary["pod_port_forward"] is True

    def test_pod_logs(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["pods/log"], verbs=["get"])])
        assert summary["pod_logs"] is True

    def test_create_pods(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["pods"], verbs=["create"])])
        assert summary["pod_write"] is True

    def test_create_deployments(self):
        summary = _summarize_rbac_rules(
            [make_policy_rule(api_groups=["apps"], resources=["deployments"], verbs=["create"])]
        )
        assert summary["workload_write"] is True

    def test_mutate_rbac(self):
        summary = _summarize_rbac_rules(
            [make_policy_rule(api_groups=["rbac.authorization.k8s.io"], resources=["roles"], verbs=["create"])]
        )
        assert summary["rbac_write"] is True

    def test_bind_permission(self):
        summary = _summarize_rbac_rules(
            [make_policy_rule(api_groups=["rbac.authorization.k8s.io"], resources=["clusterroles"], verbs=["bind"])]
        )
        assert summary["bind_permission"] is True
        assert "bind" in summary["high_risk_permission_categories"]
        assert summary["highest_severity_category"] == SEVERITY_CRITICAL

    def test_escalate_permission(self):
        summary = _summarize_rbac_rules(
            [make_policy_rule(api_groups=["rbac.authorization.k8s.io"], resources=["clusterroles"], verbs=["escalate"])]
        )
        assert summary["escalate_permission"] is True
        assert summary["highest_severity_category"] == SEVERITY_CRITICAL

    def test_impersonate_users(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["users"], verbs=["impersonate"])])
        assert summary["impersonate_permission"] is True
        assert summary["highest_severity_category"] == SEVERITY_CRITICAL

    def test_impersonate_serviceaccounts(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["serviceaccounts"], verbs=["impersonate"])])
        assert summary["impersonate_permission"] is True

    def test_create_service_account_tokens(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["serviceaccounts/token"], verbs=["create"])])
        assert summary["service_account_token_creation"] is True
        assert summary["token_request_access"] is True
        assert summary["highest_severity_category"] == SEVERITY_CRITICAL

    def test_approve_csrs(self):
        summary = _summarize_rbac_rules(
            [make_policy_rule(api_groups=["certificates.k8s.io"], resources=["certificatesigningrequests/approval"], verbs=["update"])]
        )
        assert summary["csr_approve_permission"] is True
        assert summary["highest_severity_category"] == SEVERITY_CRITICAL


class TestWildcards:
    def test_wildcard_verbs(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["pods"], verbs=["*"])])
        assert summary["wildcard_verb"] is True
        assert summary["highest_severity_category"] == SEVERITY_HIGH

    def test_wildcard_resources(self):
        summary = _summarize_rbac_rules([make_policy_rule(resources=["*"], verbs=["get"])])
        assert summary["wildcard_resource"] is True

    def test_wildcard_api_groups(self):
        summary = _summarize_rbac_rules([make_policy_rule(api_groups=["*"], resources=["pods"], verbs=["get"])])
        assert summary["wildcard_api_group"] is True

    def test_full_wildcard(self):
        summary = _summarize_rbac_rules([make_policy_rule(api_groups=["*"], resources=["*"], verbs=["*"])])
        assert summary["wildcard_api_group"] and summary["wildcard_resource"] and summary["wildcard_verb"]
        assert "full_wildcard" in summary["high_risk_permission_categories"]
        assert summary["highest_severity_category"] == SEVERITY_CRITICAL

    def test_resource_name_restricted_access(self):
        summary = _summarize_rbac_rules(
            [make_policy_rule(resources=["configmaps"], verbs=["get"], resource_names=["my-config"])]
        )
        assert summary["resource_name_restriction_present"] is True


class TestNonResourceUrls:
    def test_health_url(self):
        assert categorize_non_resource_url("/healthz") == "health_version"

    def test_wildcard_url(self):
        summary = _summarize_rbac_rules([make_policy_rule(api_groups=None, resources=None, verbs=["get"], non_resource_urls=["*"])])
        assert summary["wildcard_non_resource_url"] is True
        assert "non_resource_broad" in summary["high_risk_permission_categories"]


class TestBuiltinRoles:
    def test_view(self):
        assert categorize_builtin_role("view") == BUILTIN_ROLE_VIEW

    def test_edit(self):
        assert categorize_builtin_role("edit") == BUILTIN_ROLE_EDIT

    def test_admin(self):
        assert categorize_builtin_role("admin") == BUILTIN_ROLE_ADMIN

    def test_cluster_admin(self):
        assert categorize_builtin_role("cluster-admin") == BUILTIN_ROLE_CLUSTER_ADMIN

    def test_system_role(self):
        assert categorize_builtin_role("system:node") == BUILTIN_ROLE_SYSTEM

    def test_custom_role_is_none_category(self):
        assert categorize_builtin_role("my-custom-role") == BUILTIN_ROLE_NONE

    def test_cluster_admin_existence_is_not_itself_flagged_critical(self):
        # Recognizing the built-in role is not a judgement — only real
        # bindings to it carry risk. A standalone ClusterRole record for
        # cluster-admin with no other dangerous flags surfaced is handled
        # by the risk classifier's "added" branch, not by this function.
        cr = make_cluster_role(name="cluster-admin", rules=[make_policy_rule(resources=["pods"], verbs=["get"])])
        record = _normalize_role_object(cr, kind="ClusterRole", cluster_id="c1", cluster_name="c1")
        assert record["built_in_role_category"] == BUILTIN_ROLE_CLUSTER_ADMIN


# ── AK, AL, AM: aggregation ──────────────────────────────────────────────────

class TestAggregation:
    def test_aggregated_cluster_role_resolves_matched_permissions(self):
        role_labels = {
            "aggregate-base": {"rbac.example.com/aggregate-to-admin": "true"},
            "aggregating": {},
        }
        role_rules = {
            "aggregate-base": [make_policy_rule(resources=["secrets"], verbs=["get"])],
            "aggregating": [],
        }
        role_selectors = {
            "aggregating": [{"rbac.example.com/aggregate-to-admin": "true"}],
        }
        resolved, complete = _resolve_aggregated_rules(
            "aggregating", role_labels, role_rules, role_selectors, frozenset(),
        )
        assert complete is True
        assert len(resolved) == 1

    def test_aggregation_cycle_is_detected_and_marked_incomplete(self):
        role_labels = {"a": {"x": "1"}, "b": {"x": "1"}}
        role_rules = {"a": [], "b": []}
        role_selectors = {"a": [{"x": "1"}], "b": [{"x": "1"}]}
        _resolved, complete = _resolve_aggregated_rules("a", role_labels, role_rules, role_selectors, frozenset())
        assert complete is False

    def test_aggregated_role_with_no_matches_is_resolved_but_empty(self):
        role_labels = {"solo": {}}
        role_rules = {"solo": []}
        role_selectors = {"solo": [{"nonexistent-label": "true"}]}
        resolved, complete = _resolve_aggregated_rules("solo", role_labels, role_rules, role_selectors, frozenset())
        assert complete is True
        assert resolved == []

    def test_aggregation_rule_present_is_recorded(self):
        agg = make_aggregation_rule([{"rbac.authorization.k8s.io/aggregate-to-admin": "true"}])
        cr = make_cluster_role(name="custom-admin-aggregate", aggregation_rule=agg)
        record = _normalize_role_object(cr, kind="ClusterRole", cluster_id="c1", cluster_name="c1")
        assert record["aggregation_rule_present"] is True
        assert record["aggregation_selector_count"] == 1


# ── AN-AR: role resolution ───────────────────────────────────────────────────

class TestRoleResolution:
    def test_role_binding_to_role(self):
        role_record = {"name": "reader"}
        index = {("Role", "prod", "reader"): role_record}
        role, status, kind, name, group = _resolve_role_ref(
            make_role_ref(kind="Role", name="reader"), namespace="prod", role_index=index,
        )
        assert role is role_record
        assert status == ROLE_RESOLUTION_RESOLVED

    def test_role_binding_to_cluster_role(self):
        role_record = {"name": "view"}
        index = {("ClusterRole", None, "view"): role_record}
        role, status, kind, name, group = _resolve_role_ref(
            make_role_ref(kind="ClusterRole", name="view"), namespace="prod", role_index=index,
        )
        assert role is role_record
        assert status == ROLE_RESOLUTION_RESOLVED

    def test_missing_role(self):
        role, status, kind, name, group = _resolve_role_ref(
            make_role_ref(kind="Role", name="nonexistent"), namespace="prod", role_index={},
        )
        assert role is None
        assert status == ROLE_RESOLUTION_MISSING

    def test_malformed_role_ref(self):
        from types import SimpleNamespace as NS
        role, status, kind, name, group = _resolve_role_ref(
            NS(kind=None, name=None, api_group=""), namespace="prod", role_index={},
        )
        assert role is None
        assert status == ROLE_RESOLUTION_MALFORMED

    def test_same_role_name_in_different_namespaces_is_distinct(self):
        index = {
            ("Role", "ns-a", "reader"): {"name": "reader", "ns": "a"},
            ("Role", "ns-b", "reader"): {"name": "reader", "ns": "b"},
        }
        role_a, _s, _k, _n, _g = _resolve_role_ref(make_role_ref(kind="Role", name="reader"), namespace="ns-a", role_index=index)
        role_b, _s, _k, _n, _g = _resolve_role_ref(make_role_ref(kind="Role", name="reader"), namespace="ns-b", role_index=index)
        assert role_a["ns"] == "a"
        assert role_b["ns"] == "b"


# ── AS-BA: subject handling ───────────────────────────────────────────────────

class TestSubjectHandling:
    def test_user_subject(self):
        info = _categorize_subject(make_subject(kind="User", name="alice", namespace=None))
        assert info["subject_kind"] == "User"
        assert info["subject_identity"] == "alice"

    def test_group_subject(self):
        info = _categorize_subject(make_subject(kind="Group", name="developers", namespace=None))
        assert info["subject_kind"] == "Group"

    def test_service_account_subject(self):
        info = _categorize_subject(make_subject(kind="ServiceAccount", name="deployer", namespace="prod"))
        assert info["subject_identity"] == "system:serviceaccount:prod:deployer"

    def test_system_authenticated(self):
        info = _categorize_subject(make_subject(kind="Group", name="system:authenticated", namespace=None))
        assert info["authenticated_group"] is True
        assert info["broad_group"] is True

    def test_system_unauthenticated(self):
        info = _categorize_subject(make_subject(kind="Group", name="system:unauthenticated", namespace=None))
        assert info["unauthenticated_group"] is True
        assert info["broad_group"] is True

    def test_system_serviceaccounts_cluster_wide(self):
        info = _categorize_subject(make_subject(kind="Group", name="system:serviceaccounts", namespace=None))
        assert info["system_group"] is True
        assert info["broad_group"] is True

    def test_system_serviceaccounts_namespaced_is_not_broad(self):
        info = _categorize_subject(make_subject(kind="Group", name="system:serviceaccounts:prod", namespace=None))
        assert info["system_group"] is True
        assert info["broad_group"] is False

    def test_system_masters(self):
        info = _categorize_subject(make_subject(kind="Group", name="system:masters", namespace=None))
        assert info["system_group"] is True

    def test_anonymous_user(self):
        info = _categorize_subject(make_subject(kind="User", name="system:anonymous", namespace=None))
        assert info["anonymous_subject"] is True


# ── Ordering / fingerprints ───────────────────────────────────────────────────

class TestFingerprintsAndOrdering:
    def test_fingerprint_is_deterministic(self):
        rules = [make_policy_rule(resources=["secrets"], verbs=["get", "list"])]
        s1 = _summarize_rbac_rules(rules)
        s2 = _summarize_rbac_rules(rules)
        assert s1["permission_fingerprint"] == s2["permission_fingerprint"]

    def test_fingerprint_differs_for_different_permissions(self):
        s1 = _summarize_rbac_rules([make_policy_rule(resources=["secrets"], verbs=["get"])])
        s2 = _summarize_rbac_rules([make_policy_rule(resources=["pods"], verbs=["get"])])
        assert s1["permission_fingerprint"] != s2["permission_fingerprint"]

    def test_categories_are_sorted(self):
        summary = _summarize_rbac_rules([
            make_policy_rule(resources=["secrets", "pods"], verbs=["get", "list"]),
        ])
        assert summary["resource_categories"] == sorted(summary["resource_categories"])

    def test_no_cartesian_explosion(self):
        # 5 resources x 4 verbs must not become 20 records — categorization
        # accumulates into a single summary dict.
        rule = make_policy_rule(
            resources=["pods", "secrets", "configmaps", "services", "nodes"],
            verbs=["get", "list", "watch", "create"],
        )
        summary = _summarize_rbac_rules([rule])
        assert summary["rule_count"] == 1
        assert isinstance(summary["resource_categories"], list)


class TestMalformedRules:
    def test_malformed_rule_is_skipped_not_fatal(self):
        good_rule = make_policy_rule(resources=["pods"], verbs=["get"])

        class _RaisingRule:
            @property
            def api_groups(self):
                raise ValueError("malformed")

        summary = _summarize_rbac_rules([_RaisingRule(), good_rule])
        assert summary["rule_count"] == 1
        assert summary["pod_read"] is True


class TestAutomountResolution:
    def test_workload_explicit_true_wins(self):
        state, source = resolve_effective_automount(workload_explicit=True, sa_automount_explicit=False, sa_status="found")
        assert state == "explicit_workload_true"
        assert source == "workload_explicit"

    def test_inherited_from_service_account(self):
        state, source = resolve_effective_automount(workload_explicit=None, sa_automount_explicit=True, sa_status="found")
        assert state == "inherited_service_account_true"
        assert source == "service_account_explicit"

    def test_kubernetes_default_when_both_omitted(self):
        state, source = resolve_effective_automount(workload_explicit=None, sa_automount_explicit=None, sa_status="found")
        assert state == "kubernetes_default_true"
        assert source == "kubernetes_default"

    def test_missing_service_account_is_unknown_not_default_true(self):
        state, source = resolve_effective_automount(workload_explicit=None, sa_automount_explicit=None, sa_status="missing")
        assert state == "unknown_service_account_missing"
        assert source == "unknown"

    def test_access_denied_is_unknown_not_default_true(self):
        state, source = resolve_effective_automount(workload_explicit=None, sa_automount_explicit=None, sa_status="access_denied")
        assert state == "unknown_permission_denied"
        assert source == "unknown"
