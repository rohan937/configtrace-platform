"""Kubernetes NetworkPolicy tests (Kubernetes message 4 of 9).

Covers all isolation semantics (omitted vs. explicit-empty vs.
allow-all), selectors, IPv4/IPv6 public CIDR detection, CIDR exceptions,
port restrictions, and namespace network-posture rollups.

All tests are pure-mock; no real Kubernetes cluster is contacted.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from kubernetes.client.rest import ApiException

from app.connectors.kubernetes import (
    _build_namespace_network_postures,
    _collect_network_policies,
    _normalize_network_policy,
)
from app.connectors.kubernetes_schema import (
    POLICY_COVERAGE_BROAD,
    POLICY_COVERAGE_NONE,
    POLICY_COVERAGE_PARTIAL,
    POLICY_COVERAGE_UNKNOWN,
)
from tests._kubernetes_network_fixtures import (
    make_egress_rule_np,
    make_ingress_rule_np,
    make_ip_block,
    make_network_policy,
    make_peer,
    make_port_np,
    make_selector,
    page,
)


def _np_record(**kwargs):
    obj = make_network_policy(**kwargs)
    return _normalize_network_policy(obj, cluster_id="uid:c1", cluster_name="c1")


# ── AV-BN: selectors and semantics ────────────────────────────────────────────

class TestSelectors:
    def test_AV_selects_all_pods(self):
        record = _np_record(pod_selector=make_selector())
        assert record["pod_selector_empty_all_pods"] is True

    def test_AW_selects_subset(self):
        record = _np_record(pod_selector=make_selector(match_labels={"app": "web"}))
        assert record["pod_selector_empty_all_pods"] is False
        assert record["selected_label_key_count"] == 1


class TestIngressEgressSemantics:
    def test_AX_default_deny_ingress(self):
        record = _np_record(policy_types=["Ingress"], ingress=[])
        assert record["ingress_isolation_enabled"] is True
        assert record["empty_ingress_list"] is True
        assert record["allows_all_ingress"] is False

    def test_AY_default_deny_egress(self):
        record = _np_record(policy_types=["Egress"], egress=[])
        assert record["egress_isolation_enabled"] is True
        assert record["empty_egress_list"] is True
        assert record["allows_all_egress"] is False

    def test_AZ_allow_all_ingress(self):
        record = _np_record(policy_types=["Ingress"], ingress=[make_ingress_rule_np()])
        assert record["allows_all_ingress"] is True

    def test_BA_allow_all_egress(self):
        record = _np_record(policy_types=["Egress"], egress=[make_egress_rule_np()])
        assert record["allows_all_egress"] is True


class TestCidrDetection:
    def test_BB_public_ipv4_cidr(self):
        peer = make_peer(ip_block=make_ip_block(cidr="0.0.0.0/0"))
        record = _np_record(policy_types=["Ingress"], ingress=[make_ingress_rule_np(peers=[peer])])
        assert record["public_ipv4_cidr_allowed"] is True
        assert record["ip_block_present"] is True

    def test_BC_public_ipv6_cidr(self):
        peer = make_peer(ip_block=make_ip_block(cidr="::/0"))
        record = _np_record(policy_types=["Egress"], egress=[make_egress_rule_np(peers=[peer])])
        assert record["public_ipv6_cidr_allowed"] is True

    def test_BD_private_ipv4_cidr(self):
        peer = make_peer(ip_block=make_ip_block(cidr="10.0.0.0/8"))
        record = _np_record(policy_types=["Ingress"], ingress=[make_ingress_rule_np(peers=[peer])])
        assert record["public_ipv4_cidr_allowed"] is False
        assert record["broad_cidr_count"] == 0

    def test_BE_cidr_except_block(self):
        peer = make_peer(ip_block=make_ip_block(cidr="10.0.0.0/8", except_cidrs=["10.0.1.0/24", "10.0.2.0/24"]))
        record = _np_record(policy_types=["Ingress"], ingress=[make_ingress_rule_np(peers=[peer])])
        assert record["except_cidr_count"] == 2


class TestPeerSelectors:
    def test_BF_namespace_selector(self):
        peer = make_peer(namespace_selector=make_selector())
        record = _np_record(policy_types=["Ingress"], ingress=[make_ingress_rule_np(peers=[peer])])
        assert record["namespace_selector_present"] is True

    def test_BG_pod_selector_peer(self):
        peer = make_peer(pod_selector=make_selector(match_labels={"app": "trusted"}))
        record = _np_record(policy_types=["Ingress"], ingress=[make_ingress_rule_np(peers=[peer])])
        assert record["pod_selector_present"] is True

    def test_BH_empty_selector_semantics(self):
        # An empty (but present) namespaceSelector matches ALL namespaces —
        # presence is tracked; exact "all vs named" semantics are handled
        # at the namespace-posture rollup level (broad_namespace_selector_allowance).
        peer = make_peer(namespace_selector=make_selector())
        record = _np_record(policy_types=["Ingress"], ingress=[make_ingress_rule_np(peers=[peer])])
        assert record["namespace_selector_present"] is True


class TestDeclaredVsEmptyDistinction:
    def test_BI_omitted_ingress_field(self):
        record = _np_record(policy_types=["Egress"], ingress=None, egress=[])
        assert record["ingress_rules_declared"] is False
        assert record["ingress_isolation_enabled"] is False  # not in policyTypes

    def test_BJ_explicit_empty_ingress_list(self):
        record = _np_record(policy_types=["Ingress"], ingress=[])
        assert record["ingress_rules_declared"] is True
        assert record["empty_ingress_list"] is True

    def test_BK_ingress_rule_empty_object(self):
        record = _np_record(policy_types=["Ingress"], ingress=[make_ingress_rule_np()])
        assert record["ingress_rule_count"] == 1
        assert record["allows_all_ingress"] is True

    def test_BL_omitted_egress_field(self):
        record = _np_record(policy_types=["Ingress"], ingress=[], egress=None)
        assert record["egress_rules_declared"] is False
        assert record["egress_isolation_enabled"] is False

    def test_BM_explicit_empty_egress_list(self):
        record = _np_record(policy_types=["Egress"], egress=[])
        assert record["egress_rules_declared"] is True
        assert record["empty_egress_list"] is True

    def test_BN_egress_rule_empty_object(self):
        record = _np_record(policy_types=["Egress"], egress=[make_egress_rule_np()])
        assert record["allows_all_egress"] is True

    def test_omitted_and_empty_produce_same_effective_state_but_are_distinguishable(self):
        omitted = _np_record(policy_types=["Ingress"], ingress=None)
        explicit_empty = _np_record(policy_types=["Ingress"], ingress=[])
        # Same effective behavior (both deny-all)...
        assert omitted["empty_ingress_list"] == explicit_empty["empty_ingress_list"] is True
        # ...but never silently treated as equivalent at the schema level.
        assert omitted["ingress_rules_declared"] != explicit_empty["ingress_rules_declared"]


class TestPortsAndProtocols:
    def test_BO_port_restricted_rule(self):
        peer = make_peer(pod_selector=make_selector())
        rule = make_ingress_rule_np(peers=[peer], ports=[make_port_np(protocol="TCP", port=443)])
        record = _np_record(policy_types=["Ingress"], ingress=[rule])
        assert record["port_restriction_present"] is True
        assert record["protocol_categories"] == ["TCP"]

    def test_BP_unrestricted_protocol_port(self):
        record = _np_record(policy_types=["Ingress"], ingress=[make_ingress_rule_np()])
        assert record["port_restriction_present"] is False


class TestMalformedCidr:
    def test_CD_malformed_cidr_becomes_unknown(self):
        peer = make_peer(ip_block=make_ip_block(cidr="not-a-real-cidr"))
        record = _np_record(policy_types=["Ingress"], ingress=[make_ingress_rule_np(peers=[peer])])
        assert record["public_ipv4_cidr_allowed"] is False
        assert record["public_ipv6_cidr_allowed"] is False
        assert record["broad_cidr_count"] == 0  # unknown_malformed is not counted as broad-public


class TestNetworkPolicyCollectionFailSoft:
    def test_CG_403_reports_partial(self):
        list_fn = MagicMock(side_effect=ApiException(status=403))
        records, status = _collect_network_policies(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "partial"
        assert records == []

    def test_namespace_allowlist(self):
        policies = [make_network_policy(namespace="prod", name="a"), make_network_policy(namespace="staging", name="b")]
        list_fn = MagicMock(return_value=page(policies))
        records, _status = _collect_network_policies(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=["prod"],
        )
        assert [r["namespace"] for r in records] == ["prod"]

    def test_malformed_object_isolated(self):
        good = make_network_policy(name="good")
        malformed = object()
        list_fn = MagicMock(return_value=page([malformed, good]))
        records, status = _collect_network_policies(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert len(records) == 1


# ── BQ-BT: namespace rollups ───────────────────────────────────────────────────

class TestNamespaceNetworkPosture:
    def test_BQ_namespace_no_policies(self):
        postures = _build_namespace_network_postures(
            [], ["empty-ns"], cluster_id="c1", cluster_name="c1", collection_status="complete",
        )
        assert postures[0]["policy_coverage_category"] == POLICY_COVERAGE_NONE
        assert postures[0]["has_any_network_policy"] is False

    def test_BR_namespace_partial_isolation(self):
        policy = _np_record(policy_types=["Ingress"], ingress=[make_ingress_rule_np()])
        postures = _build_namespace_network_postures(
            [policy], ["prod"], cluster_id="c1", cluster_name="c1", collection_status="complete",
        )
        assert postures[0]["policy_coverage_category"] == POLICY_COVERAGE_PARTIAL

    def test_BS_namespace_full_ingress_default_deny(self):
        policy = _np_record(policy_types=["Ingress"], ingress=[], pod_selector=make_selector())
        postures = _build_namespace_network_postures(
            [policy], ["prod"], cluster_id="c1", cluster_name="c1", collection_status="complete",
        )
        assert postures[0]["all_pod_ingress_default_deny"] is True

    def test_BT_namespace_full_egress_default_deny(self):
        policy = _np_record(policy_types=["Egress"], egress=[], pod_selector=make_selector())
        postures = _build_namespace_network_postures(
            [policy], ["prod"], cluster_id="c1", cluster_name="c1", collection_status="complete",
        )
        assert postures[0]["all_pod_egress_default_deny"] is True

    def test_broad_coverage_requires_both_ingress_and_egress_deny(self):
        policy = _np_record(
            policy_types=["Ingress", "Egress"], ingress=[], egress=[], pod_selector=make_selector(),
        )
        postures = _build_namespace_network_postures(
            [policy], ["prod"], cluster_id="c1", cluster_name="c1", collection_status="complete",
        )
        assert postures[0]["policy_coverage_category"] == POLICY_COVERAGE_BROAD

    def test_CG_incomplete_collection_marks_unknown_coverage(self):
        policy = _np_record(policy_types=["Ingress"], ingress=[])
        postures = _build_namespace_network_postures(
            [policy], ["prod"], cluster_id="c1", cluster_name="c1", collection_status="partial",
        )
        assert postures[0]["policy_coverage_category"] == POLICY_COVERAGE_UNKNOWN

    def test_public_ingress_allowance_present(self):
        peer = make_peer(ip_block=make_ip_block(cidr="0.0.0.0/0"))
        policy = _np_record(policy_types=["Ingress"], ingress=[make_ingress_rule_np(peers=[peer])])
        postures = _build_namespace_network_postures(
            [policy], ["prod"], cluster_id="c1", cluster_name="c1", collection_status="complete",
        )
        assert postures[0]["public_ingress_allowance_present"] is True


class TestSensitiveDataExclusion:
    def test_no_arbitrary_selector_labels_persisted_only_counts(self):
        import json
        record = _np_record(pod_selector=make_selector(match_labels={"secret-project-codename": "phoenix"}))
        assert "secret-project-codename" not in json.dumps(record)
        assert "phoenix" not in json.dumps(record)
        assert record["selected_label_key_count"] == 1
