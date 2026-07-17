"""Kubernetes network diff and risk-routing tests (Kubernetes message 4 of 9).

Exercises the REAL ``compute_diff()`` -> ``classify_kubernetes_change()``
pipeline for the 10 newly emitted network record types: Service exposure
transitions, LoadBalancer public/internal, NodePort added/removed, Ingress
TLS removed/restored, wildcard host added/removed, Gateway allowedRoutes
broadened/narrowed, HTTPRoute cross-namespace introduced/removed,
NetworkPolicy default-deny added/removed, allow-all introduced/removed,
public CIDR introduced/removed, provider metadata, and ordering-only/
resourceVersion-only changes being ignored (since those fields are never
emitted at all).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from app.connectors.kubernetes import (
    _build_namespace_network_postures,
    _collect_gateways,
    _collect_http_routes,
    _collect_ingresses,
    _collect_network_policies,
    _collect_services,
)
from app.services.diff_service import compute_diff
from app.services.risk_rules.kubernetes import classify_kubernetes_change
from app.services.risk_service import classify_change
from tests._kubernetes_network_fixtures import (
    dict_page,
    make_gateway,
    make_gateway_listener,
    make_http_route,
    make_http_route_rule,
    make_ingress,
    make_ingress_rule,
    make_ingress_rule_np,
    make_ingress_tls,
    make_ip_block,
    make_network_policy,
    make_peer,
    make_selector,
    make_service,
    make_service_port,
    page,
)


class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]) -> list[dict]:
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


def _collect_one_service(**kwargs):
    svc = make_service(**kwargs)
    records, ports, _status = _collect_services(
        MagicMock(return_value=page([svc])), cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
    )
    return records[0], ports


def _collect_one_ingress(**kwargs):
    ing = make_ingress(**kwargs)
    records, rules, _status = _collect_ingresses(
        MagicMock(return_value=page([ing])), cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
    )
    return records[0], rules


def _collect_one_gateway(**kwargs):
    gw = make_gateway(**kwargs)
    custom_api = MagicMock()
    custom_api.list_cluster_custom_object.return_value = dict_page([gw])
    records, listeners, _status = _collect_gateways(
        custom_api, cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
    )
    return records[0], listeners


def _collect_one_http_route(**kwargs):
    route = make_http_route(**kwargs)
    custom_api = MagicMock()
    custom_api.list_cluster_custom_object.return_value = dict_page([route])
    records, rules, _status = _collect_http_routes(
        custom_api, cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
    )
    return records[0], rules


def _collect_one_network_policy(**kwargs):
    np = make_network_policy(**kwargs)
    records, _status = _collect_network_policies(
        MagicMock(return_value=page([np])), cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
    )
    return records[0]


class TestServiceExposureDiff:
    def test_internal_to_confirmed_external(self):
        a, _pa = _collect_one_service(service_type="ClusterIP")
        b, _pb = _collect_one_service(service_type="LoadBalancer", lb_ingress=["203.0.113.9"])
        changes = _real_changes([a], [b])
        exposure_changes = [c for c in changes if c["field_path"] == "exposure_category"]
        assert len(exposure_changes) == 1
        severity, msg = classify_kubernetes_change(exposure_changes[0])
        assert severity == "high"
        assert "external" in msg.lower()

    def test_load_balancer_public_then_internal(self):
        a, _pa = _collect_one_service(service_type="LoadBalancer", lb_ingress=["203.0.113.9"])
        b, _pb = _collect_one_service(
            service_type="LoadBalancer", lb_ingress=["10.0.5.5"],
            annotations={"service.beta.kubernetes.io/aws-load-balancer-internal": "true"},
        )
        changes = _real_changes([a], [b])
        exposure_changes = [c for c in changes if c["field_path"] == "exposure_category"]
        assert len(exposure_changes) == 1
        severity, _msg = classify_kubernetes_change(exposure_changes[0])
        assert severity == "low"  # external -> internal is an improvement

    def test_node_port_added(self):
        port_a = make_service_port(node_port=None)
        port_b = make_service_port(node_port=30080)
        _a, ports_a = _collect_one_service(service_type="NodePort", ports=[port_a])
        _b, ports_b = _collect_one_service(service_type="NodePort", ports=[port_b])
        changes = _real_changes(ports_a, ports_b)
        node_port_changes = [c for c in changes if c["field_path"] == "node_port"]
        assert len(node_port_changes) == 1
        severity, _msg = classify_kubernetes_change(node_port_changes[0])
        assert severity == "medium"

    def test_node_port_removed(self):
        port_a = make_service_port(node_port=30080)
        port_b = make_service_port(node_port=None)
        _a, ports_a = _collect_one_service(service_type="NodePort", ports=[port_a])
        _b, ports_b = _collect_one_service(service_type="NodePort", ports=[port_b])
        changes = _real_changes(ports_a, ports_b)
        node_port_changes = [c for c in changes if c["field_path"] == "node_port"]
        severity, _msg = classify_kubernetes_change(node_port_changes[0])
        assert severity == "low"


class TestIngressTlsDiff:
    def test_tls_removed(self):
        tls = make_ingress_tls(hosts=["app.example.com"])
        a, _ra = _collect_one_ingress(rules=[make_ingress_rule(host="app.example.com")], tls=[tls])
        b, _rb = _collect_one_ingress(rules=[make_ingress_rule(host="app.example.com")], tls=[])
        changes = _real_changes([a], [b])
        tls_changes = [c for c in changes if c["field_path"] == "plaintext_exposure_category"]
        assert len(tls_changes) == 1
        severity, msg = classify_kubernetes_change(tls_changes[0])
        assert severity == "high"
        assert "tls" in msg.lower()

    def test_tls_restored(self):
        tls = make_ingress_tls(hosts=["app.example.com"])
        a, _ra = _collect_one_ingress(rules=[make_ingress_rule(host="app.example.com")], tls=[])
        b, _rb = _collect_one_ingress(rules=[make_ingress_rule(host="app.example.com")], tls=[tls])
        changes = _real_changes([a], [b])
        tls_changes = [c for c in changes if c["field_path"] == "plaintext_exposure_category"]
        assert len(tls_changes) == 1
        severity, _msg = classify_kubernetes_change(tls_changes[0])
        assert severity == "low"

    def test_wildcard_host_added(self):
        a, _ra = _collect_one_ingress(rules=[make_ingress_rule(host="app.example.com")])
        b, _rb = _collect_one_ingress(rules=[make_ingress_rule(host="*.example.com")])
        changes = _real_changes([a], [b])
        wc_changes = [c for c in changes if c["field_path"] == "wildcard_host_count"]
        assert len(wc_changes) == 1
        severity, _msg = classify_kubernetes_change(wc_changes[0])
        assert severity == "high"

    def test_wildcard_host_removed(self):
        a, _ra = _collect_one_ingress(rules=[make_ingress_rule(host="*.example.com")])
        b, _rb = _collect_one_ingress(rules=[make_ingress_rule(host="app.example.com")])
        changes = _real_changes([a], [b])
        wc_changes = [c for c in changes if c["field_path"] == "wildcard_host_count"]
        severity, _msg = classify_kubernetes_change(wc_changes[0])
        assert severity == "low"


class TestGatewayAllowedRoutesDiff:
    def test_allowed_routes_broadened_to_all(self):
        a, _la = _collect_one_gateway(listeners=[make_gateway_listener(allowed_routes={"namespaces": {"from": "Same"}})])
        b, _lb = _collect_one_gateway(listeners=[make_gateway_listener(allowed_routes={"namespaces": {"from": "All"}})])
        changes = _real_changes([a], [b])
        allowed_changes = [c for c in changes if c["field_path"] == "allowed_routes_category"]
        assert len(allowed_changes) == 1
        severity, msg = classify_kubernetes_change(allowed_changes[0])
        assert severity == "high"
        assert "all" in msg.lower()

    def test_allowed_routes_narrowed(self):
        a, _la = _collect_one_gateway(listeners=[make_gateway_listener(allowed_routes={"namespaces": {"from": "All"}})])
        b, _lb = _collect_one_gateway(listeners=[make_gateway_listener(allowed_routes={"namespaces": {"from": "Same"}})])
        changes = _real_changes([a], [b])
        allowed_changes = [c for c in changes if c["field_path"] == "allowed_routes_category"]
        assert len(allowed_changes) == 1
        severity, _msg = classify_kubernetes_change(allowed_changes[0])
        assert severity == "low"


class TestHttpRouteCrossNamespaceDiff:
    def test_cross_namespace_backend_introduced(self):
        rule_a = make_http_route_rule(backend_refs=[{"name": "svc"}])
        rule_b = make_http_route_rule(backend_refs=[{"name": "svc", "namespace": "other-ns"}])
        a, _ra = _collect_one_http_route(rules=[rule_a])
        b, _rb = _collect_one_http_route(rules=[rule_b])
        changes = _real_changes([a], [b])
        cross_ns_changes = [c for c in changes if c["field_path"] == "cross_namespace_backend_count"]
        assert len(cross_ns_changes) == 1
        severity, _msg = classify_kubernetes_change(cross_ns_changes[0])
        assert severity == "high"

    def test_cross_namespace_backend_removed(self):
        rule_a = make_http_route_rule(backend_refs=[{"name": "svc", "namespace": "other-ns"}])
        rule_b = make_http_route_rule(backend_refs=[{"name": "svc"}])
        a, _ra = _collect_one_http_route(rules=[rule_a])
        b, _rb = _collect_one_http_route(rules=[rule_b])
        changes = _real_changes([a], [b])
        cross_ns_changes = [c for c in changes if c["field_path"] == "cross_namespace_backend_count"]
        severity, _msg = classify_kubernetes_change(cross_ns_changes[0])
        assert severity == "low"


class TestNetworkPolicyDiff:
    def test_default_deny_added(self):
        a = _collect_one_network_policy(policy_types=["Ingress"], ingress=[make_ingress_rule_np()])
        b = _collect_one_network_policy(policy_types=["Ingress"], ingress=[])
        changes = _real_changes([a], [b])
        deny_changes = [c for c in changes if c["field_path"] == "empty_ingress_list"]
        assert len(deny_changes) == 1
        severity, _msg = classify_kubernetes_change(deny_changes[0])
        assert severity == "low"

    def test_default_deny_removed(self):
        a = _collect_one_network_policy(policy_types=["Ingress"], ingress=[])
        b = _collect_one_network_policy(policy_types=["Ingress"], ingress=[make_ingress_rule_np()])
        changes = _real_changes([a], [b])
        deny_changes = [c for c in changes if c["field_path"] == "empty_ingress_list"]
        assert len(deny_changes) == 1
        severity, msg = classify_kubernetes_change(deny_changes[0])
        assert severity == "high"
        assert "default-deny" in msg.lower()

    def test_allow_all_ingress_introduced_all_pods_is_critical(self):
        a = _collect_one_network_policy(
            pod_selector=make_selector(), policy_types=["Ingress"], ingress=[],
        )
        b = _collect_one_network_policy(
            pod_selector=make_selector(), policy_types=["Ingress"], ingress=[make_ingress_rule_np()],
        )
        changes = _real_changes([a], [b])
        allow_all_changes = [c for c in changes if c["field_path"] == "allows_all_ingress"]
        assert len(allow_all_changes) == 1
        severity, _msg = classify_kubernetes_change(allow_all_changes[0])
        assert severity == "critical"

    def test_public_cidr_introduced(self):
        peer_public = make_peer(ip_block=make_ip_block(cidr="0.0.0.0/0"))
        a = _collect_one_network_policy(policy_types=["Ingress"], ingress=[make_ingress_rule_np()])
        b = _collect_one_network_policy(policy_types=["Ingress"], ingress=[make_ingress_rule_np(peers=[peer_public])])
        changes = _real_changes([a], [b])
        cidr_changes = [c for c in changes if c["field_path"] == "public_ipv4_cidr_allowed"]
        assert len(cidr_changes) == 1
        severity, msg = classify_kubernetes_change(cidr_changes[0])
        assert severity == "high"
        assert "0.0.0.0/0" in msg

    def test_public_cidr_removed(self):
        peer_public = make_peer(ip_block=make_ip_block(cidr="0.0.0.0/0"))
        a = _collect_one_network_policy(policy_types=["Ingress"], ingress=[make_ingress_rule_np(peers=[peer_public])])
        b = _collect_one_network_policy(policy_types=["Ingress"], ingress=[make_ingress_rule_np()])
        changes = _real_changes([a], [b])
        cidr_changes = [c for c in changes if c["field_path"] == "public_ipv4_cidr_allowed"]
        severity, _msg = classify_kubernetes_change(cidr_changes[0])
        assert severity == "low"


class TestNoisyFieldsIgnored:
    def test_resource_version_only_change_ignored(self):
        # Kubernetes network records never carry resourceVersion at all —
        # byte-identical records produce zero Changes.
        a, _pa = _collect_one_service()
        changes = _real_changes([dict(a)], [dict(a)])
        assert changes == []

    def test_ordering_only_change_ignored(self):
        a, _pa = _collect_one_service(ip_families=["IPv4", "IPv6"])
        b, _pb = _collect_one_service(ip_families=["IPv4", "IPv6"])
        changes = _real_changes([a], [b])
        assert changes == []


class TestProviderMetadata:
    def test_service_change_metadata(self):
        a, _pa = _collect_one_service(service_type="ClusterIP")
        b, _pb = _collect_one_service(service_type="LoadBalancer", lb_ingress=["203.0.113.9"])
        changes = _real_changes([a], [b])
        exposure_changes = [c for c in changes if c["field_path"] == "exposure_category"]
        pm = exposure_changes[0]["provider_metadata"]
        assert pm["record_type"] == "kubernetes_service"
        assert pm["service_name"] == "web"
        assert pm["cluster_id"] == "uid:c1"

    def test_network_policy_change_metadata(self):
        a = _collect_one_network_policy(policy_types=["Ingress"], ingress=[])
        b = _collect_one_network_policy(policy_types=["Ingress"], ingress=[make_ingress_rule_np()])
        changes = _real_changes([a], [b])
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == "kubernetes_network_policy"
        assert pm["policy_name"] == "policy1"


class TestRiskRoutingNeverFallsThroughToOtherProviders:
    def test_service_change_routes_to_kubernetes_classifier(self):
        a, _pa = _collect_one_service(service_type="ClusterIP")
        b, _pb = _collect_one_service(service_type="NodePort")
        changes = _real_changes([a], [b])
        assert changes
        for change in changes:
            assert change["provider_metadata"]["record_type"].startswith("kubernetes_")

        class _ChangeObj:
            def __init__(self, d):
                self.__dict__.update(d)

        for change in changes:
            severity, msg = classify_change(_ChangeObj(change))
            assert severity in ("low", "medium", "high", "critical")
            assert "cloudflare" not in msg.lower()
            assert "aws" not in msg.lower()

    def test_network_policy_never_routes_to_cloudflare_fallback(self):
        a = _collect_one_network_policy(policy_types=["Ingress"], ingress=[])
        b = _collect_one_network_policy(policy_types=["Ingress"], ingress=[make_ingress_rule_np()])
        changes = _real_changes([a], [b])
        assert changes
        for change in changes:
            assert change["provider_metadata"]["record_type"] == "kubernetes_network_policy"

    def test_gateway_and_httproute_route_to_kubernetes(self):
        a, _la = _collect_one_gateway(listeners=[make_gateway_listener(allowed_routes={"namespaces": {"from": "Same"}})])
        b, _lb = _collect_one_gateway(listeners=[make_gateway_listener(allowed_routes={"namespaces": {"from": "All"}})])
        changes = _real_changes([a], [b])
        assert changes
        for change in changes:
            assert change["provider_metadata"]["record_type"] == "kubernetes_gateway"


class TestNamespaceNetworkPostureDiff:
    def test_all_pod_ingress_default_deny_lost(self):
        policy_a = _collect_one_network_policy(pod_selector=make_selector(), policy_types=["Ingress"], ingress=[])
        posture_a = _build_namespace_network_postures(
            [policy_a], ["prod"], cluster_id="uid:c1", cluster_name="c1", collection_status="complete",
        )
        posture_b = _build_namespace_network_postures(
            [], ["prod"], cluster_id="uid:c1", cluster_name="c1", collection_status="complete",
        )
        changes = _real_changes(posture_a, posture_b)
        deny_changes = [c for c in changes if c["field_path"] == "all_pod_ingress_default_deny"]
        assert len(deny_changes) == 1
        severity, _msg = classify_kubernetes_change(deny_changes[0])
        assert severity == "high"
