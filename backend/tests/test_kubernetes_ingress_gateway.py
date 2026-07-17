"""Kubernetes Ingress and Gateway API tests (Kubernetes message 4 of 9).

Covers Ingress host/path/TLS/backend/status normalization, Gateway API
absence/availability (via CustomObjectsApi dict-based pagination),
Gateway/listener normalization, HTTPRoute/rule normalization, allowedRoutes
categorization, cross-namespace parent/backend detection, unresolved refs,
and filter presence-only tracking.

All tests are pure-mock; no real Kubernetes cluster is contacted.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from kubernetes.client.rest import ApiException

from app.connectors.kubernetes import (
    _collect_gateways,
    _collect_http_routes,
    _collect_ingresses,
    _normalize_gateway,
    _normalize_http_route,
    _normalize_ingress,
)
from app.connectors.kubernetes_schema import (
    ALLOWED_NAMESPACES_ALL,
    ALLOWED_NAMESPACES_SAME,
    ALLOWED_NAMESPACES_SELECTOR,
    EXPOSURE_UNKNOWN,
    GATEWAY_ADDRESS_EXTERNAL,
    HOST_CATEGORY_EXACT,
    HOST_CATEGORY_HOSTLESS,
    HOST_CATEGORY_WILDCARD,
    ROUTE_REFS_ALL_RESOLVED,
    ROUTE_REFS_SOME_UNRESOLVED,
)
from tests._kubernetes_network_fixtures import (
    dict_page,
    make_gateway,
    make_gateway_listener,
    make_http_route,
    make_http_route_rule,
    make_ingress,
    make_ingress_path,
    make_ingress_rule,
    make_ingress_tls,
    page,
)


def _ing_record(**kwargs):
    obj = make_ingress(**kwargs)
    return _normalize_ingress(obj, cluster_id="uid:c1", cluster_name="c1")


# ── O-AA: Ingress ──────────────────────────────────────────────────────────────

class TestIngressNormalization:
    def test_O_exact_host(self):
        record, rules = _ing_record(rules=[make_ingress_rule(host="app.example.com")])
        assert rules[0]["host_category"] == HOST_CATEGORY_EXACT

    def test_P_wildcard_host(self):
        record, rules = _ing_record(rules=[make_ingress_rule(host="*.example.com")])
        assert record["wildcard_host_count"] == 1
        assert rules[0]["host_category"] == HOST_CATEGORY_WILDCARD

    def test_Q_hostless_rule(self):
        record, rules = _ing_record(rules=[make_ingress_rule(host=None)])
        assert record["hostless_rule_present"] is True
        assert rules[0]["host_category"] == HOST_CATEGORY_HOSTLESS

    def test_R_default_backend(self):
        from types import SimpleNamespace as NS
        db = NS(service=NS(name="default-svc", port=NS(number=80)), resource=None)
        record, rules = _ing_record(default_backend=db, rules=[])
        assert record["default_backend_present"] is True
        assert any(r["default_backend"] for r in rules)

    def test_S_prefix_root(self):
        path = make_ingress_path(path="/", path_type="Prefix")
        record, rules = _ing_record(rules=[make_ingress_rule(host=None, paths=[path])])
        assert rules[0]["catch_all_route"] is True

    def test_T_implementation_specific_catch_all(self):
        path = make_ingress_path(path="/", path_type="ImplementationSpecific")
        record, rules = _ing_record(rules=[make_ingress_rule(host=None, paths=[path])])
        assert rules[0]["path_category"] == "implementation_specific_catch_all"

    def test_U_tls_covers_host(self):
        tls = make_ingress_tls(hosts=["app.example.com"])
        record, rules = _ing_record(rules=[make_ingress_rule(host="app.example.com")], tls=[tls])
        assert rules[0]["tls_covered"] is True
        assert record["plaintext_exposure_category"] == "tls_covered"

    def test_V_tls_missing(self):
        record, rules = _ing_record(rules=[make_ingress_rule(host="app.example.com")], tls=[])
        assert rules[0]["tls_covered"] is False
        assert record["plaintext_exposure_category"] == "plaintext_http_present"

    def test_W_tls_removed_partial_coverage(self):
        tls = make_ingress_tls(hosts=["a.example.com"])
        record, rules = _ing_record(
            rules=[make_ingress_rule(host="a.example.com"), make_ingress_rule(host="b.example.com")],
            tls=[tls],
        )
        assert record["tls_host_count"] == 1
        assert record["plaintext_exposure_category"] == "plaintext_http_present"

    def test_X_public_ingress_status_address(self):
        record, _rules = _ing_record(lb_ingress=["203.0.113.5"])
        assert record["public_exposure_category"] == "external_load_balancer"
        assert record["load_balancer_ingress_count"] == 1

    def test_Y_no_status_is_unknown_not_public(self):
        record, _rules = _ing_record(lb_ingress=None)
        assert record["public_exposure_category"] == EXPOSURE_UNKNOWN

    def test_Z_backend_service_changed(self):
        path_a = make_ingress_path(backend_service="svc-a")
        path_b = make_ingress_path(backend_service="svc-b")
        _rec_a, rules_a = _ing_record(rules=[make_ingress_rule(paths=[path_a])])
        _rec_b, rules_b = _ing_record(rules=[make_ingress_rule(paths=[path_b])])
        assert rules_a[0]["backend_service_name"] == "svc-a"
        assert rules_b[0]["backend_service_name"] == "svc-b"
        assert rules_a[0]["route_fingerprint"] != rules_b[0]["route_fingerprint"]

    def test_AA_ingress_class_changed(self):
        record_a, _r = _ing_record(ingress_class="nginx")
        record_b, _r = _ing_record(ingress_class="traefik")
        assert record_a["ingress_class"] == "nginx"
        assert record_b["ingress_class"] == "traefik"

    def test_tls_secret_reference_count_only(self):
        tls = make_ingress_tls(hosts=["a.example.com"], secret_name="my-tls-secret")
        record, _rules = _ing_record(tls=[tls])
        assert record["tls_secret_reference_count"] == 1
        import json
        assert "my-tls-secret" not in json.dumps(record)


class TestIngressCollectionFailSoft:
    def test_403_reports_partial(self):
        list_fn = MagicMock(side_effect=ApiException(status=403))
        records, rules, status = _collect_ingresses(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "partial"
        assert records == [] and rules == []

    def test_namespace_allowlist(self):
        ingresses = [make_ingress(namespace="prod", name="a"), make_ingress(namespace="staging", name="b")]
        list_fn = MagicMock(return_value=page(ingresses))
        records, _rules, _status = _collect_ingresses(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=["prod"],
        )
        assert [r["namespace"] for r in records] == ["prod"]

    def test_malformed_object_isolated(self):
        good = make_ingress(name="good")
        malformed = object()
        list_fn = MagicMock(return_value=page([malformed, good]))
        records, _rules, status = _collect_ingresses(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert len(records) == 1


# ── AB-AK: Gateway API ─────────────────────────────────────────────────────────

class TestGatewayApiAvailability:
    def test_AB_gateway_api_absent(self):
        custom_api = MagicMock()
        custom_api.list_cluster_custom_object.side_effect = ApiException(status=404)
        records, listeners, status = _collect_gateways(
            custom_api, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "unsupported"
        assert records == [] and listeners == []

    def test_AC_gateway_v1_available(self):
        custom_api = MagicMock()
        custom_api.list_cluster_custom_object.return_value = dict_page([make_gateway()])
        records, _listeners, status = _collect_gateways(
            custom_api, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert len(records) == 1


class TestGatewayNormalization:
    def test_AD_http_listener(self):
        gw = make_gateway(listeners=[make_gateway_listener(protocol="HTTP")])
        record, listeners = _normalize_gateway(gw, cluster_id="c1", cluster_name="c1")
        assert record["http_listener_count"] == 1
        assert listeners[0]["protocol"] == "HTTP"

    def test_AE_https_listener(self):
        gw = make_gateway(listeners=[make_gateway_listener(protocol="HTTPS", tls={"mode": "Terminate", "certificateRefs": [{"name": "cert"}]})])
        record, listeners = _normalize_gateway(gw, cluster_id="c1", cluster_name="c1")
        assert record["https_listener_count"] == 1
        assert listeners[0]["certificate_reference_count"] == 1

    def test_AF_wildcard_hostname(self):
        gw = make_gateway(listeners=[make_gateway_listener(hostname="*.example.com")])
        record, listeners = _normalize_gateway(gw, cluster_id="c1", cluster_name="c1")
        assert record["wildcard_hostname_count"] == 1
        assert listeners[0]["hostname_category"] == HOST_CATEGORY_WILDCARD

    def test_AG_allowed_routes_same(self):
        gw = make_gateway(listeners=[make_gateway_listener(allowed_routes={"namespaces": {"from": "Same"}})])
        record, listeners = _normalize_gateway(gw, cluster_id="c1", cluster_name="c1")
        assert listeners[0]["allowed_namespace_policy"] == ALLOWED_NAMESPACES_SAME
        assert record["cross_namespace_route_allowance"] is False

    def test_AH_allowed_routes_all(self):
        gw = make_gateway(listeners=[make_gateway_listener(allowed_routes={"namespaces": {"from": "All"}})])
        record, listeners = _normalize_gateway(gw, cluster_id="c1", cluster_name="c1")
        assert listeners[0]["allowed_namespace_policy"] == ALLOWED_NAMESPACES_ALL
        assert record["cross_namespace_route_allowance"] is True

    def test_AI_allowed_routes_selector(self):
        gw = make_gateway(listeners=[make_gateway_listener(allowed_routes={"namespaces": {"from": "Selector"}})])
        _record, listeners = _normalize_gateway(gw, cluster_id="c1", cluster_name="c1")
        assert listeners[0]["allowed_namespace_policy"] == ALLOWED_NAMESPACES_SELECTOR

    def test_AJ_external_address(self):
        gw = make_gateway(addresses=[{"type": "IPAddress", "value": "8.8.8.8"}])
        record, _listeners = _normalize_gateway(gw, cluster_id="c1", cluster_name="c1")
        assert record["public_address_category"] == GATEWAY_ADDRESS_EXTERNAL

    def test_AK_internal_unknown_address(self):
        gw = make_gateway(addresses=[{"type": "IPAddress", "value": "10.0.0.5"}])
        record, _listeners = _normalize_gateway(gw, cluster_id="c1", cluster_name="c1")
        assert record["public_address_category"] == "internal"

        gw2 = make_gateway(addresses=[])
        record2, _l2 = _normalize_gateway(gw2, cluster_id="c1", cluster_name="c1")
        assert record2["public_address_category"] == "unassigned"


# ── AL-AU: HTTPRoute ───────────────────────────────────────────────────────────

class TestHttpRouteNormalization:
    def test_AL_exact_hostname(self):
        route = make_http_route(hostnames=["app.example.com"])
        record, _rules = _normalize_http_route(route, cluster_id="c1", cluster_name="c1")
        assert record["wildcard_hostname_count"] == 0
        assert record["hostname_count"] == 1

    def test_AM_wildcard_hostname(self):
        route = make_http_route(hostnames=["*.example.com"])
        record, _rules = _normalize_http_route(route, cluster_id="c1", cluster_name="c1")
        assert record["wildcard_hostname_count"] == 1

    def test_AN_catch_all_path(self):
        rule = make_http_route_rule(matches=[{"path": {"type": "PathPrefix", "value": "/"}}])
        route = make_http_route(rules=[rule])
        _record, rules = _normalize_http_route(route, cluster_id="c1", cluster_name="c1")
        assert rules[0]["catch_all_path"] is True

    def test_AO_backend_service(self):
        rule = make_http_route_rule(backend_refs=[{"name": "web-svc"}])
        route = make_http_route(rules=[rule])
        _record, rules = _normalize_http_route(route, cluster_id="c1", cluster_name="c1")
        assert rules[0]["backend_count"] == 1

    def test_AP_cross_namespace_parent(self):
        route = make_http_route(parent_refs=[{"name": "gw1", "namespace": "gateway-ns"}])
        record, _rules = _normalize_http_route(route, cluster_id="c1", cluster_name="c1")
        assert record["cross_namespace_parent_count"] == 1

    def test_AQ_cross_namespace_backend(self):
        rule = make_http_route_rule(backend_refs=[{"name": "svc", "namespace": "other-ns"}])
        route = make_http_route(rules=[rule])
        record, rules = _normalize_http_route(route, cluster_id="c1", cluster_name="c1")
        assert record["cross_namespace_backend_count"] == 1
        assert rules[0]["cross_namespace_backend"] is True

    def test_AR_unresolved_refs(self):
        route = make_http_route(status_parents=[{"conditions": [{"type": "ResolvedRefs", "status": "False"}]}])
        record, _rules = _normalize_http_route(route, cluster_id="c1", cluster_name="c1")
        assert record["resolved_refs_status"] == ROUTE_REFS_SOME_UNRESOLVED

    def test_resolved_refs_all_resolved(self):
        route = make_http_route()
        record, _rules = _normalize_http_route(route, cluster_id="c1", cluster_name="c1")
        assert record["resolved_refs_status"] == ROUTE_REFS_ALL_RESOLVED

    def test_AS_redirect_filter(self):
        rule = make_http_route_rule(filters=[{"type": "RequestRedirect"}])
        route = make_http_route(rules=[rule])
        record, rules = _normalize_http_route(route, cluster_id="c1", cluster_name="c1")
        assert record["redirect_present"] is True
        assert rules[0]["redirect_present"] is True

    def test_AT_rewrite_filter(self):
        rule = make_http_route_rule(filters=[{"type": "URLRewrite"}])
        route = make_http_route(rules=[rule])
        record, _rules = _normalize_http_route(route, cluster_id="c1", cluster_name="c1")
        assert record["rewrite_present"] is True

    def test_AU_header_filter_presence_only(self):
        rule = make_http_route_rule(matches=[{"path": {"type": "PathPrefix", "value": "/"}, "headers": [{"name": "X-Test", "value": "secret-header-value"}]}])
        route = make_http_route(rules=[rule])
        record, _rules = _normalize_http_route(route, cluster_id="c1", cluster_name="c1")
        assert record["header_match_present"] is True
        import json
        assert "secret-header-value" not in json.dumps(record)


class TestHttpRouteCollectionFailSoft:
    def test_gateway_api_absent_for_http_routes(self):
        custom_api = MagicMock()
        custom_api.list_cluster_custom_object.side_effect = ApiException(status=404)
        records, rules, status = _collect_http_routes(
            custom_api, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "unsupported"
        assert records == [] and rules == []

    def test_pagination_via_custom_objects_api(self):
        custom_api = MagicMock()
        pages = [
            dict_page([make_http_route(name="a")], continue_token="tok1"),
            dict_page([make_http_route(name="b")], continue_token=None),
        ]
        custom_api.list_cluster_custom_object.side_effect = pages
        records, _rules, status = _collect_http_routes(
            custom_api, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert {r["name"] for r in records} == {"a", "b"}

    def test_repeated_continuation_token_stops(self):
        custom_api = MagicMock()
        pages = [
            dict_page([make_http_route(name="a")], continue_token="tok1"),
            dict_page([make_http_route(name="b")], continue_token="tok1"),
        ]
        custom_api.list_cluster_custom_object.side_effect = pages
        records, _rules, status = _collect_http_routes(
            custom_api, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "partial"
        assert {r["name"] for r in records} == {"a", "b"}
