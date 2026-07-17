"""Kubernetes Service networking tests (Kubernetes message 4 of 9).

Covers Service collection, exposure categorization (all types + evidence
hierarchy), ports, LoadBalancer status, the internal-load-balancer
annotation allowlist, pagination, fail-soft behavior, and stable IDs.

All tests are pure-mock; no real Kubernetes cluster is contacted.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from kubernetes.client.rest import ApiException

from app.connectors.kubernetes import _collect_services, _normalize_service
from app.connectors.kubernetes_schema import (
    CIDR_CATEGORY_BROAD_PUBLIC_RANGE,
    EXPOSURE_CLUSTER_INTERNAL,
    EXPOSURE_EXTERNAL_IP,
    EXPOSURE_EXTERNAL_LOAD_BALANCER,
    EXPOSURE_EXTERNAL_NAME,
    EXPOSURE_HEADLESS_INTERNAL,
    EXPOSURE_INTERNAL_LOAD_BALANCER,
    EXPOSURE_NODE_PORT,
    EXPOSURE_PENDING_LOAD_BALANCER,
    categorize_cidr,
)
from tests._kubernetes_network_fixtures import make_service, make_service_port, page


def _svc_record(**kwargs):
    obj = make_service(**kwargs)
    record, ports = _normalize_service(obj, cluster_id="uid:c1", cluster_name="c1")
    return record, ports


# ── A-I: exposure categorization ──────────────────────────────────────────────

class TestExposureCategorization:
    def test_A_cluster_ip_service(self):
        record, _ports = _svc_record(service_type="ClusterIP", cluster_ip="10.0.0.5")
        assert record["exposure_category"] == EXPOSURE_CLUSTER_INTERNAL

    def test_B_headless_service(self):
        record, _ports = _svc_record(service_type="ClusterIP", cluster_ip="None")
        assert record["headless"] is True
        assert record["exposure_category"] == EXPOSURE_HEADLESS_INTERNAL

    def test_C_node_port_service(self):
        record, _ports = _svc_record(service_type="NodePort")
        assert record["exposure_category"] == EXPOSURE_NODE_PORT

    def test_D_load_balancer_requested_pending(self):
        record, _ports = _svc_record(service_type="LoadBalancer", lb_ingress=None)
        assert record["exposure_category"] == EXPOSURE_PENDING_LOAD_BALANCER

    def test_E_load_balancer_external_ip_assigned(self):
        record, _ports = _svc_record(service_type="LoadBalancer", lb_ingress=["203.0.113.9"])
        assert record["exposure_category"] == EXPOSURE_EXTERNAL_LOAD_BALANCER
        assert record["load_balancer_ingress_count"] == 1

    def test_F_internal_load_balancer_annotation(self):
        record, _ports = _svc_record(
            service_type="LoadBalancer", lb_ingress=["10.0.5.5"],
            annotations={"service.beta.kubernetes.io/aws-load-balancer-internal": "true"},
        )
        assert record["internal_load_balancer_annotation_present"] is True
        assert record["exposure_category"] == EXPOSURE_INTERNAL_LOAD_BALANCER

    def test_G_external_ips_present(self):
        record, _ports = _svc_record(service_type="ClusterIP", external_ips=["203.0.113.50"])
        assert record["exposure_category"] == EXPOSURE_EXTERNAL_IP
        assert record["external_ip_count"] == 1

    def test_H_external_name_service(self):
        record, _ports = _svc_record(service_type="ExternalName", cluster_ip=None, external_name="db.example.com")
        assert record["exposure_category"] == EXPOSURE_EXTERNAL_NAME
        assert record["external_name_category"] == "exact"

    def test_I_mixed_exposure_evidence(self):
        record, _ports = _svc_record(
            service_type="LoadBalancer", lb_ingress=["203.0.113.9"], external_ips=["203.0.113.51"],
        )
        assert record["mixed_exposure_evidence"] is True


# ── J, K: IP families ─────────────────────────────────────────────────────────

class TestIpFamilies:
    def test_J_ipv4_service(self):
        record, _ports = _svc_record(ip_families=["IPv4"])
        assert record["ip_family_categories"] == ["IPv4"]

    def test_K_dual_stack_service(self):
        record, _ports = _svc_record(ip_families=["IPv4", "IPv6"])
        assert record["ip_family_categories"] == ["IPv4", "IPv6"]


# ── L, M, N: ports / selector / drift-relevant fields ─────────────────────────

class TestServicePortsAndSelectors:
    def test_L_sensitive_node_port(self):
        port = make_service_port(port=3306, node_port=30306)
        record, ports = _svc_record(service_type="NodePort", ports=[port])
        assert ports[0]["sensitive_port"] is True
        assert ports[0]["node_port"] == 30306

    def test_M_service_selector_fingerprint(self):
        record, _ports = _svc_record(selector={"app": "web", "tier": "frontend"})
        assert record["selector_key_count"] == 2
        assert isinstance(record["selector_fingerprint"], str) and record["selector_fingerprint"]

    def test_N_service_port_changed_fields_present(self):
        port = make_service_port(protocol="UDP", port=53)
        _record, ports = _svc_record(ports=[port])
        assert ports[0]["protocol"] == "UDP"
        assert ports[0]["port"] == 53

    def test_non_sensitive_port_not_flagged(self):
        port = make_service_port(port=8080)
        _record, ports = _svc_record(ports=[port])
        assert ports[0]["sensitive_port"] is False

    def test_named_target_port_category(self):
        port = make_service_port(target_port="http-web")
        _record, ports = _svc_record(ports=[port])
        assert ports[0]["target_port_category"] == "named"

    def test_numeric_target_port_category(self):
        port = make_service_port(target_port=8080)
        _record, ports = _svc_record(ports=[port])
        assert ports[0]["target_port_category"] == "numeric"


# ── CIDR categorization reused for gateway addresses ─────────────────────────

class TestCidrCategorization:
    def test_public_ipv4_unrestricted(self):
        assert categorize_cidr("0.0.0.0/0").startswith("public_ipv4")

    def test_broad_public_range(self):
        assert categorize_cidr("8.8.8.0/24") == CIDR_CATEGORY_BROAD_PUBLIC_RANGE

    def test_private_ipv4(self):
        assert categorize_cidr("10.0.0.0/8") == "private"

    def test_malformed_cidr(self):
        assert categorize_cidr("not-a-cidr") == "unknown_malformed"


# ── Collection: pagination, fail-soft, stable IDs ────────────────────────────

class TestServiceCollection:
    def test_pagination_multiple_pages(self):
        pages = [
            page([make_service(name="a")], continue_token="tok1"),
            page([make_service(name="b")], continue_token=None),
        ]
        list_fn = MagicMock(side_effect=pages)
        records, _ports, status = _collect_services(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert {r["name"] for r in records} == {"a", "b"}

    def test_403_reports_partial_without_raising(self):
        list_fn = MagicMock(side_effect=ApiException(status=403))
        records, ports, status = _collect_services(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "partial"
        assert records == [] and ports == []

    def test_namespace_allowlist(self):
        services = [make_service(namespace="prod", name="a"), make_service(namespace="staging", name="b")]
        list_fn = MagicMock(return_value=page(services))
        records, _ports, _status = _collect_services(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=["prod"],
        )
        assert [r["namespace"] for r in records] == ["prod"]

    def test_stable_uid_based_id(self):
        svc = make_service(uid="stable-uid")
        list_fn = MagicMock(return_value=page([svc]))
        records, _ports, _status = _collect_services(
            list_fn, cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert records[0]["record_id"] == "uid:c1/service/prod/stable-uid"

    def test_malformed_object_isolated(self):
        good = make_service(name="good")
        malformed = object()
        list_fn = MagicMock(return_value=page([malformed, good]))
        records, _ports, status = _collect_services(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert len(records) == 1
        assert records[0]["name"] == "good"

    def test_deterministic_ordering(self):
        services = [make_service(name="z"), make_service(name="a")]
        list_fn = MagicMock(return_value=page(services))
        records, _ports, _status = _collect_services(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert [r["name"] for r in records] == ["a", "z"]


class TestSensitiveDataExclusion:
    def test_no_arbitrary_annotations_persisted(self):
        import json
        record, _ports = _svc_record(annotations={"my-team.example.com/owner": "backend-team-secret-value"})
        assert "backend-team-secret-value" not in json.dumps(record)
        assert "my-team.example.com/owner" not in json.dumps(record)

    def test_selector_values_not_persisted_only_key_count(self):
        import json
        record, _ports = _svc_record(selector={"app": "super-secret-workload-name"})
        assert "super-secret-workload-name" not in json.dumps(record)
        assert record["selector_key_count"] == 1
