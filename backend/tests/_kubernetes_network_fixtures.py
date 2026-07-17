"""Shared fake-object builders for Kubernetes message-4 (networking) tests.

Not a test file itself — a plain helper module imported by
``test_kubernetes_service_networking.py``, ``test_kubernetes_ingress_gateway.py``,
``test_kubernetes_network_policy.py``, and ``test_kubernetes_network_diff.py``.

Services/Ingresses/NetworkPolicies use ``SimpleNamespace`` fakes shaped like
the official ``kubernetes`` client's typed model objects (attribute access).
Gateway/HTTPRoute use plain dicts, matching what ``CustomObjectsApi``
actually returns (no typed client exists for Gateway API).
"""

from __future__ import annotations

from types import SimpleNamespace as NS
from typing import Optional


def make_service_port(
    *, name: Optional[str] = "http", protocol: str = "TCP", port: int = 80,
    target_port=8080, node_port: Optional[int] = None, app_protocol: Optional[str] = None,
) -> NS:
    return NS(name=name, protocol=protocol, port=port, target_port=target_port,
              node_port=node_port, app_protocol=app_protocol)


def make_service(
    *, namespace: str = "prod", name: str = "web", uid: str = "svc-1",
    service_type: str = "ClusterIP", cluster_ip: Optional[str] = "10.0.0.5",
    external_ips: Optional[list[str]] = None, external_name: Optional[str] = None,
    lb_ingress: Optional[list] = None, annotations: Optional[dict] = None,
    selector: Optional[dict] = None, ports: Optional[list] = None,
    external_traffic_policy: Optional[str] = None, internal_traffic_policy: Optional[str] = None,
    session_affinity: Optional[str] = None, ip_families: Optional[list[str]] = None,
    ip_family_policy: Optional[str] = None, publish_not_ready_addresses: bool = False,
) -> NS:
    lb_status = NS(ingress=[NS(ip=ip) for ip in (lb_ingress or [])]) if lb_ingress is not None else None
    return NS(
        metadata=NS(namespace=namespace, name=name, uid=uid, annotations=annotations or {}),
        spec=NS(
            type=service_type, cluster_ip=cluster_ip, external_i_ps=external_ips or [],
            external_name=external_name, selector=selector or {}, ports=ports or [make_service_port()],
            external_traffic_policy=external_traffic_policy, internal_traffic_policy=internal_traffic_policy,
            session_affinity=session_affinity, ip_families=ip_families or [],
            ip_family_policy=ip_family_policy, publish_not_ready_addresses=publish_not_ready_addresses,
        ),
        status=NS(load_balancer=lb_status),
    )


def make_ingress_path(*, path: Optional[str] = "/", path_type: Optional[str] = "Prefix",
                       backend_service: Optional[str] = "web-svc", backend_port: Optional[int] = 80) -> NS:
    backend = None
    if backend_service is not None:
        backend = NS(service=NS(name=backend_service, port=NS(number=backend_port)), resource=None)
    return NS(path=path, path_type=path_type, backend=backend)


def make_ingress_rule(*, host: Optional[str] = "app.example.com", paths: Optional[list] = None) -> NS:
    return NS(host=host, http=NS(paths=paths if paths is not None else [make_ingress_path()]))


def make_ingress_tls(*, hosts: Optional[list[str]] = None, secret_name: Optional[str] = "tls-secret") -> NS:
    return NS(hosts=hosts or [], secret_name=secret_name)


def make_ingress(
    *, namespace: str = "prod", name: str = "web-ingress", uid: str = "ing-1",
    ingress_class: Optional[str] = "nginx", default_backend: Optional[NS] = None,
    rules: Optional[list] = None, tls: Optional[list] = None, lb_ingress: Optional[list] = None,
) -> NS:
    lb_status = NS(ingress=[NS(ip=ip) for ip in (lb_ingress or [])]) if lb_ingress is not None else None
    return NS(
        metadata=NS(namespace=namespace, name=name, uid=uid),
        spec=NS(
            ingress_class_name=ingress_class, default_backend=default_backend,
            rules=rules if rules is not None else [make_ingress_rule()],
            tls=tls or [],
        ),
        status=NS(load_balancer=lb_status),
    )


def make_gateway(
    *, namespace: str = "prod", name: str = "gw1", uid: str = "gw-1",
    gateway_class: Optional[str] = "istio", listeners: Optional[list[dict]] = None,
    addresses: Optional[list[dict]] = None, status_conditions: Optional[list[dict]] = None,
) -> dict:
    return {
        "metadata": {"namespace": namespace, "name": name, "uid": uid},
        "spec": {
            "gatewayClassName": gateway_class,
            "listeners": listeners if listeners is not None else [make_gateway_listener()],
            "addresses": addresses or [],
        },
        "status": {"conditions": status_conditions if status_conditions is not None else [{"type": "Accepted", "status": "True"}]},
    }


def make_gateway_listener(
    *, name: str = "http", protocol: str = "HTTP", port: int = 80,
    hostname: Optional[str] = None, tls: Optional[dict] = None,
    allowed_routes: Optional[dict] = None,
) -> dict:
    return {"name": name, "protocol": protocol, "port": port, "hostname": hostname,
            "tls": tls, "allowedRoutes": allowed_routes}


def make_http_route(
    *, namespace: str = "prod", name: str = "route1", uid: str = "r-1",
    parent_refs: Optional[list[dict]] = None, hostnames: Optional[list[str]] = None,
    rules: Optional[list[dict]] = None, status_parents: Optional[list[dict]] = None,
) -> dict:
    return {
        "metadata": {"namespace": namespace, "name": name, "uid": uid},
        "spec": {
            "parentRefs": parent_refs if parent_refs is not None else [{"name": "gw1"}],
            "hostnames": hostnames or [],
            "rules": rules if rules is not None else [make_http_route_rule()],
        },
        "status": {"parents": status_parents if status_parents is not None else [
            {"conditions": [{"type": "ResolvedRefs", "status": "True"}]}
        ]},
    }


def make_http_route_rule(
    *, matches: Optional[list[dict]] = None, backend_refs: Optional[list[dict]] = None,
    filters: Optional[list[dict]] = None, timeouts: Optional[dict] = None,
) -> dict:
    return {
        "matches": matches if matches is not None else [{"path": {"type": "PathPrefix", "value": "/"}}],
        "backendRefs": backend_refs if backend_refs is not None else [{"name": "web-svc"}],
        "filters": filters or [],
        "timeouts": timeouts,
    }


def make_ip_block(*, cidr: str = "10.0.0.0/8", except_cidrs: Optional[list[str]] = None) -> NS:
    return NS(cidr=cidr, _except=except_cidrs or [])


def make_peer(*, namespace_selector: Optional[NS] = None, pod_selector: Optional[NS] = None,
              ip_block: Optional[NS] = None) -> NS:
    return NS(namespace_selector=namespace_selector, pod_selector=pod_selector, ip_block=ip_block)


def make_selector(*, match_labels: Optional[dict] = None, match_expressions: Optional[list] = None) -> NS:
    return NS(match_labels=match_labels or {}, match_expressions=match_expressions or [])


def make_ingress_rule_np(*, peers: Optional[list] = None, ports: Optional[list] = None) -> NS:
    return NS(_from=peers, ports=ports)


def make_egress_rule_np(*, peers: Optional[list] = None, ports: Optional[list] = None) -> NS:
    return NS(to=peers, ports=ports)


def make_network_policy(
    *, namespace: str = "prod", name: str = "policy1", uid: str = "np-1",
    pod_selector: Optional[NS] = None, policy_types: Optional[list[str]] = None,
    ingress: Optional[list] = None, egress: Optional[list] = None,
) -> NS:
    return NS(
        metadata=NS(namespace=namespace, name=name, uid=uid),
        spec=NS(
            pod_selector=pod_selector if pod_selector is not None else make_selector(),
            policy_types=policy_types if policy_types is not None else ["Ingress"],
            ingress=ingress, egress=egress,
        ),
    )


def make_port_np(*, protocol: str = "TCP", port: int = 80) -> NS:
    return NS(protocol=protocol, port=port)


def page(items: list, continue_token=None) -> NS:
    return NS(items=items, metadata=NS(_continue=continue_token))


def dict_page(items: list, continue_token=None) -> dict:
    return {"items": items, "metadata": {"continue": continue_token}}
