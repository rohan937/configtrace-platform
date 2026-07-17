"""Shared fake-object builders for Kubernetes message-5 (admission control
and configuration governance) tests.

Not a test file itself — a plain helper module imported by
``test_kubernetes_admission_webhooks.py``, ``test_kubernetes_pod_security_admission.py``,
``test_kubernetes_resource_governance.py``, and ``test_kubernetes_admission_diff.py``.
"""

from __future__ import annotations

from types import SimpleNamespace as NS
from typing import Optional


def make_rule(
    *, operations: Optional[list[str]] = None, api_groups: Optional[list[str]] = None,
    api_versions: Optional[list[str]] = None, resources: Optional[list[str]] = None,
    scope: Optional[str] = "Namespaced",
) -> NS:
    return NS(
        operations=operations if operations is not None else ["CREATE", "UPDATE"],
        api_groups=api_groups if api_groups is not None else [""],
        api_versions=api_versions if api_versions is not None else ["v1"],
        resources=resources if resources is not None else ["pods"],
        scope=scope,
    )


def make_service_ref(*, namespace: str = "kube-system", name: str = "admission-svc",
                      path: Optional[str] = "/validate", port: int = 443) -> NS:
    return NS(namespace=namespace, name=name, path=path, port=port)


def make_client_config(*, service: Optional[NS] = None, url: Optional[str] = None,
                        ca_bundle: Optional[bytes] = None) -> NS:
    return NS(service=service, url=url, ca_bundle=ca_bundle)


def make_selector(*, match_labels: Optional[dict] = None, match_expressions: Optional[list] = None) -> Optional[NS]:
    if match_labels is None and match_expressions is None:
        return None
    return NS(match_labels=match_labels or {}, match_expressions=match_expressions or [])


def make_webhook(
    *, name: str = "validate.example.com", client_config: Optional[NS] = None,
    failure_policy: Optional[str] = "Fail", match_policy: Optional[str] = "Equivalent",
    side_effects: Optional[str] = "None", timeout_seconds: Optional[int] = 10,
    namespace_selector: Optional[NS] = None, object_selector: Optional[NS] = None,
    rules: Optional[list] = None, admission_review_versions: Optional[list[str]] = None,
    reinvocation_policy: Optional[str] = None,
) -> NS:
    return NS(
        name=name,
        client_config=client_config if client_config is not None else make_client_config(service=make_service_ref()),
        failure_policy=failure_policy, match_policy=match_policy, side_effects=side_effects,
        timeout_seconds=timeout_seconds, namespace_selector=namespace_selector, object_selector=object_selector,
        rules=rules if rules is not None else [make_rule()],
        admission_review_versions=admission_review_versions or ["v1"],
        reinvocation_policy=reinvocation_policy,
    )


def make_webhook_configuration(*, name: str = "my-webhook-config", uid: str = "wc-1",
                                webhooks: Optional[list] = None) -> NS:
    return NS(metadata=NS(name=name, uid=uid), webhooks=webhooks if webhooks is not None else [make_webhook()])


def make_namespace_record(
    *, name: str = "prod", enforce: Optional[str] = None, enforce_version: Optional[str] = None,
    audit: Optional[str] = None, audit_version: Optional[str] = None,
    warn: Optional[str] = None, warn_version: Optional[str] = None,
) -> dict:
    return {
        "name": name, "psa_enforce": enforce, "psa_enforce_version": enforce_version,
        "psa_audit": audit, "psa_audit_version": audit_version,
        "psa_warn": warn, "psa_warn_version": warn_version,
    }


def make_resource_quota(
    *, namespace: str = "prod", name: str = "compute-quota", uid: str = "rq-1",
    hard: Optional[dict] = None, scopes: Optional[list[str]] = None, scope_selector: Optional[NS] = None,
) -> NS:
    return NS(
        metadata=NS(namespace=namespace, name=name, uid=uid),
        spec=NS(hard=hard if hard is not None else {"cpu": "4", "requests.memory": "8Gi", "pods": "50"},
                scopes=scopes or [], scope_selector=scope_selector),
    )


def make_limit_range_item(
    *, item_type: str = "Container", default: Optional[dict] = None, default_request: Optional[dict] = None,
    max_: Optional[dict] = None, min_: Optional[dict] = None, ratio: Optional[dict] = None,
) -> NS:
    return NS(
        type=item_type, default=default or {}, default_request=default_request or {},
        max=max_ or {}, min=min_ or {}, max_limit_request_ratio=ratio or {},
    )


def make_limit_range(*, namespace: str = "prod", name: str = "defaults", uid: str = "lr-1",
                      items: Optional[list] = None) -> NS:
    return NS(
        metadata=NS(namespace=namespace, name=name, uid=uid),
        spec=NS(limits=items if items is not None else [make_limit_range_item()]),
    )


def page(items: list, continue_token=None) -> NS:
    return NS(items=items, metadata=NS(_continue=continue_token))
