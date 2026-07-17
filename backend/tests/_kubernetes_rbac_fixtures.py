"""Shared fake-object builders for Kubernetes message-3 (RBAC) tests.

Not a test file itself — a plain helper module imported by
``test_kubernetes_rbac_collection.py``, ``test_kubernetes_rbac_normalization.py``,
``test_kubernetes_rbac_diff.py``, and ``test_kubernetes_workload_identity.py``.

Builds lightweight ``SimpleNamespace`` fakes shaped like the official
``kubernetes`` client's RBAC model objects (``V1Role``, ``V1PolicyRule``,
``V1RoleBinding``, ``V1Subject``, ``V1ServiceAccount``, etc.).
"""

from __future__ import annotations

from types import SimpleNamespace as NS
from typing import Optional


def make_policy_rule(
    *,
    api_groups: Optional[list[str]] = None,
    resources: Optional[list[str]] = None,
    verbs: Optional[list[str]] = None,
    resource_names: Optional[list[str]] = None,
    non_resource_urls: Optional[list[str]] = None,
) -> NS:
    return NS(
        api_groups=api_groups if api_groups is not None else [""],
        resources=resources if resources is not None else [],
        verbs=verbs if verbs is not None else [],
        resource_names=resource_names,
        non_resource_urls=non_resource_urls,
    )


def make_role(
    *, namespace: str = "prod", name: str = "reader", uid: str = "role-uid-1",
    rules: Optional[list] = None, labels: Optional[dict] = None,
) -> NS:
    return NS(
        metadata=NS(namespace=namespace, name=name, uid=uid, labels=labels or {}),
        rules=rules if rules is not None else [make_policy_rule(resources=["pods"], verbs=["get", "list"])],
        aggregation_rule=None,
    )


def make_cluster_role(
    *, name: str = "custom-role", uid: str = "crole-uid-1",
    rules: Optional[list] = None, labels: Optional[dict] = None,
    aggregation_rule: Optional[NS] = None,
) -> NS:
    return NS(
        metadata=NS(name=name, uid=uid, labels=labels or {}),
        rules=rules if rules is not None else [make_policy_rule(resources=["pods"], verbs=["get", "list"])],
        aggregation_rule=aggregation_rule,
    )


def make_aggregation_rule(match_labels_list: list[dict]) -> NS:
    return NS(cluster_role_selectors=[NS(match_labels=ml) for ml in match_labels_list])


def make_subject(
    *, kind: str = "ServiceAccount", name: str = "deployer", namespace: Optional[str] = "prod",
) -> NS:
    return NS(kind=kind, name=name, namespace=namespace)


def make_role_ref(*, kind: str = "ClusterRole", name: str = "view", api_group: str = "rbac.authorization.k8s.io") -> NS:
    return NS(kind=kind, name=name, api_group=api_group)


_UNSET = object()


def make_role_binding(
    *, namespace: str = "prod", name: str = "deployer-binding", uid: str = "rb-uid-1",
    role_ref=_UNSET, subjects: Optional[list] = None,
) -> NS:
    return NS(
        metadata=NS(namespace=namespace, name=name, uid=uid),
        role_ref=make_role_ref(kind="Role", name="reader") if role_ref is _UNSET else role_ref,
        subjects=subjects if subjects is not None else [make_subject()],
    )


def make_cluster_role_binding(
    *, name: str = "deployer-cluster-binding", uid: str = "crb-uid-1",
    role_ref: Optional[NS] = None, subjects: Optional[list] = None,
) -> NS:
    return NS(
        metadata=NS(name=name, uid=uid),
        role_ref=role_ref if role_ref is not None else make_role_ref(),
        subjects=subjects if subjects is not None else [make_subject()],
    )


def make_service_account(
    *, namespace: str = "prod", name: str = "deployer", uid: str = "sa-uid-1",
    automount_service_account_token: Optional[bool] = None,
    image_pull_secrets: Optional[list] = None, secrets: Optional[list] = None,
) -> NS:
    return NS(
        metadata=NS(namespace=namespace, name=name, uid=uid),
        automount_service_account_token=automount_service_account_token,
        image_pull_secrets=image_pull_secrets or [],
        secrets=secrets or [],
    )


def page(items: list, continue_token: Optional[str] = None) -> NS:
    return NS(items=items, metadata=NS(_continue=continue_token))
