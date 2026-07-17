"""Shared fake-object builders for Kubernetes message-2 (workload) tests.

Not a test file itself (no ``Test*``/``test_*`` collectable members) — a
plain helper module imported by ``test_kubernetes_workload_foundation.py``,
``test_kubernetes_pod_security_normalization.py``, and
``test_kubernetes_workload_diff.py``.

Builds lightweight ``SimpleNamespace`` fakes shaped like the official
``kubernetes`` client's generated model objects (``V1Container``,
``V1PodSpec``, ``V1Deployment``, etc.) — attribute access only, matching
what the connector's normalization code expects via ``getattr(...)``.
"""

from __future__ import annotations

from types import SimpleNamespace as NS
from typing import Any, Optional


def make_security_context(
    *,
    privileged: Optional[bool] = None,
    allow_privilege_escalation: Optional[bool] = None,
    run_as_user: Optional[int] = None,
    run_as_group: Optional[int] = None,
    run_as_non_root: Optional[bool] = None,
    read_only_root_filesystem: Optional[bool] = None,
    seccomp_profile: Any = None,
    app_armor_profile: Any = None,
    capabilities_add: Optional[list[str]] = None,
    capabilities_drop: Optional[list[str]] = None,
    se_linux_options: Any = None,
    windows_options: Any = None,
    proc_mount: Optional[str] = None,
) -> NS:
    capabilities = None
    if capabilities_add is not None or capabilities_drop is not None:
        capabilities = NS(add=capabilities_add, drop=capabilities_drop)
    return NS(
        privileged=privileged,
        allow_privilege_escalation=allow_privilege_escalation,
        run_as_user=run_as_user,
        run_as_group=run_as_group,
        run_as_non_root=run_as_non_root,
        read_only_root_filesystem=read_only_root_filesystem,
        seccomp_profile=seccomp_profile,
        app_armor_profile=app_armor_profile,
        capabilities=capabilities,
        se_linux_options=se_linux_options,
        windows_options=windows_options,
        proc_mount=proc_mount,
    )


def make_container(
    *,
    name: str = "app",
    image: str = "nginx:1.25.3",
    image_pull_policy: Optional[str] = None,
    security_context: Any = None,
    ports: Optional[list] = None,
    resources: Any = None,
    volume_mounts: Optional[list] = None,
    liveness_probe: Any = None,
    readiness_probe: Any = None,
    startup_probe: Any = None,
    env: Optional[list] = None,
    command: Optional[list[str]] = None,
    args: Optional[list[str]] = None,
) -> NS:
    return NS(
        name=name,
        image=image,
        image_pull_policy=image_pull_policy,
        security_context=security_context,
        ports=ports or [],
        resources=resources or NS(requests={}, limits={}),
        volume_mounts=volume_mounts or [],
        liveness_probe=liveness_probe,
        readiness_probe=readiness_probe,
        startup_probe=startup_probe,
        # These are never read by the connector's normalization — present
        # here only so sensitive-data-exclusion tests can prove that.
        env=env,
        command=command,
        args=args,
    )


def make_hostpath_volume(name: str, path: str) -> NS:
    return NS(
        name=name,
        host_path=NS(path=path),
        config_map=None, secret=None, empty_dir=None,
        persistent_volume_claim=None, projected=None,
    )


def make_configmap_volume(name: str) -> NS:
    return NS(
        name=name, host_path=None,
        config_map=NS(name=f"{name}-cm"),
        secret=None, empty_dir=None, persistent_volume_claim=None, projected=None,
    )


def make_secret_volume(name: str) -> NS:
    return NS(
        name=name, host_path=None, config_map=None,
        secret=NS(secret_name=f"{name}-secret"),
        empty_dir=None, persistent_volume_claim=None, projected=None,
    )


def make_sa_token_volume(name: str = "kube-api-access-abcde") -> NS:
    return NS(
        name=name, host_path=None, config_map=None, secret=None, empty_dir=None,
        persistent_volume_claim=None,
        projected=NS(sources=[NS(service_account_token=NS(path="token"))]),
    )


def make_volume_mount(
    name: str, *, read_only: bool = False, mount_propagation: Optional[str] = None
) -> NS:
    return NS(name=name, read_only=read_only, mount_propagation=mount_propagation)


def make_pod_spec(
    *,
    containers: Optional[list] = None,
    init_containers: Optional[list] = None,
    ephemeral_containers: Optional[list] = None,
    volumes: Optional[list] = None,
    service_account_name: Optional[str] = "default",
    automount_service_account_token: Optional[bool] = None,
    host_network: bool = False,
    host_pid: bool = False,
    host_ipc: bool = False,
    share_process_namespace: Optional[bool] = None,
    dns_policy: Optional[str] = "ClusterFirst",
    restart_policy: Optional[str] = "Always",
    runtime_class_name: Optional[str] = None,
    node_selector: Optional[dict] = None,
    tolerations: Optional[list] = None,
    affinity: Any = None,
    topology_spread_constraints: Optional[list] = None,
    image_pull_secrets: Optional[list] = None,
    security_context: Any = None,
) -> NS:
    return NS(
        containers=containers or [make_container()],
        init_containers=init_containers or [],
        ephemeral_containers=ephemeral_containers or [],
        volumes=volumes or [],
        service_account_name=service_account_name,
        service_account=None,
        automount_service_account_token=automount_service_account_token,
        host_network=host_network,
        host_pid=host_pid,
        host_ipc=host_ipc,
        share_process_namespace=share_process_namespace,
        dns_policy=dns_policy,
        restart_policy=restart_policy,
        runtime_class_name=runtime_class_name,
        node_selector=node_selector or {},
        tolerations=tolerations or [],
        affinity=affinity,
        topology_spread_constraints=topology_spread_constraints or [],
        image_pull_secrets=image_pull_secrets or [],
        security_context=security_context,
    )


def make_pod_template(pod_spec: NS, *, annotations: Optional[dict] = None, labels: Optional[dict] = None) -> NS:
    return NS(spec=pod_spec, metadata=NS(annotations=annotations or {}, labels=labels or {}))


def make_deployment(
    *, namespace: str = "prod", name: str = "web", uid: str = "uid-dep-1",
    replicas: int = 3, strategy_type: str = "RollingUpdate", pod_spec: Optional[NS] = None,
) -> NS:
    return NS(
        metadata=NS(namespace=namespace, name=name, uid=uid),
        spec=NS(
            replicas=replicas,
            strategy=NS(type=strategy_type),
            template=make_pod_template(pod_spec or make_pod_spec()),
        ),
    )


def make_statefulset(
    *, namespace: str = "prod", name: str = "db", uid: str = "uid-sts-1",
    replicas: int = 3, strategy_type: str = "RollingUpdate", pod_spec: Optional[NS] = None,
) -> NS:
    return NS(
        metadata=NS(namespace=namespace, name=name, uid=uid),
        spec=NS(
            replicas=replicas,
            update_strategy=NS(type=strategy_type),
            template=make_pod_template(pod_spec or make_pod_spec()),
        ),
    )


def make_daemonset(
    *, namespace: str = "kube-system", name: str = "agent", uid: str = "uid-ds-1",
    strategy_type: str = "RollingUpdate", pod_spec: Optional[NS] = None,
) -> NS:
    return NS(
        metadata=NS(namespace=namespace, name=name, uid=uid),
        spec=NS(
            update_strategy=NS(type=strategy_type),
            template=make_pod_template(pod_spec or make_pod_spec()),
        ),
    )


def make_job(
    *, namespace: str = "batch", name: str = "migrate", uid: str = "uid-job-1",
    parallelism: int = 1, pod_spec: Optional[NS] = None,
) -> NS:
    ps = pod_spec or make_pod_spec(restart_policy="Never")
    return NS(
        metadata=NS(namespace=namespace, name=name, uid=uid),
        spec=NS(parallelism=parallelism, template=make_pod_template(ps)),
    )


def make_cronjob(
    *, namespace: str = "batch", name: str = "nightly", uid: str = "uid-cj-1",
    concurrency_policy: str = "Forbid", pod_spec: Optional[NS] = None,
) -> NS:
    ps = pod_spec or make_pod_spec(restart_policy="OnFailure")
    job_spec = NS(template=make_pod_template(ps))
    return NS(
        metadata=NS(namespace=namespace, name=name, uid=uid),
        spec=NS(concurrency_policy=concurrency_policy, job_template=NS(spec=job_spec)),
    )


def make_pod(
    *, namespace: str = "prod", name: str = "standalone-debug", uid: str = "uid-pod-1",
    owner_references: Optional[list] = None, pod_spec: Optional[NS] = None,
    phase: str = "Running", annotations: Optional[dict] = None,
    conditions: Optional[list] = None, host_ip: Optional[str] = "10.0.0.9",
    pod_ips: Optional[list] = None, container_statuses: Optional[list] = None,
) -> NS:
    status = NS(
        phase=phase,
        conditions=conditions if conditions is not None else [
            NS(type="PodScheduled", status="True"),
            NS(type="Ready", status="True"),
        ],
        host_ip=host_ip,
        pod_ips=pod_ips if pod_ips is not None else [NS(ip="10.1.2.3")],
        container_statuses=container_statuses or [],
        init_container_statuses=[],
    )
    return NS(
        metadata=NS(
            namespace=namespace, name=name, uid=uid,
            owner_references=owner_references or [],
            annotations=annotations or {},
        ),
        spec=pod_spec or make_pod_spec(),
        status=status,
    )


def make_container_status(*, restart_count: int = 0, waiting_reason: Optional[str] = None, terminated_reason: Optional[str] = None) -> NS:
    waiting = NS(reason=waiting_reason) if waiting_reason else None
    terminated = NS(reason=terminated_reason) if terminated_reason else None
    return NS(restart_count=restart_count, state=NS(waiting=waiting, terminated=terminated))


def page(items: list, continue_token: Optional[str] = None) -> NS:
    return NS(items=items, metadata=NS(_continue=continue_token))
