"""Kubernetes connector — foundation + workload security (messages 1-2 of 9).

Message 1 established the durable architecture for the Kubernetes provider:
client initialization, cluster identity, namespace scoping, API discovery, a
fail-soft API-call wrapper, and a pagination helper, emitting
``kubernetes_cluster``, ``kubernetes_namespace``, and
``kubernetes_api_capability`` records.

Message 2 (this message) adds workload inventory and Pod-security posture:
Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, standalone Pods, and
per-container security-context records. RBAC, networking, and
admission-control collection are NOT implemented yet; they are built in
later messages against this same foundation.

Pod-emission policy (message 2)
----------------------------------
Standalone Pods (``metadata.ownerReferences`` empty) are emitted as
``kubernetes_pod`` records with both declarative posture (mirroring the
controller-record fields) and a small set of clearly-separated runtime-only
fields (phase, scheduled/ready conditions, restart count, IP presence).

Controller-owned Pods (owned by a ReplicaSet/StatefulSet/DaemonSet/Job) are
**not** emitted as individual ``kubernetes_pod`` records. Their security
posture is fully captured once, precisely, from the owning controller's Pod
template (``spec.template``/``spec.jobTemplate.spec.template``) — emitting
one record per live Pod of e.g. a 50-replica Deployment would duplicate
identical template posture 50 times with zero additional security signal,
and would make an ordinary rolling-update look like 50 create/delete
"configuration" Changes rather than the one real Change (the template
itself). Runtime-only fields for controller-owned Pods (restart counts,
phase transitions, node placement) are explicitly deferred — this message
does not attempt to reconcile per-replica runtime drift, per the "avoid
duplicating meaningless data" requirement.

Container security-context records (``kubernetes_container_security_context``)
are emitted once per container — application, init, or ephemeral — for
every workload family (including standalone Pods), giving container-level
diff precision independent of the coarser workload-level aggregate summary
fields also carried on the controller/Pod record.

Explicit / effective / unknown semantics
-------------------------------------------
See ``kubernetes_schema.py`` for the full policy. In short: every tri-state
security field is ``True``/``False``/``None``, where ``None`` always means
"not explicitly set in the object we read" — never a confirmed secure or
risky state. ``hostNetwork``/``hostPID``/``hostIPC`` are the one exception
stored as concrete booleans (their Kubernetes-documented default is
``false``, not "unknown").

Authentication model
---------------------
Supported (message 1):
    kubeconfig content (YAML), supplied as ``credentials["kubeconfig"]``,
    with an explicit or default context selected via
    ``credentials.get("context")``. This transparently covers static
    bearer-token, client-certificate/key, and basic-auth user entries,
    since those are all standard kubeconfig ``users[].user`` shapes that
    the official Kubernetes client already parses safely.

Explicitly rejected (never executed, for safety):
    ``exec:`` auth plugins and legacy ``auth-provider`` cloud plugins
    (e.g. gcp/azure) in the selected context's user entry. Both mechanisms
    shell out to external binaries; ConfigTrace's backend has no business
    executing arbitrary commands supplied via user-uploaded configuration.
    Detected and rejected BEFORE the kubeconfig is ever handed to the
    Kubernetes client, with a clear, actionable error message.

Deferred (not implemented, no architectural objection):
    A flat bearer-token + API-server-URL + CA-certificate credential mode
    (useful for a minimal-permission ServiceAccount token without a full
    kubeconfig). Natural to add in a later message; kubeconfig content
    already covers the same use case today.

Not applicable:
    In-cluster ServiceAccount auto-discovery. ConfigTrace's backend runs
    as an external service, not inside the monitored cluster.

SENSITIVE-DATA POLICY (mandatory)
-----------------------------------
This connector NEVER fetches or persists:
    Secret values, ConfigMap values, service-account token contents,
    kubeconfig contents, bearer tokens, client private keys/certificates
    (beyond the fact that TLS verification is enabled/disabled), registry
    pull secrets, environment-variable values, Pod logs, exec output,
    application logs, raw admission-review payloads, raw audit events, raw
    annotation maps, or arbitrary label maps.

Message 1 does not call any Secret or ConfigMap API at all — not even to
read metadata. That begins (metadata only, values never) in message 5.

Namespace labels are read ONLY for the fixed, well-known Pod Security
Admission label keys (see ``SAFE_NAMESPACE_LABEL_KEYS`` in
``kubernetes_schema.py``) — never as an arbitrary label map. No annotations
are read anywhere in this connector.

Scope model
------------
One cluster (one kubeconfig context) per Integration. Cluster-scoped
listing (namespaces) is attempted when permitted. An optional user-supplied
namespace allowlist (``credentials["namespace_allowlist"]``) restricts which
namespaces are collected; there is no default denylist — ``kube-system``,
``kube-public``, and ``kube-node-lease`` are collected like any other
namespace unless the user explicitly excludes them via the allowlist.

Cluster identity
------------------
The stable ``cluster_id`` is the ``kube-system`` namespace UID when it can
be read (immutable for the life of the cluster, present on every real
Kubernetes cluster). If ``kube-system`` cannot be read (permission denied),
a deterministic SHA-256 hash of the normalized API server host (scheme,
host, port only — no path, query string, or credentials) is used instead.
The kubeconfig context name is never part of the identity — it is
mutable, user-chosen display metadata only.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import yaml

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.kubernetes_schema import (
    APPARMOR_ANNOTATION_PREFIX,
    CAPABILITY_ALL,
    CONTAINER_CATEGORY_APPLICATION,
    CONTAINER_CATEGORY_EPHEMERAL,
    CONTAINER_CATEGORY_INIT,
    COVERAGE_FULL,
    COVERAGE_NONE,
    COVERAGE_PARTIAL,
    DANGEROUS_CAPABILITIES,
    DANGEROUS_HOSTPATH_CATEGORIES,
    IMAGE_TAG_EXPLICIT,
    IMAGE_TAG_LATEST_EXPLICIT,
    IMAGE_TAG_LATEST_IMPLICIT,
    IMAGE_TAG_PINNED_DIGEST,
    KUBERNETES_API_CAPABILITY,
    KUBERNETES_CLUSTER,
    KUBERNETES_CONTAINER_SECURITY_CONTEXT,
    KUBERNETES_CRONJOB,
    KUBERNETES_DAEMONSET,
    KUBERNETES_DEPLOYMENT,
    KUBERNETES_JOB,
    KUBERNETES_NAMESPACE,
    KUBERNETES_POD,
    KUBERNETES_STATEFULSET,
    KUBERNETES_WORKLOAD_SERVICE_ACCOUNT,
    PROFILE_CATEGORY_OMITTED,
    PSA_LABEL_AUDIT,
    PSA_LABEL_AUDIT_VERSION,
    PSA_LABEL_ENFORCE,
    PSA_LABEL_ENFORCE_VERSION,
    PSA_LABEL_WARN,
    PSA_LABEL_WARN_VERSION,
    SECURITY_POSTURE_ELEVATED,
    SECURITY_POSTURE_PRIVILEGED_OR_HOST_ACCESS,
    SECURITY_POSTURE_STANDARD,
    SENSITIVE_HOST_PORTS,
    categorize_hostpath,
    categorize_image_registry,
    categorize_image_tag,
    categorize_legacy_apparmor_annotation,
    seccomp_or_apparmor_profile_category,
)

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT_SECONDS = 30
_DEFAULT_PAGE_SIZE = 100
_MAX_PAGES = 50  # defensive cap — prevents unbounded continuation loops

# API-server host categories. Never store the raw hostname/IP — only the
# safe category — since the literal host string could reveal internal
# network topology.
_HOST_CATEGORY_PRIVATE_IP = "private_ip"
_HOST_CATEGORY_PUBLIC_IP = "public_ip"
_HOST_CATEGORY_LOCALHOST = "localhost"
_HOST_CATEGORY_DNS_HOSTNAME = "dns_hostname"
_HOST_CATEGORY_UNKNOWN = "unknown"

# Resource families this connector plans to eventually collect (messages
# 2-5). Anything discovered outside this set is still recorded (so future
# messages can see it was available) but categorized "not_supported" rather
# than "planned".
_PLANNED_RESOURCE_NAMES: frozenset[str] = frozenset(
    {
        "namespaces",
        "deployments", "statefulsets", "daemonsets", "jobs", "cronjobs", "pods",
        "roles", "clusterroles", "rolebindings", "clusterrolebindings", "serviceaccounts",
        "services", "ingresses", "gateways", "httproutes", "networkpolicies",
        "secrets", "configmaps", "validatingwebhookconfigurations",
        "mutatingwebhookconfigurations", "resourcequotas", "limitranges",
    }
)

# API groups probed during discovery. Each is fetched independently and
# fails soft — an absent group (e.g. no Gateway API installed) is recorded
# as unavailable, never assumed present or absent without a real API call.
# (group, version, typed-client-attr-or-None). typed-client-attr None means
# "no generated client class exists for this group" (true for CRD-based
# APIs like Gateway API) — those are probed via a raw discovery call.
_DISCOVERY_GROUPS: tuple[tuple[str, str, Optional[str]], ...] = (
    ("", "v1", "CoreV1Api"),
    ("apps", "v1", "AppsV1Api"),
    ("rbac.authorization.k8s.io", "v1", "RbacAuthorizationV1Api"),
    ("networking.k8s.io", "v1", "NetworkingV1Api"),
    ("policy", "v1", "PolicyV1Api"),
    ("batch", "v1", "BatchV1Api"),
    ("admissionregistration.k8s.io", "v1", "AdmissionregistrationV1Api"),
    ("gateway.networking.k8s.io", "v1", None),
)


# ── Fail-soft API-call wrapper ────────────────────────────────────────────────

@dataclass
class CallOutcome:
    """Result of one fail-soft Kubernetes API call.

    ``category`` is always one of the values below and never leaks
    credential material — only a safe, fixed message plus the HTTP status
    code (if any) is retained in ``detail``.
    """

    ok: bool
    result: Any = None
    category: str = "success"
    detail: str = ""


# Category constants — one per distinguishable failure mode this wrapper
# must separate (see module docstring / kubernetes_foundation_contract.md).
CATEGORY_SUCCESS = "success"
CATEGORY_AUTH_FAILED = "auth_failed"
CATEGORY_PERMISSION_DENIED = "permission_denied"
CATEGORY_NOT_FOUND = "not_found"
CATEGORY_CONTINUATION_EXPIRED = "continuation_expired"
CATEGORY_THROTTLED = "throttled"
CATEGORY_SERVER_ERROR = "server_error"
CATEGORY_CONNECTION_ERROR = "connection_error"
CATEGORY_TLS_ERROR = "tls_error"
CATEGORY_MALFORMED_RESPONSE = "malformed_response"
CATEGORY_API_UNAVAILABLE = "api_unavailable"


def _classify_api_exception(exc: Exception) -> tuple[str, str]:
    """Map a raised exception to ``(category, safe_detail)``.

    Never includes raw exception text that might embed request URLs with
    query strings, tokens, or certificate material — only the HTTP status
    code (safe) and a fixed, category-specific description.
    """
    from kubernetes.client.rest import ApiException

    if isinstance(exc, ApiException):
        status = exc.status
        if status == 401:
            return CATEGORY_AUTH_FAILED, "HTTP 401: credentials rejected by the API server."
        if status == 403:
            return CATEGORY_PERMISSION_DENIED, "HTTP 403: permission denied for this resource."
        if status == 404:
            return CATEGORY_NOT_FOUND, "HTTP 404: resource or API group not found."
        if status == 410:
            return CATEGORY_CONTINUATION_EXPIRED, "HTTP 410: list continuation token expired."
        if status == 429:
            return CATEGORY_THROTTLED, "HTTP 429: request was throttled by the API server."
        if status is not None and status >= 500:
            return CATEGORY_SERVER_ERROR, f"HTTP {status}: API server returned a server error."
        return CATEGORY_SERVER_ERROR, f"HTTP {status}: unexpected API error."

    # Import lazily — these are urllib3/ssl exceptions raised by the
    # transport layer beneath the generated client, not ApiException.
    import ssl

    from urllib3.exceptions import MaxRetryError, SSLError as Urllib3SSLError

    if isinstance(exc, (Urllib3SSLError, ssl.SSLError)):
        return CATEGORY_TLS_ERROR, "TLS certificate verification failed."
    if isinstance(exc, MaxRetryError):
        cause = str(exc.reason).lower() if exc.reason else ""
        if "certificate" in cause or "ssl" in cause:
            return CATEGORY_TLS_ERROR, "TLS certificate verification failed."
        return CATEGORY_CONNECTION_ERROR, "Could not connect to the Kubernetes API server."
    if isinstance(exc, (ConnectionError, OSError)):
        return CATEGORY_CONNECTION_ERROR, "Could not connect to the Kubernetes API server."

    return CATEGORY_MALFORMED_RESPONSE, "The API server returned a response that could not be parsed."


def call_k8s(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> CallOutcome:
    """Fail-soft wrapper around any single (non-paginated) Kubernetes API call.

    Every list/get call made by this connector — now and in future
    messages — should route through this wrapper (or ``paginate_list``,
    which uses it internally) rather than calling the generated client
    directly, so every caller gets the same distinguishable failure
    categories instead of an uncaught exception.
    """
    kwargs.setdefault("_request_timeout", _REQUEST_TIMEOUT_SECONDS)
    try:
        result = fn(*args, **kwargs)
        return CallOutcome(ok=True, result=result, category=CATEGORY_SUCCESS)
    except Exception as exc:  # noqa: BLE001 — deliberately broad; classified below
        category, detail = _classify_api_exception(exc)
        logger.info("Kubernetes API call failed: category=%s detail=%s", category, detail)
        return CallOutcome(ok=False, result=None, category=category, detail=detail)


# ── Pagination helper ─────────────────────────────────────────────────────────

@dataclass
class PageDiagnostics:
    pages_fetched: int = 0
    complete: bool = True
    truncated_by_page_cap: bool = False
    permission_denied: bool = False
    continuation_restarted: bool = False
    malformed_metadata: bool = False
    error_category: Optional[str] = None
    error_detail: str = ""


def paginate_list(
    list_fn: Callable[..., Any],
    *,
    page_size: int = _DEFAULT_PAGE_SIZE,
    max_pages: int = _MAX_PAGES,
    **kwargs: Any,
) -> tuple[list[Any], PageDiagnostics]:
    """Collect every item from a Kubernetes list API, following ``_continue``.

    Returns ``(items, diagnostics)``. ``diagnostics.complete`` is ``False``
    whenever the collection stopped early for any reason (permission
    denial, page cap, malformed metadata, repeated continuation token) —
    callers must treat an incomplete collection as PARTIAL data, never as
    "the resource family is empty".

    Safety properties:
    * A 410 (continuation token expired) triggers exactly one restart from
      the beginning without a continue token — never an infinite retry
      loop. If the restarted first page also fails, collection stops with
      ``complete=False``.
    * A repeated (identical) continuation token is detected and treated as
      a stop condition rather than looping forever.
    * ``max_pages`` bounds the number of pages fetched even when the
      server keeps returning a fresh continue token, so an
    * A permission failure on any page after the first returns everything
      collected so far, marked incomplete — it never raises, and it never
      discards previously-collected items.
    """
    items: list[Any] = []
    diag = PageDiagnostics()
    seen_tokens: set[str] = set()
    continue_token: Optional[str] = None
    already_restarted = False

    while True:
        if diag.pages_fetched >= max_pages:
            diag.complete = False
            diag.truncated_by_page_cap = True
            break

        call_kwargs = dict(kwargs)
        call_kwargs["limit"] = page_size
        if continue_token:
            call_kwargs["_continue"] = continue_token

        outcome = call_k8s(list_fn, **call_kwargs)

        if not outcome.ok:
            if outcome.category == CATEGORY_CONTINUATION_EXPIRED and not already_restarted:
                # Restart from the beginning exactly once — per the K8s API
                # contract, a 410 means the token is no longer valid; the
                # client must re-list from scratch to get a consistent view.
                already_restarted = True
                diag.continuation_restarted = True
                continue_token = None
                items = []
                continue
            diag.complete = False
            diag.permission_denied = outcome.category == CATEGORY_PERMISSION_DENIED
            diag.error_category = outcome.category
            diag.error_detail = outcome.detail
            break

        diag.pages_fetched += 1
        page = outcome.result
        page_items = getattr(page, "items", None)
        if page_items is None:
            # Malformed/unexpected page shape — stop rather than guess.
            diag.complete = False
            diag.malformed_metadata = True
            break
        items.extend(page_items)

        metadata = getattr(page, "metadata", None)
        next_token = getattr(metadata, "_continue", None) if metadata is not None else None
        if metadata is None:
            diag.malformed_metadata = True

        if not next_token:
            break
        if next_token in seen_tokens:
            # Repeated continuation token — stop to avoid an infinite loop.
            diag.complete = False
            diag.error_category = "repeated_continuation_token"
            break
        seen_tokens.add(next_token)
        continue_token = next_token

    return items, diag


# ── Cluster identity ──────────────────────────────────────────────────────────

def normalize_api_server_host(raw_host: str) -> str:
    """Return ``host:port`` (or ``host``) with no scheme, credentials, path,
    or query string. Never returns anything that could embed a token."""
    candidate = raw_host.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    netloc = parsed.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[-1]
    return netloc.lower()


def categorize_api_server_host(raw_host: str) -> str:
    """Classify the API server host into a safe bucket — never persist the
    literal hostname/IP, since it may reveal internal network topology."""
    normalized = normalize_api_server_host(raw_host)
    hostname = normalized.rsplit(":", 1)[0] if ":" in normalized else normalized
    hostname = hostname.strip("[]")  # IPv6 literals are bracketed
    if hostname in ("localhost",):
        return _HOST_CATEGORY_LOCALHOST
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return _HOST_CATEGORY_DNS_HOSTNAME if hostname else _HOST_CATEGORY_UNKNOWN
    if ip.is_loopback:
        return _HOST_CATEGORY_LOCALHOST
    if ip.is_private:
        return _HOST_CATEGORY_PRIVATE_IP
    return _HOST_CATEGORY_PUBLIC_IP


def compute_cluster_id(*, api_server_host: str, kube_system_uid: Optional[str]) -> str:
    """Stable cluster identity.

    Prefers the ``kube-system`` namespace UID (immutable, always present on
    a real cluster). Falls back to a deterministic hash of the normalized
    API server host when ``kube-system`` cannot be read (e.g. the
    credential lacks permission to get that one namespace) — this fallback
    means two different clusters reachable at the same host:port could
    theoretically collide, and a cluster whose host changes (e.g. DNS
    migration) without kube-system access would be seen as a new cluster;
    both are accepted, documented trade-offs of the fallback path. The
    kube-system UID path has no such collision risk since UIDs are
    server-generated and globally unique.
    """
    if kube_system_uid:
        return f"uid:{kube_system_uid}"
    normalized = normalize_api_server_host(api_server_host)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]
    return f"host:{digest}"


# ── kubeconfig safety ─────────────────────────────────────────────────────────

_REJECTED_AUTH_KEYS: tuple[str, ...] = ("exec", "auth-provider")


def _resolve_context(config_dict: dict, context_name: Optional[str]) -> dict:
    contexts = {c.get("name"): c for c in (config_dict.get("contexts") or [])}
    if not contexts:
        raise ConnectorError("kubeconfig contains no contexts.")
    selected_name = context_name or config_dict.get("current-context")
    if not selected_name:
        raise ConnectorError(
            "No context was specified and the kubeconfig has no current-context set."
        )
    ctx = contexts.get(selected_name)
    if ctx is None:
        raise ConnectorError(f"Context {selected_name!r} was not found in the kubeconfig.")
    return ctx


def assert_context_auth_is_supported(config_dict: dict, context_name: Optional[str]) -> str:
    """Reject contexts whose user entry requires executing an external
    binary. Returns the resolved context name on success.

    This check runs BEFORE the kubeconfig is ever handed to the Kubernetes
    client library, so an ``exec``/``auth-provider`` entry is never
    invoked — not even once — by ConfigTrace's backend.
    """
    ctx = _resolve_context(config_dict, context_name)
    resolved_name = ctx.get("name")
    user_name = (ctx.get("context") or {}).get("user")
    users = {u.get("name"): u for u in (config_dict.get("users") or [])}
    user_entry = (users.get(user_name) or {}).get("user") or {}

    for rejected_key in _REJECTED_AUTH_KEYS:
        if rejected_key in user_entry:
            raise AuthenticationError(
                f"The selected context {resolved_name!r} uses a {rejected_key!r} "
                "authentication mechanism, which ConfigTrace does not execute "
                "for security reasons (it would run an external binary supplied "
                "via uploaded configuration). Use a context with a static "
                "bearer token or client certificate instead."
            )
    return resolved_name


# ── Version normalization ─────────────────────────────────────────────────────

def normalize_kubernetes_version(git_version: Optional[str]) -> Optional[str]:
    """Strip noisy build-metadata suffixes from a GitVersion string.

    Examples: ``"v1.29.3-eks-1234abc"`` -> ``"v1.29.3"``;
    ``"v1.28.9+k3s1"`` -> ``"v1.28.9"``.
    """
    if not git_version:
        return None
    version = git_version.strip()
    for sep in ("+", "-"):
        if sep in version:
            version = version.split(sep, 1)[0]
    return version or None


def major_minor(version: Optional[str]) -> Optional[str]:
    if not version:
        return None
    stripped = version.lstrip("v")
    parts = stripped.split(".")
    if len(parts) < 2:
        return None
    return f"{parts[0]}.{parts[1]}"


# ── Namespace normalization ────────────────────────────────────────────────────

def _normalize_namespace(namespace_obj: Any, *, cluster_id: str, cluster_name: str) -> dict:
    metadata = namespace_obj.metadata
    name = metadata.name
    uid = getattr(metadata, "uid", None)
    labels = getattr(metadata, "labels", None) or {}
    status = getattr(namespace_obj, "status", None)
    phase = getattr(status, "phase", None) if status is not None else None

    record_id = f"{cluster_id}/namespace/{uid or name}"
    return {
        "record_type": KUBERNETES_NAMESPACE,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "api_version": "v1",
        "kind": "Namespace",
        "name": name,
        "uid": uid,
        "phase": phase,
        "terminating": phase == "Terminating",
        "psa_enforce": labels.get(PSA_LABEL_ENFORCE),
        "psa_enforce_version": labels.get(PSA_LABEL_ENFORCE_VERSION),
        "psa_audit": labels.get(PSA_LABEL_AUDIT),
        "psa_audit_version": labels.get(PSA_LABEL_AUDIT_VERSION),
        "psa_warn": labels.get(PSA_LABEL_WARN),
        "psa_warn_version": labels.get(PSA_LABEL_WARN_VERSION),
    }


def _apply_namespace_allowlist(
    namespaces: list[dict], allowlist: Optional[list[str]]
) -> list[dict]:
    if allowlist is None:
        return namespaces
    allowed = set(allowlist)
    return [ns for ns in namespaces if ns["name"] in allowed]


# ── Workload / Pod-security normalization (message 2) ─────────────────────────

_API_VERSION_BY_KIND: dict[str, str] = {
    "Deployment": "apps/v1",
    "StatefulSet": "apps/v1",
    "DaemonSet": "apps/v1",
    "Job": "batch/v1",
    "CronJob": "batch/v1",
}

_DANGEROUS_TOLERATION_KEYS: frozenset[str] = frozenset(
    {"node-role.kubernetes.io/master", "node-role.kubernetes.io/control-plane"}
)

_CONTAINER_STATE_REASON_CATEGORIES: dict[str, str] = {
    "ImagePullBackOff": "image_pull_error",
    "ErrImagePull": "image_pull_error",
    "CrashLoopBackOff": "crash_loop",
    "Completed": "completed",
    "OOMKilled": "oom_killed",
    "Error": "error",
    "ContainerCreating": "creating",
    "PodInitializing": "creating",
}


def _categorize_container_state_reason(reason: Optional[str]) -> Optional[str]:
    if not reason:
        return None
    return _CONTAINER_STATE_REASON_CATEGORIES.get(reason, "other")


def _coverage(count: int, total: int) -> str:
    if total == 0 or count == 0:
        return COVERAGE_NONE
    if count == total:
        return COVERAGE_FULL
    return COVERAGE_PARTIAL


def _summarize_categories(categories: set[str]) -> str:
    if not categories:
        return PROFILE_CATEGORY_OMITTED
    if len(categories) == 1:
        return next(iter(categories))
    return "mixed"


def _normalize_capabilities(security_context: Any) -> tuple[list[str], list[str], list[str]]:
    """Returns ``(added, dropped, dangerous_added)`` — all uppercased, sorted,
    de-duplicated. ``dangerous_added`` includes ``ALL`` and any name in
    ``DANGEROUS_CAPABILITIES``."""
    capabilities = getattr(security_context, "capabilities", None) if security_context else None
    added_raw = (getattr(capabilities, "add", None) or []) if capabilities else []
    dropped_raw = (getattr(capabilities, "drop", None) or []) if capabilities else []
    added = sorted({str(c).strip().upper() for c in added_raw if c})
    dropped = sorted({str(c).strip().upper() for c in dropped_raw if c})
    dangerous_added = sorted(c for c in added if c in DANGEROUS_CAPABILITIES or c == CAPABILITY_ALL)
    return added, dropped, dangerous_added


def _effective_seccomp_category(container_security_context: Any, pod_security_context: Any) -> str:
    """Container-level seccomp profile if explicitly set, else the
    Pod-level (inherited) profile, else omitted. Never invents a value."""
    container_profile = (
        getattr(container_security_context, "seccomp_profile", None)
        if container_security_context else None
    )
    if container_profile is not None:
        return seccomp_or_apparmor_profile_category(container_profile)
    pod_profile = (
        getattr(pod_security_context, "seccomp_profile", None)
        if pod_security_context else None
    )
    return seccomp_or_apparmor_profile_category(pod_profile)


def _apparmor_profile_category(
    container_security_context: Any, pod_annotations: dict, container_name: str
) -> str:
    """Modern structured field first (Kubernetes 1.30+); falls back to the
    legacy, single well-known annotation key for this exact container name.
    Never reads or stores any other annotation."""
    structured = (
        getattr(container_security_context, "app_armor_profile", None)
        if container_security_context else None
    )
    if structured is not None:
        return seccomp_or_apparmor_profile_category(structured)
    annotation_key = f"{APPARMOR_ANNOTATION_PREFIX}{container_name}"
    return categorize_legacy_apparmor_annotation((pod_annotations or {}).get(annotation_key))


def _volume_category_map(volumes: Any) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for v in volumes or []:
        name = getattr(v, "name", None)
        if not name:
            continue
        if getattr(v, "host_path", None) is not None:
            mapping[name] = "hostpath"
        elif getattr(v, "config_map", None) is not None:
            mapping[name] = "configmap"
        elif getattr(v, "secret", None) is not None:
            mapping[name] = "secret"
        elif getattr(v, "empty_dir", None) is not None:
            mapping[name] = "emptydir"
        elif getattr(v, "persistent_volume_claim", None) is not None:
            mapping[name] = "pvc"
        elif getattr(v, "projected", None) is not None:
            mapping[name] = "projected"
        else:
            mapping[name] = "other"
    return mapping


def _is_service_account_token_volume(v: Any) -> bool:
    name = getattr(v, "name", None) or ""
    if name.startswith("kube-api-access-"):
        return True
    projected = getattr(v, "projected", None)
    if projected is not None:
        for source in getattr(projected, "sources", None) or []:
            if getattr(source, "service_account_token", None) is not None:
                return True
    return False


def _hostpath_volume_summary(volumes: Any) -> tuple[int, list[str]]:
    """Returns ``(hostpath_volume_count, sorted dangerous categories)``. The
    raw path is read only to categorize it — never stored."""
    count = 0
    categories: set[str] = set()
    for v in volumes or []:
        host_path = getattr(v, "host_path", None)
        if host_path is None:
            continue
        count += 1
        category = categorize_hostpath(getattr(host_path, "path", None))
        if category in DANGEROUS_HOSTPATH_CATEGORIES:
            categories.add(category)
    return count, sorted(categories)


def _toleration_categories(tolerations: Any) -> list[str]:
    categories: set[str] = set()
    for t in tolerations or []:
        key = getattr(t, "key", None)
        operator = getattr(t, "operator", None)
        effect = getattr(t, "effect", None)
        if not key and operator == "Exists":
            categories.add("tolerates_all_taints")
        if key in _DANGEROUS_TOLERATION_KEYS:
            categories.add("control_plane_toleration")
        if effect == "NoExecute" and operator == "Exists" and not key:
            categories.add("tolerates_all_taints")
    return sorted(categories)


def _affinity_flags(affinity: Any) -> tuple[bool, bool]:
    if affinity is None:
        return False, False
    node_affinity = getattr(affinity, "node_affinity", None)
    pod_affinity = getattr(affinity, "pod_affinity", None)
    pod_anti_affinity = getattr(affinity, "pod_anti_affinity", None)
    return bool(node_affinity or pod_affinity), bool(pod_anti_affinity)


def _dangerous_host_ports(ports: list[int]) -> list[int]:
    return sorted({p for p in ports if p in SENSITIVE_HOST_PORTS})


def _is_explicit_root(container_record: dict) -> bool:
    if container_record["run_as_non_root"] is False:
        return True
    if container_record["run_as_uid"] == 0:
        return True
    return False


def _normalize_container(
    container: Any,
    *,
    category: str,
    pod_security_context: Any,
    pod_annotations: dict,
    volume_category_map: dict[str, str],
    sa_token_volume_names: set[str],
    cluster_id: str,
    cluster_name: str,
    namespace: str,
    parent_workload_type: str,
    parent_workload_uid: Optional[str],
    parent_record_id: str,
) -> dict:
    """Normalize one container (application/init/ephemeral) into a
    ``kubernetes_container_security_context`` record. Never reads or stores
    env values, command, args, probe payload contents, or arbitrary mount
    paths — see the module docstring's sensitive-data policy."""
    name = getattr(container, "name", "") or ""
    sc = getattr(container, "security_context", None)
    image = getattr(container, "image", "") or ""

    run_as_user = getattr(sc, "run_as_user", None) if sc else None
    run_as_group = getattr(sc, "run_as_group", None) if sc else None

    added, dropped, dangerous_added = _normalize_capabilities(sc)

    ports = getattr(container, "ports", None) or []
    host_ports = [
        getattr(p, "host_port", None) for p in ports if getattr(p, "host_port", None)
    ]

    resources = getattr(container, "resources", None)
    requests = (getattr(resources, "requests", None) or {}) if resources else {}
    limits = (getattr(resources, "limits", None) or {}) if resources else {}

    mounts = getattr(container, "volume_mounts", None) or []
    mount_categories: set[str] = set()
    hostpath_mount_count = 0
    writable_hostpath_mount_count = 0
    sa_token_mounted = False
    bidirectional_propagation = False
    for m in mounts:
        vol_name = getattr(m, "name", None)
        vol_category = volume_category_map.get(vol_name, "other")
        mount_categories.add(vol_category)
        if vol_category == "hostpath":
            hostpath_mount_count += 1
            if not getattr(m, "read_only", False):
                writable_hostpath_mount_count += 1
        if vol_name in sa_token_volume_names:
            sa_token_mounted = True
        if getattr(m, "mount_propagation", None) == "Bidirectional":
            bidirectional_propagation = True

    record_id = f"{parent_record_id}/container/{category}/{name}"

    return {
        "record_type": KUBERNETES_CONTAINER_SECURITY_CONTEXT,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "parent_workload_type": parent_workload_type,
        "parent_workload_uid": parent_workload_uid,
        "parent_record_id": parent_record_id,
        "container_name": name,
        "container_category": category,
        "image": image,
        "image_registry_category": categorize_image_registry(image),
        "image_tag_category": categorize_image_tag(image),
        "image_pull_policy": getattr(container, "image_pull_policy", None),
        "privileged": getattr(sc, "privileged", None) if sc else None,
        "allow_privilege_escalation": (
            getattr(sc, "allow_privilege_escalation", None) if sc else None
        ),
        "run_as_user_set": run_as_user is not None,
        "run_as_uid": run_as_user,
        "run_as_group_set": run_as_group is not None,
        "run_as_non_root": getattr(sc, "run_as_non_root", None) if sc else None,
        "read_only_root_filesystem": (
            getattr(sc, "read_only_root_filesystem", None) if sc else None
        ),
        "seccomp_profile_category": _effective_seccomp_category(sc, pod_security_context),
        "apparmor_profile_category": _apparmor_profile_category(sc, pod_annotations, name),
        "selinux_options_present": bool(getattr(sc, "se_linux_options", None)) if sc else False,
        "windows_security_context_present": bool(getattr(sc, "windows_options", None)) if sc else False,
        "capabilities_added": added,
        "capabilities_dropped": dropped,
        "dangerous_added_capability_categories": dangerous_added,
        "proc_mount_category": getattr(sc, "proc_mount", None) if sc else None,
        "host_port_count": len(host_ports),
        "dangerous_host_ports": _dangerous_host_ports(host_ports),
        "cpu_request_present": "cpu" in requests,
        "memory_request_present": "memory" in requests,
        "cpu_limit_present": "cpu" in limits,
        "memory_limit_present": "memory" in limits,
        "any_resource_request_present": bool(requests),
        "any_resource_limit_present": bool(limits),
        "liveness_probe_present": getattr(container, "liveness_probe", None) is not None,
        "readiness_probe_present": getattr(container, "readiness_probe", None) is not None,
        "startup_probe_present": getattr(container, "startup_probe", None) is not None,
        "volume_mount_categories": sorted(mount_categories),
        "hostpath_mount_count": hostpath_mount_count,
        "writable_hostpath_mount_count": writable_hostpath_mount_count,
        "service_account_token_explicitly_mounted": sa_token_mounted,
        "bidirectional_mount_propagation_present": bidirectional_propagation,
    }


_EMPTY_AGGREGATE: dict = {
    "privileged_container_count": 0,
    "root_container_count": 0,
    "allow_privilege_escalation_count": 0,
    "added_capability_categories": [],
    "seccomp_posture_summary": PROFILE_CATEGORY_OMITTED,
    "apparmor_posture_summary": PROFILE_CATEGORY_OMITTED,
    "read_only_root_filesystem_coverage": COVERAGE_NONE,
    "resource_limit_coverage": COVERAGE_NONE,
    "liveness_probe_coverage": COVERAGE_NONE,
    "readiness_probe_coverage": COVERAGE_NONE,
    "startup_probe_coverage": COVERAGE_NONE,
    "image_posture_summary": "unknown",
}


def _aggregate_workload_security(container_records: list[dict]) -> dict:
    if not container_records:
        return dict(_EMPTY_AGGREGATE)

    total = len(container_records)
    privileged_count = sum(1 for c in container_records if c["privileged"] is True)
    root_count = sum(1 for c in container_records if _is_explicit_root(c))
    allow_priv_esc_count = sum(
        1 for c in container_records if c["allow_privilege_escalation"] is True
    )
    added_categories: set[str] = set()
    for c in container_records:
        added_categories.update(c["dangerous_added_capability_categories"])
        if CAPABILITY_ALL in c["capabilities_added"]:
            added_categories.add(CAPABILITY_ALL)

    seccomp_summary = _summarize_categories({c["seccomp_profile_category"] for c in container_records})
    apparmor_summary = _summarize_categories({c["apparmor_profile_category"] for c in container_records})

    ro_count = sum(1 for c in container_records if c["read_only_root_filesystem"] is True)
    resource_limit_count = sum(1 for c in container_records if c["any_resource_limit_present"])
    liveness_count = sum(1 for c in container_records if c["liveness_probe_present"])
    readiness_count = sum(1 for c in container_records if c["readiness_probe_present"])
    startup_count = sum(1 for c in container_records if c["startup_probe_present"])

    image_tag_categories = {c["image_tag_category"] for c in container_records}
    if image_tag_categories == {IMAGE_TAG_PINNED_DIGEST}:
        image_summary = "pinned"
    elif image_tag_categories & {IMAGE_TAG_LATEST_EXPLICIT, IMAGE_TAG_LATEST_IMPLICIT}:
        image_summary = "mutable"
    elif image_tag_categories == {IMAGE_TAG_EXPLICIT}:
        image_summary = "explicit_tag"
    else:
        image_summary = "mixed"

    return {
        "privileged_container_count": privileged_count,
        "root_container_count": root_count,
        "allow_privilege_escalation_count": allow_priv_esc_count,
        "added_capability_categories": sorted(added_categories),
        "seccomp_posture_summary": seccomp_summary,
        "apparmor_posture_summary": apparmor_summary,
        "read_only_root_filesystem_coverage": _coverage(ro_count, total),
        "resource_limit_coverage": _coverage(resource_limit_count, total),
        "liveness_probe_coverage": _coverage(liveness_count, total),
        "readiness_probe_coverage": _coverage(readiness_count, total),
        "startup_probe_coverage": _coverage(startup_count, total),
        "image_posture_summary": image_summary,
    }


def _security_posture_summary(
    *,
    host_network: bool,
    host_pid: bool,
    host_ipc: bool,
    privileged_count: int,
    dangerous_hostpath_categories: list[str],
    root_count: int,
    allow_priv_esc_count: int,
    added_capability_categories: list[str],
) -> str:
    """Purely descriptive/structural summary — NOT a severity judgement.
    Severity classification is the risk classifier's job (see
    ``risk_rules/kubernetes.py``); message 7 owns full calibration."""
    if privileged_count > 0 or host_pid or dangerous_hostpath_categories:
        return SECURITY_POSTURE_PRIVILEGED_OR_HOST_ACCESS
    if host_network or host_ipc or root_count > 0 or allow_priv_esc_count > 0 or added_capability_categories:
        return SECURITY_POSTURE_ELEVATED
    return SECURITY_POSTURE_STANDARD


def _normalize_pod_template_common(
    pod_spec: Any,
    pod_metadata: Any,
    *,
    cluster_id: str,
    cluster_name: str,
    namespace: str,
    parent_workload_type: str,
    parent_workload_uid: Optional[str],
    parent_record_id: str,
) -> tuple[dict, list[dict]]:
    """Normalize the declarative posture shared by every workload family's
    Pod template (or a standalone Pod's own spec). Returns
    ``(common_fields, container_security_context_records)``.

    Malformed individual container objects are skipped (logged, not
    raised) so one bad container never aborts the whole workload family.
    """
    annotations = getattr(pod_metadata, "annotations", None) or {}
    pod_sc = getattr(pod_spec, "security_context", None)

    service_account_name = (
        getattr(pod_spec, "service_account_name", None)
        or getattr(pod_spec, "service_account", None)
        or "default"
    )
    host_network = bool(getattr(pod_spec, "host_network", False))
    host_pid = bool(getattr(pod_spec, "host_pid", False))
    host_ipc = bool(getattr(pod_spec, "host_ipc", False))

    volumes = getattr(pod_spec, "volumes", None) or []
    volume_map = _volume_category_map(volumes)
    sa_token_volume_names = {
        getattr(v, "name", None) for v in volumes if _is_service_account_token_volume(v)
    }
    hostpath_count, dangerous_hostpath_categories = _hostpath_volume_summary(volumes)

    containers = getattr(pod_spec, "containers", None) or []
    init_containers = getattr(pod_spec, "init_containers", None) or []
    ephemeral_containers = getattr(pod_spec, "ephemeral_containers", None) or []

    container_records: list[dict] = []
    for category, items in (
        (CONTAINER_CATEGORY_APPLICATION, containers),
        (CONTAINER_CATEGORY_INIT, init_containers),
        (CONTAINER_CATEGORY_EPHEMERAL, ephemeral_containers),
    ):
        for c in items:
            try:
                container_records.append(
                    _normalize_container(
                        c,
                        category=category,
                        pod_security_context=pod_sc,
                        pod_annotations=annotations,
                        volume_category_map=volume_map,
                        sa_token_volume_names=sa_token_volume_names,
                        cluster_id=cluster_id,
                        cluster_name=cluster_name,
                        namespace=namespace,
                        parent_workload_type=parent_workload_type,
                        parent_workload_uid=parent_workload_uid,
                        parent_record_id=parent_record_id,
                    )
                )
            except Exception:  # noqa: BLE001 — one malformed container must not abort the family
                logger.info(
                    "Skipping malformed container object on %s", parent_record_id
                )

    aggregate = _aggregate_workload_security(container_records)
    affinity_present, anti_affinity_present = _affinity_flags(getattr(pod_spec, "affinity", None))
    tolerations = getattr(pod_spec, "tolerations", None) or []

    security_posture_summary = _security_posture_summary(
        host_network=host_network,
        host_pid=host_pid,
        host_ipc=host_ipc,
        privileged_count=aggregate["privileged_container_count"],
        dangerous_hostpath_categories=dangerous_hostpath_categories,
        root_count=aggregate["root_container_count"],
        allow_priv_esc_count=aggregate["allow_privilege_escalation_count"],
        added_capability_categories=aggregate["added_capability_categories"],
    )

    common = {
        "service_account_name": service_account_name,
        "automount_service_account_token": getattr(
            pod_spec, "automount_service_account_token", None
        ),
        "host_network": host_network,
        "host_pid": host_pid,
        "host_ipc": host_ipc,
        "share_process_namespace": getattr(pod_spec, "share_process_namespace", None),
        "dns_policy_category": getattr(pod_spec, "dns_policy", None),
        "restart_policy": getattr(pod_spec, "restart_policy", None),
        "runtime_class_name": getattr(pod_spec, "runtime_class_name", None),
        "node_selector_key_count": len(getattr(pod_spec, "node_selector", None) or {}),
        "toleration_count": len(tolerations),
        "dangerous_toleration_categories": _toleration_categories(tolerations),
        "affinity_present": affinity_present,
        "anti_affinity_present": anti_affinity_present,
        "topology_spread_constraint_count": len(
            getattr(pod_spec, "topology_spread_constraints", None) or []
        ),
        "image_pull_secret_count": len(getattr(pod_spec, "image_pull_secrets", None) or []),
        "container_count": len(containers),
        "init_container_count": len(init_containers),
        "ephemeral_container_count": len(ephemeral_containers),
        "hostpath_volume_count": hostpath_count,
        "dangerous_hostpath_categories": dangerous_hostpath_categories,
        "security_posture_summary": security_posture_summary,
        **aggregate,
    }
    return common, container_records


def _normalize_workload_controller(
    obj: Any, *, kind: str, record_type: str, cluster_id: str, cluster_name: str
) -> tuple[dict, list[dict]]:
    """Normalize one Deployment/StatefulSet/DaemonSet/Job/CronJob object."""
    metadata = obj.metadata
    namespace = metadata.namespace
    name = metadata.name
    uid = getattr(metadata, "uid", None)
    spec = getattr(obj, "spec", None)

    if kind in ("Deployment", "StatefulSet", "DaemonSet"):
        replicas = getattr(spec, "replicas", None)
        strategy_attr = "strategy" if kind == "Deployment" else "update_strategy"
        strategy = getattr(spec, strategy_attr, None)
        update_strategy_category = getattr(strategy, "type", None) if strategy else None
        pod_template = getattr(spec, "template", None)
    elif kind == "Job":
        replicas = getattr(spec, "parallelism", None)
        update_strategy_category = None
        pod_template = getattr(spec, "template", None)
    elif kind == "CronJob":
        replicas = None
        update_strategy_category = getattr(spec, "concurrency_policy", None)
        job_template = getattr(spec, "job_template", None)
        job_spec = getattr(job_template, "spec", None) if job_template else None
        pod_template = getattr(job_spec, "template", None) if job_spec else None
    else:  # pragma: no cover — guarded by the fixed caller set
        raise ValueError(f"Unsupported workload kind: {kind}")

    pod_spec = getattr(pod_template, "spec", None) if pod_template else None
    pod_metadata = getattr(pod_template, "metadata", None) if pod_template else None

    record_id = f"{cluster_id}/{kind.lower()}/{namespace}/{uid or name}"

    common, container_records = _normalize_pod_template_common(
        pod_spec,
        pod_metadata,
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        namespace=namespace,
        parent_workload_type=kind.lower(),
        parent_workload_uid=uid,
        parent_record_id=record_id,
    )
    common.pop("share_process_namespace", None)  # Pod-only field

    record = {
        "record_type": record_type,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "name": name,
        "uid": uid,
        "api_version": _API_VERSION_BY_KIND[kind],
        "kind": kind,
        "desired_replica_count": replicas,
        "update_strategy_category": update_strategy_category,
        "collection_completeness_category": "complete",
        **common,
    }
    return record, container_records


def _normalize_standalone_pod(pod: Any, *, cluster_id: str, cluster_name: str) -> tuple[dict, list[dict]]:
    """Normalize one standalone Pod (no ownerReferences). See module
    docstring for why controller-owned Pods are not emitted this way."""
    metadata = pod.metadata
    namespace = metadata.namespace
    name = metadata.name
    uid = getattr(metadata, "uid", None)
    spec = getattr(pod, "spec", None)
    status = getattr(pod, "status", None)
    annotations = getattr(metadata, "annotations", None) or {}

    record_id = f"{cluster_id}/pod/{namespace}/{uid or name}"

    common, container_records = _normalize_pod_template_common(
        spec,
        metadata,
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        namespace=namespace,
        parent_workload_type="pod",
        parent_workload_uid=uid,
        parent_record_id=record_id,
    )

    # Only this one well-known, fixed annotation key is ever inspected —
    # the mirror-Pod convention is a stable Kubernetes API contract, not
    # arbitrary user-defined annotation content.
    mirror_pod = bool(annotations.get("kubernetes.io/config.mirror"))

    phase = getattr(status, "phase", None) if status else None
    phase_category = (phase or "unknown").lower()

    scheduled: Optional[bool] = None
    ready: Optional[bool] = None
    for cond in (getattr(status, "conditions", None) or []) if status else []:
        ctype = getattr(cond, "type", None)
        cstatus = getattr(cond, "status", None)
        if ctype == "PodScheduled":
            scheduled = cstatus == "True"
        elif ctype == "Ready":
            ready = cstatus == "True"

    host_ip = getattr(status, "host_ip", None) if status else None
    pod_ips = (getattr(status, "pod_ips", None) or []) if status else []

    container_statuses = (
        (getattr(status, "container_statuses", None) or [])
        + (getattr(status, "init_container_statuses", None) or [])
    ) if status else []
    restart_count_aggregate = sum(getattr(cs, "restart_count", 0) or 0 for cs in container_statuses)

    waiting_reason_category: Optional[str] = None
    terminated_reason_category: Optional[str] = None
    for cs in container_statuses:
        state = getattr(cs, "state", None)
        if state is None:
            continue
        waiting = getattr(state, "waiting", None)
        if waiting is not None and waiting_reason_category is None:
            waiting_reason_category = _categorize_container_state_reason(getattr(waiting, "reason", None))
        terminated = getattr(state, "terminated", None)
        if terminated is not None and terminated_reason_category is None:
            terminated_reason_category = _categorize_container_state_reason(getattr(terminated, "reason", None))

    record = {
        "record_type": KUBERNETES_POD,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "name": name,
        "uid": uid,
        "api_version": "v1",
        "kind": "Pod",
        "mirror_pod": mirror_pod,
        "collection_completeness_category": "complete",
        **common,
        "phase_category": phase_category,
        "scheduled": scheduled,
        "ready": ready,
        "host_ip_present": bool(host_ip),
        "pod_ip_count": len(pod_ips),
        "restart_count_aggregate": restart_count_aggregate,
        "container_waiting_reason_category": waiting_reason_category,
        "container_terminated_reason_category": terminated_reason_category,
    }
    return record, container_records


def _family_completeness_status(diag: "PageDiagnostics") -> str:
    if diag.complete:
        return "complete"
    if diag.error_category in (CATEGORY_NOT_FOUND, CATEGORY_API_UNAVAILABLE):
        return "unsupported"
    return "partial"


def _collect_workload_family(
    list_fn: Callable[..., Any],
    *,
    kind: str,
    record_type: str,
    cluster_id: str,
    cluster_name: str,
    namespace_allowlist: Optional[list[str]],
) -> tuple[list[dict], list[dict], str]:
    """Fail-soft collection of one workload-controller family (Deployments,
    StatefulSets, DaemonSets, Jobs, or CronJobs). A permission failure or
    absent API on this family never raises and never affects any other
    family. Returns ``(controller_records, container_records,
    completeness_status)``."""
    raw_items, diag = paginate_list(list_fn)
    controller_records: list[dict] = []
    container_records: list[dict] = []

    for item in raw_items:
        try:
            ns = item.metadata.namespace
        except Exception:  # noqa: BLE001 — malformed object must not abort the family
            logger.info("Skipping malformed %s object (no readable namespace)", kind)
            continue
        if namespace_allowlist is not None and ns not in namespace_allowlist:
            continue
        try:
            record, containers = _normalize_workload_controller(
                item, kind=kind, record_type=record_type,
                cluster_id=cluster_id, cluster_name=cluster_name,
            )
        except Exception:  # noqa: BLE001 — malformed object must not abort the family
            logger.info("Skipping malformed %s object", kind)
            continue
        controller_records.append(record)
        container_records.extend(containers)

    status = _family_completeness_status(diag)
    for record in controller_records:
        record["collection_completeness_category"] = status

    controller_records.sort(key=lambda r: (r["namespace"], r["name"]))
    container_records.sort(key=lambda r: r["record_id"])
    return controller_records, container_records, status


def _collect_standalone_pods(
    list_fn: Callable[..., Any],
    *,
    cluster_id: str,
    cluster_name: str,
    namespace_allowlist: Optional[list[str]],
) -> tuple[list[dict], list[dict], str]:
    """Fail-soft collection of standalone Pods only — controller-owned Pods
    are filtered out here (represented via their controller's template
    instead; see module docstring)."""
    raw_items, diag = paginate_list(list_fn)
    pod_records: list[dict] = []
    container_records: list[dict] = []

    for pod in raw_items:
        try:
            ns = pod.metadata.namespace
            owners = getattr(pod.metadata, "owner_references", None) or []
        except Exception:  # noqa: BLE001 — malformed object must not abort the family
            logger.info("Skipping malformed Pod object (no readable metadata)")
            continue
        if owners:
            continue
        if namespace_allowlist is not None and ns not in namespace_allowlist:
            continue
        try:
            record, containers = _normalize_standalone_pod(
                pod, cluster_id=cluster_id, cluster_name=cluster_name
            )
        except Exception:  # noqa: BLE001 — malformed object must not abort the family
            logger.info("Skipping malformed Pod object")
            continue
        pod_records.append(record)
        container_records.extend(containers)

    status = _family_completeness_status(diag)
    for record in pod_records:
        record["collection_completeness_category"] = status

    pod_records.sort(key=lambda r: (r["namespace"], r["name"]))
    container_records.sort(key=lambda r: r["record_id"])
    return pod_records, container_records, status


def _aggregate_workload_service_accounts(
    workload_records: list[dict], *, cluster_id: str, cluster_name: str
) -> list[dict]:
    """One rollup record per (namespace, service_account_name) pair actually
    referenced by a collected workload this sync. Full RBAC/ServiceAccount
    collection (and the SA's own default automount value) is message 3."""
    buckets: dict[tuple[str, str], dict[str, int]] = {}
    for r in workload_records:
        key = (r["namespace"], r["service_account_name"])
        bucket = buckets.setdefault(
            key, {"referencing_workload_count": 0, "true": 0, "false": 0, "inherited": 0}
        )
        bucket["referencing_workload_count"] += 1
        automount = r.get("automount_service_account_token")
        if automount is True:
            bucket["true"] += 1
        elif automount is False:
            bucket["false"] += 1
        else:
            bucket["inherited"] += 1

    records: list[dict] = []
    for (namespace, sa_name), counts in sorted(buckets.items()):
        records.append(
            {
                "record_type": KUBERNETES_WORKLOAD_SERVICE_ACCOUNT,
                "record_id": f"{cluster_id}/workload_service_account/{namespace}/{sa_name}",
                "cluster_id": cluster_id,
                "cluster_name": cluster_name,
                "namespace": namespace,
                "service_account_name": sa_name,
                "referencing_workload_count": counts["referencing_workload_count"],
                "automount_explicit_true_count": counts["true"],
                "automount_explicit_false_count": counts["false"],
                "automount_inherited_count": counts["inherited"],
            }
        )
    return records


# ── Connector ──────────────────────────────────────────────────────────────────

class KubernetesConnector(BaseConnector):
    """Fetches cluster identity, namespace posture, and API capability
    records from a single Kubernetes cluster.

    Credentials shape::

        {
            "kubeconfig": "<kubeconfig YAML content>",
            "context": "<optional context name; defaults to current-context>",
            "namespace_allowlist": ["ns-a", "ns-b"],  # optional
            "cluster_name": "<optional user-supplied display name>",
        }

    SECURITY: ``credentials["kubeconfig"]`` (and any bearer token, client
    key, or client certificate it embeds) is NEVER logged, NEVER returned,
    and NEVER copied into a normalized record. It is parsed in memory only
    to build a short-lived API client for the duration of one ``fetch()``
    or ``validate_credentials()`` call.
    """

    def _build_api_client(self, credentials: dict) -> tuple[Any, dict, str]:
        """Parse kubeconfig, reject unsafe auth mechanisms, and return
        ``(api_client, config_dict, resolved_context_name)``.

        Raises ``ConnectorError``/``AuthenticationError`` for malformed
        input or unsafe/missing context — never silently proceeds.
        """
        from kubernetes import client as k8s_client
        from kubernetes import config as k8s_config

        raw_kubeconfig = credentials.get("kubeconfig")
        if not raw_kubeconfig or not isinstance(raw_kubeconfig, str):
            raise ConnectorError("kubeconfig content is required and must be a string.")

        try:
            config_dict = yaml.safe_load(raw_kubeconfig)
        except yaml.YAMLError as exc:
            raise ConnectorError(f"kubeconfig could not be parsed as YAML: {exc.__class__.__name__}") from exc

        if not isinstance(config_dict, dict):
            raise ConnectorError("kubeconfig content is not a valid kubeconfig document.")

        context_name = credentials.get("context")
        resolved_context = assert_context_auth_is_supported(config_dict, context_name)

        configuration = k8s_client.Configuration()
        try:
            k8s_config.load_kube_config_from_dict(
                config_dict,
                context=resolved_context,
                client_configuration=configuration,
                persist_config=False,
            )
        except k8s_config.config_exception.ConfigException as exc:
            raise ConnectorError(f"kubeconfig context could not be loaded: {exc.__class__.__name__}") from exc

        api_client = k8s_client.ApiClient(configuration)
        return api_client, config_dict, resolved_context

    # ── Discovery ──────────────────────────────────────────────────────────

    def _discover_capabilities(
        self, api_client: Any, *, cluster_id: str, cluster_name: str
    ) -> tuple[list[dict], str]:
        """Probe a curated set of API groups and return one
        ``kubernetes_api_capability`` record per discovered resource.

        Never assumes a group is present — each is a real, individually
        fail-soft API call. Returns ``(records, discovery_status)`` where
        ``discovery_status`` is ``"complete"`` (every probed group
        answered, whether available or not), or ``"partial"`` (at least
        one probe hit an unexpected error rather than a clean
        available/unavailable answer).
        """
        from kubernetes import client as k8s_client

        records: list[dict] = []
        any_unexpected_error = False

        for group, version, typed_attr in _DISCOVERY_GROUPS:
            group_label = group or "core"
            if typed_attr is not None:
                api_cls = getattr(k8s_client, typed_attr)
                outcome = call_k8s(api_cls(api_client).get_api_resources)
            else:
                # No generated client for this group (CRD-based, e.g. the
                # Gateway API) — probe via a raw discovery call instead.
                path = f"/apis/{group}/{version}"
                outcome = call_k8s(
                    api_client.call_api,
                    path, "GET",
                    response_type="object",
                    auth_settings=["BearerToken"],
                    _preload_content=True,
                    _return_http_data_only=True,
                )

            if not outcome.ok:
                available = False
                if outcome.category not in (CATEGORY_NOT_FOUND, CATEGORY_API_UNAVAILABLE):
                    any_unexpected_error = True
                    logger.info(
                        "Kubernetes discovery: unexpected error probing %s/%s: %s",
                        group_label, version, outcome.category,
                    )
                # Still emit one record so callers can see the group was
                # probed and is (for now) unavailable — not silently omitted.
                records.append({
                    "record_type": KUBERNETES_API_CAPABILITY,
                    "record_id": f"{cluster_id}/api_capability/{group_label}/{version}/*",
                    "cluster_id": cluster_id,
                    "cluster_name": cluster_name,
                    "api_group": group_label,
                    "api_version": version,
                    "resource": "*",
                    "namespaced": False,
                    "verbs": [],
                    "available": False,
                    "preferred_version": False,
                    "collection_support_status": "not_supported",
                })
                continue

            resources = self._extract_resources(outcome.result, typed_attr is None)
            for res in resources:
                name = res["name"]
                records.append({
                    "record_type": KUBERNETES_API_CAPABILITY,
                    "record_id": f"{cluster_id}/api_capability/{group_label}/{version}/{name}",
                    "cluster_id": cluster_id,
                    "cluster_name": cluster_name,
                    "api_group": group_label,
                    "api_version": version,
                    "resource": name,
                    "namespaced": bool(res["namespaced"]),
                    "verbs": sorted(res["verbs"] or []),
                    "available": True,
                    "preferred_version": True,
                    "collection_support_status": (
                        "planned" if name in _PLANNED_RESOURCE_NAMES else "not_supported"
                    ),
                })

        return records, ("partial" if any_unexpected_error else "complete")

    @staticmethod
    def _extract_resources(payload: Any, is_raw_dict: bool) -> list[dict]:
        """Normalize a discovery response (typed ``V1APIResourceList`` or a
        raw dict from ``call_api``) into a list of ``{name, namespaced,
        verbs}`` dicts. Never persists the full discovery document."""
        if is_raw_dict:
            if not isinstance(payload, dict):
                return []
            raw_resources = payload.get("resources") or []
            return [
                {
                    "name": r.get("name"),
                    "namespaced": r.get("namespaced", False),
                    "verbs": r.get("verbs") or [],
                }
                for r in raw_resources
                if isinstance(r, dict) and r.get("name") and "/" not in r.get("name", "")
            ]
        items = getattr(payload, "resources", None) or []
        return [
            {"name": r.name, "namespaced": r.namespaced, "verbs": r.verbs}
            for r in items
            if getattr(r, "name", None) and "/" not in r.name
        ]

    # ── Public interface ─────────────────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Confirm the kubeconfig parses, the context exists, its auth
        mechanism is supported, and the API server is reachable via
        ``/version``. Does not require cluster-admin — a successful
        ``/version`` call is the minimum bar for "credentials are valid".
        """
        api_client, _config_dict, _context = self._build_api_client(credentials)
        from kubernetes import client as k8s_client

        try:
            outcome = call_k8s(k8s_client.VersionApi(api_client).get_code)
            if not outcome.ok:
                if outcome.category == CATEGORY_AUTH_FAILED:
                    raise AuthenticationError("Kubernetes API server rejected the supplied credentials.")
                if outcome.category == CATEGORY_THROTTLED:
                    raise RateLimitError("Kubernetes API server throttled the validation request.")
                if outcome.category == CATEGORY_CONNECTION_ERROR:
                    raise NetworkError("Could not reach the Kubernetes API server.")
                if outcome.category == CATEGORY_TLS_ERROR:
                    raise NetworkError("TLS certificate verification failed connecting to the API server.")
                raise ConnectorError(f"Kubernetes API server validation failed: {outcome.category}")
            return True
        finally:
            api_client.rest_client.pool_manager.clear()

    def fetch(self, credentials: dict) -> list[dict]:
        from kubernetes import client as k8s_client

        api_client, config_dict, resolved_context = self._build_api_client(credentials)
        try:
            configuration: Any = api_client.configuration
            tls_verify_enabled = bool(configuration.verify_ssl)
            display_cluster_name = (
                credentials.get("cluster_name") or resolved_context or "kubernetes-cluster"
            )
            host_category = categorize_api_server_host(configuration.host or "")

            core_v1 = k8s_client.CoreV1Api(api_client)

            # ── kube-system UID -> cluster identity ─────────────────────────
            kube_system_outcome = call_k8s(core_v1.read_namespace, "kube-system")
            kube_system_uid = None
            partial_permission = False
            if kube_system_outcome.ok:
                kube_system_uid = getattr(kube_system_outcome.result.metadata, "uid", None)
            else:
                partial_permission = True

            cluster_id = compute_cluster_id(
                api_server_host=configuration.host or "",
                kube_system_uid=kube_system_uid,
            )

            # ── Version ─────────────────────────────────────────────────────
            version_outcome = call_k8s(k8s_client.VersionApi(api_client).get_code)
            kubernetes_version = None
            if version_outcome.ok:
                kubernetes_version = normalize_kubernetes_version(version_outcome.result.git_version)
            else:
                partial_permission = partial_permission or version_outcome.category == CATEGORY_PERMISSION_DENIED

            # ── Namespaces ──────────────────────────────────────────────────
            raw_namespaces, ns_diag = paginate_list(core_v1.list_namespace)
            namespace_records = [
                _normalize_namespace(ns, cluster_id=cluster_id, cluster_name=display_cluster_name)
                for ns in raw_namespaces
            ]
            allowlist = credentials.get("namespace_allowlist")
            selected_namespace_records = _apply_namespace_allowlist(namespace_records, allowlist)
            # Deterministic ordering — never rely on API-returned order.
            selected_namespace_records.sort(key=lambda r: r["name"])

            if ns_diag.permission_denied or not ns_diag.complete:
                partial_permission = True

            cluster_scoped_access_available = ns_diag.pages_fetched > 0 or (
                ns_diag.complete and not ns_diag.permission_denied
            )

            # ── API discovery ───────────────────────────────────────────────
            capability_records, discovery_status = self._discover_capabilities(
                api_client, cluster_id=cluster_id, cluster_name=display_cluster_name
            )
            if discovery_status != "complete":
                partial_permission = True

            # ── Workloads (message 2) ────────────────────────────────────────
            # Each family is collected and normalized independently — a
            # permission failure or absent API on ONE family never affects
            # any other family's records, and never raises.
            apps_v1 = k8s_client.AppsV1Api(api_client)
            batch_v1 = k8s_client.BatchV1Api(api_client)

            deployment_records, deployment_containers, deployment_status = _collect_workload_family(
                apps_v1.list_deployment_for_all_namespaces,
                kind="Deployment", record_type=KUBERNETES_DEPLOYMENT,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )
            statefulset_records, statefulset_containers, statefulset_status = _collect_workload_family(
                apps_v1.list_stateful_set_for_all_namespaces,
                kind="StatefulSet", record_type=KUBERNETES_STATEFULSET,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )
            daemonset_records, daemonset_containers, daemonset_status = _collect_workload_family(
                apps_v1.list_daemon_set_for_all_namespaces,
                kind="DaemonSet", record_type=KUBERNETES_DAEMONSET,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )
            job_records, job_containers, job_status = _collect_workload_family(
                batch_v1.list_job_for_all_namespaces,
                kind="Job", record_type=KUBERNETES_JOB,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )
            cronjob_records, cronjob_containers, cronjob_status = _collect_workload_family(
                batch_v1.list_cron_job_for_all_namespaces,
                kind="CronJob", record_type=KUBERNETES_CRONJOB,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )
            pod_records, pod_containers, pod_status = _collect_standalone_pods(
                core_v1.list_pod_for_all_namespaces,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )

            # "unsupported" (API group genuinely absent) is not a permission
            # problem — only a real partial/error status marks the overall
            # cluster collection as partial.
            if "partial" in (
                deployment_status, statefulset_status, daemonset_status,
                job_status, cronjob_status, pod_status,
            ):
                partial_permission = True

            all_workload_records = (
                deployment_records + statefulset_records + daemonset_records
                + job_records + cronjob_records + pod_records
            )
            all_container_records = (
                deployment_containers + statefulset_containers + daemonset_containers
                + job_containers + cronjob_containers + pod_containers
            )
            service_account_records = _aggregate_workload_service_accounts(
                all_workload_records, cluster_id=cluster_id, cluster_name=display_cluster_name
            )

            collection_completeness = "complete" if not partial_permission else "partial"

            cluster_record = {
                "record_type": KUBERNETES_CLUSTER,
                "record_id": cluster_id,
                "cluster_id": cluster_id,
                "cluster_name": display_cluster_name,
                "context_name": resolved_context,
                "api_server_host_category": host_category,
                "kubernetes_version": kubernetes_version,
                "kubernetes_major_minor": major_minor(kubernetes_version),
                # Distribution categorization from safe server metadata is
                # intentionally deferred (see kubernetes_foundation_contract.md)
                # to avoid brittle guessing across EKS/GKE/AKS/self-managed.
                "platform": "unknown",
                "authentication_mode_category": "kubeconfig",
                "cluster_scoped_access_available": cluster_scoped_access_available,
                "namespace_count": len(namespace_records) if ns_diag.complete else None,
                "visible_namespace_count": len(namespace_records),
                "selected_namespace_count": len(selected_namespace_records),
                "api_discovery_status": discovery_status,
                "collection_completeness_category": collection_completeness,
                "partial_permission_indicator": partial_permission,
                "server_certificate_verification_enabled": tls_verify_enabled,
            }

            return (
                [cluster_record] + selected_namespace_records + capability_records
                + all_workload_records + all_container_records + service_account_records
            )
        finally:
            api_client.rest_client.pool_manager.clear()
