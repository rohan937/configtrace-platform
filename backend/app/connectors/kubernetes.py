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
from app.connectors import kubernetes_schema as ks
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
    API_GROUP_WILDCARD,
    AUTOMOUNT_SOURCE_KUBERNETES_DEFAULT,
    AUTOMOUNT_SOURCE_SERVICE_ACCOUNT_EXPLICIT,
    AUTOMOUNT_SOURCE_UNKNOWN,
    AUTOMOUNT_SOURCE_WORKLOAD_EXPLICIT,
    AUTOMOUNT_STATE_EXPLICIT_WORKLOAD_FALSE,
    AUTOMOUNT_STATE_EXPLICIT_WORKLOAD_TRUE,
    AUTOMOUNT_STATE_INHERITED_SERVICE_ACCOUNT_FALSE,
    AUTOMOUNT_STATE_INHERITED_SERVICE_ACCOUNT_TRUE,
    AUTOMOUNT_STATE_KUBERNETES_DEFAULT_TRUE,
    AUTOMOUNT_STATE_UNKNOWN_PERMISSION_DENIED,
    AUTOMOUNT_STATE_UNKNOWN_SERVICE_ACCOUNT_MISSING,
    BUILTIN_ROLE_CLUSTER_ADMIN,
    CATEGORY_CLUSTER_ROLE_BINDING_WRITE,
    CATEGORY_IMPERSONATE,
    CATEGORY_POD_EXEC,
    CATEGORY_POD_WRITE,
    CATEGORY_ROLE_OR_CLUSTER_ROLE_WRITE,
    CATEGORY_SECRET_READ,
    CATEGORY_SECRET_READ_BROAD_SCOPE,
    CATEGORY_SECRET_WRITE,
    CATEGORY_WORKLOAD_WRITE,
    GROUP_SYSTEM_AUTHENTICATED,
    GROUP_SYSTEM_MASTERS,
    GROUP_SYSTEM_NODES,
    GROUP_SYSTEM_SERVICEACCOUNTS_PREFIX,
    GROUP_SYSTEM_UNAUTHENTICATED,
    KUBERNETES_CLUSTER_ROLE,
    KUBERNETES_RBAC_PERMISSION_SUMMARY,
    KUBERNETES_RBAC_SUBJECT_BINDING,
    KUBERNETES_ROLE,
    KUBERNETES_ROLE_BINDING,
    KUBERNETES_CLUSTER_ROLE_BINDING,
    KUBERNETES_SERVICE_ACCOUNT,
    READ_VERBS,
    RESOURCE_CATEGORY_CLUSTER_ROLE_BINDINGS,
    RESOURCE_CATEGORY_CLUSTER_ROLES,
    RESOURCE_CATEGORY_CONFIGMAPS,
    RESOURCE_CATEGORY_CRDS,
    RESOURCE_CATEGORY_CSR_APPROVAL,
    RESOURCE_CATEGORY_INGRESSES,
    RESOURCE_CATEGORY_MUTATING_WEBHOOKS,
    RESOURCE_CATEGORY_NAMESPACES,
    RESOURCE_CATEGORY_NETWORK_POLICIES,
    RESOURCE_CATEGORY_NODES,
    RESOURCE_CATEGORY_NODES_PROXY,
    RESOURCE_CATEGORY_PERSISTENT_VOLUMES,
    RESOURCE_CATEGORY_PODS,
    RESOURCE_CATEGORY_PODS_ATTACH,
    RESOURCE_CATEGORY_PODS_EXEC,
    RESOURCE_CATEGORY_PODS_LOG,
    RESOURCE_CATEGORY_PODS_PORTFORWARD,
    RESOURCE_CATEGORY_ROLE_BINDINGS,
    RESOURCE_CATEGORY_ROLES,
    RESOURCE_CATEGORY_SECRETS,
    RESOURCE_CATEGORY_SERVICE_ACCOUNTS_TOKEN,
    RESOURCE_CATEGORY_SERVICES,
    RESOURCE_CATEGORY_SUBJECT_ACCESS_REVIEWS,
    RESOURCE_CATEGORY_VALIDATING_WEBHOOKS,
    RESOURCE_CATEGORY_WILDCARD,
    RESOURCE_CATEGORY_WORKLOADS,
    ROLE_RESOLUTION_ACCESS_DENIED,
    ROLE_RESOLUTION_MALFORMED,
    ROLE_RESOLUTION_MISSING,
    ROLE_RESOLUTION_RESOLVED,
    SAFE_ROLE_LABEL_KEYS,
    SEVERITY_CRITICAL,
    SEVERITY_LOW,
    SEVERITY_UNKNOWN,
    SUBJECT_KIND_GROUP,
    SUBJECT_KIND_SERVICE_ACCOUNT,
    SUBJECT_KIND_USER,
    USER_SYSTEM_ANONYMOUS,
    VERB_APPROVE,
    VERB_BIND,
    VERB_ESCALATE,
    VERB_IMPERSONATE,
    VERB_WILDCARD,
    WRITE_VERBS,
    canonical_service_account_identity,
    categorize_api_group,
    categorize_builtin_role,
    categorize_group,
    categorize_non_resource_url,
    categorize_resource,
    highest_severity,
    KUBERNETES_GATEWAY,
    KUBERNETES_GATEWAY_LISTENER,
    KUBERNETES_HTTP_ROUTE,
    KUBERNETES_HTTP_ROUTE_RULE,
    KUBERNETES_INGRESS,
    KUBERNETES_INGRESS_RULE,
    KUBERNETES_NAMESPACE_NETWORK_POSTURE,
    KUBERNETES_NETWORK_POLICY,
    KUBERNETES_SERVICE,
    KUBERNETES_SERVICE_PORT,
    SAFE_INTERNAL_LOAD_BALANCER_ANNOTATION_KEYS,
    SENSITIVE_SERVICE_PORTS,
    categorize_cidr,
    categorize_host,
    categorize_ingress_path,
    categorize_ip_address,
    is_catch_all_path,
    is_public_cidr_category,
    rule_permits_everything,
    stable_fingerprint,
    KUBERNETES_LIMIT_RANGE,
    KUBERNETES_MUTATING_WEBHOOK,
    KUBERNETES_MUTATING_WEBHOOK_CONFIGURATION,
    KUBERNETES_NAMESPACE_GOVERNANCE_POSTURE,
    KUBERNETES_POD_SECURITY_ADMISSION,
    KUBERNETES_RESOURCE_QUOTA,
    KUBERNETES_VALIDATING_WEBHOOK,
    KUBERNETES_VALIDATING_WEBHOOK_CONFIGURATION,
    categorize_admission_scope,
    categorize_failure_policy,
    categorize_match_policy,
    categorize_reinvocation_policy,
    categorize_selector_presence,
    categorize_side_effects,
    parse_cpu_quantity_millicores,
    parse_memory_quantity_bytes,
)

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT_SECONDS = 30
# Differentiated (connect, read) timeout, per the official client's own
# support for a 2-tuple `_request_timeout` (urllib3.Timeout(connect=,
# read=)) — a slow-to-respond API server should not be treated the same as
# an entirely unreachable one, and neither should ever hang a sync
# indefinitely. Every API call in this connector goes through `call_k8s()`,
# which sets this bounded default unless a caller overrides it.
_CONNECT_TIMEOUT_SECONDS = 10
_READ_TIMEOUT_SECONDS = 30
_REQUEST_TIMEOUT = (_CONNECT_TIMEOUT_SECONDS, _READ_TIMEOUT_SECONDS)
_DEFAULT_PAGE_SIZE = 100
_MAX_PAGES = 50  # defensive cap — prevents unbounded continuation loops

# Bounded 429 (throttled) retry policy (message 8). Applies ONLY to
# CATEGORY_THROTTLED — 401/403 are never retried as if transient, since
# retrying an auth/permission failure wastes budget and cannot succeed.
_MAX_THROTTLE_RETRIES = 3
_THROTTLE_BASE_DELAY_SECONDS = 0.5
_THROTTLE_MAX_DELAY_SECONDS = 8.0

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
CATEGORY_TIMEOUT = "timeout"


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
    import socket
    import ssl

    from urllib3.exceptions import (
        ConnectTimeoutError,
        MaxRetryError,
        ReadTimeoutError,
        SSLError as Urllib3SSLError,
    )

    # Checked before MaxRetryError: urllib3 sometimes raises the timeout
    # error directly, sometimes wraps it as MaxRetryError.reason — both
    # must classify as a bounded timeout, never a generic connection error,
    # so callers/tests can tell "server unreachable" apart from "server
    # took too long to respond" (connect vs read timeout).
    if isinstance(exc, (ReadTimeoutError, ConnectTimeoutError, socket.timeout, TimeoutError)):
        return CATEGORY_TIMEOUT, "The request to the Kubernetes API server timed out."
    if isinstance(exc, (Urllib3SSLError, ssl.SSLError)):
        return CATEGORY_TLS_ERROR, "TLS certificate verification failed."
    if isinstance(exc, MaxRetryError):
        cause = str(exc.reason).lower() if exc.reason else ""
        if "certificate" in cause or "ssl" in cause:
            return CATEGORY_TLS_ERROR, "TLS certificate verification failed."
        if "timed out" in cause or "timeout" in cause:
            return CATEGORY_TIMEOUT, "The request to the Kubernetes API server timed out."
        return CATEGORY_CONNECTION_ERROR, "Could not connect to the Kubernetes API server."
    if isinstance(exc, (ConnectionError, OSError)):
        return CATEGORY_CONNECTION_ERROR, "Could not connect to the Kubernetes API server."

    return CATEGORY_MALFORMED_RESPONSE, "The API server returned a response that could not be parsed."


def _retry_after_seconds(exc: Exception) -> Optional[float]:
    """Extract a ``Retry-After`` header value (seconds) from an ApiException,
    if present and parseable. Never guesses — returns ``None`` on anything
    that isn't a plain non-negative number of seconds."""
    headers = getattr(exc, "headers", None)
    if not headers:
        return None
    try:
        raw = headers.get("Retry-After") if hasattr(headers, "get") else None
    except Exception:  # noqa: BLE001 — malformed header container
        return None
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _throttle_backoff_seconds(attempt: int, *, retry_after: Optional[float]) -> float:
    """Bounded exponential backoff with jitter for a 429 retry attempt
    (0-indexed). Honors ``Retry-After`` when the server provided one and it
    is within the configured maximum; otherwise falls back to
    ``base * 2**attempt`` capped at the maximum, plus deterministic-bounded
    jitter (never unboundedly long, never negative)."""
    import random

    if retry_after is not None:
        return min(retry_after, _THROTTLE_MAX_DELAY_SECONDS)
    base = min(_THROTTLE_BASE_DELAY_SECONDS * (2 ** attempt), _THROTTLE_MAX_DELAY_SECONDS)
    jitter = random.uniform(0, base * 0.25)
    return min(base + jitter, _THROTTLE_MAX_DELAY_SECONDS)


def call_k8s(
    fn: Callable[..., Any], *args: Any,
    _sleep_fn: Callable[[float], None] = None, **kwargs: Any,
) -> CallOutcome:
    """Fail-soft wrapper around any single (non-paginated) Kubernetes API call.

    Every list/get call made by this connector — now and in future
    messages — should route through this wrapper (or ``paginate_list``,
    which uses it internally) rather than calling the generated client
    directly, so every caller gets the same distinguishable failure
    categories instead of an uncaught exception.

    Throttled (429) responses get a bounded retry with exponential backoff
    and jitter (honoring ``Retry-After`` when the server provides one) —
    never an unbounded wait, and never more than ``_MAX_THROTTLE_RETRIES``
    attempts. 401/403/other categories are never retried as if transient.
    Tests inject ``_sleep_fn`` (a no-op) so retry tests never actually sleep.
    """
    import time as _time

    sleep_fn = _sleep_fn or _time.sleep
    kwargs.setdefault("_request_timeout", _REQUEST_TIMEOUT)
    attempt = 0
    while True:
        try:
            result = fn(*args, **kwargs)
            return CallOutcome(ok=True, result=result, category=CATEGORY_SUCCESS)
        except Exception as exc:  # noqa: BLE001 — deliberately broad; classified below
            category, detail = _classify_api_exception(exc)
            if category == CATEGORY_THROTTLED and attempt < _MAX_THROTTLE_RETRIES:
                delay = _throttle_backoff_seconds(attempt, retry_after=_retry_after_seconds(exc))
                logger.info(
                    "Kubernetes API call throttled (attempt %d/%d) — retrying in %.2fs",
                    attempt + 1, _MAX_THROTTLE_RETRIES, delay,
                )
                sleep_fn(delay)
                attempt += 1
                continue
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
    _sleep_fn: Callable[[float], None] = None,
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

        outcome = call_k8s(list_fn, _sleep_fn=_sleep_fn, **call_kwargs)

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


# ── RBAC and identity normalization (message 3) ───────────────────────────────
#
# Rule-expansion policy: a single RBAC rule is scanned once, its apiGroups/
# resources/verbs/nonResourceURLs are each categorized into the bounded
# vocabulary in kubernetes_schema.py, and the categorized SETS (never a
# per-combination Cartesian product) accumulate into one summary dict per
# Role/ClusterRole. This keeps a Role with e.g. 5 resources x 4 verbs to a
# handful of category flags, not 20 synthetic records.

def _expand_rbac_rule(rule: Any) -> Optional[dict]:
    """Return a plain-dict expansion of one RBAC rule, or None if the rule
    object is too malformed to read at all (skipped — never aborts the
    whole Role)."""
    try:
        api_groups = getattr(rule, "api_groups", None) or []
        resources = getattr(rule, "resources", None) or []
        verbs = getattr(rule, "verbs", None) or []
        resource_names = getattr(rule, "resource_names", None) or []
        non_resource_urls = getattr(rule, "non_resource_urls", None) or []
        return {
            "api_groups": [str(g) for g in api_groups if g is not None],
            "resources": [str(r) for r in resources if r is not None],
            "verbs": [str(v) for v in verbs if v is not None],
            "resource_names_present": bool(resource_names),
            "non_resource_urls": [str(u) for u in non_resource_urls if u is not None],
        }
    except Exception:  # noqa: BLE001 — malformed rule object, skip it
        return None


_RBAC_BOOLEAN_FLAG_NAMES: tuple[str, ...] = (
    "secret_read", "secret_write", "configmap_read", "configmap_write",
    "pod_read", "pod_write", "pod_exec", "pod_attach", "pod_port_forward", "pod_logs",
    "workload_write", "service_write", "network_mutation",
    "rbac_read", "rbac_write", "cluster_role_binding_write",
    "bind_permission", "escalate_permission", "impersonate_permission", "csr_approve_permission",
    "node_proxy_access", "nodes_read", "nodes_write", "persistent_volume_access",
    "admission_webhook_modification", "crd_modification", "namespace_modification",
    "service_account_token_creation", "subject_access_review_creation",
)


def _summarize_rbac_rules(rules: list) -> dict:
    """Categorize a list of raw RBAC rule objects into one deterministic
    summary dict: categorized API-group/resource/verb/non-resource-URL
    sets, the full dangerous-permission boolean taxonomy, a sorted
    high-risk category tag list, a highest-severity category, and a stable
    permission fingerprint. Never infers access beyond what a rule states;
    never persists the raw rule documents."""
    api_group_categories: set[str] = set()
    resource_categories: set[str] = set()
    verb_categories: set[str] = set()
    non_resource_categories: set[str] = set()
    resource_name_restriction_present = False
    non_resource_url_count = 0
    wildcard_api_group = wildcard_resource = wildcard_verb = wildcard_non_resource_url = False
    rule_count = 0
    flags: dict[str, bool] = {name: False for name in _RBAC_BOOLEAN_FLAG_NAMES}

    for raw_rule in rules or []:
        expanded = _expand_rbac_rule(raw_rule)
        if expanded is None:
            continue
        rule_count += 1
        groups, resources, verbs = expanded["api_groups"], expanded["resources"], expanded["verbs"]
        non_resource_urls = expanded["non_resource_urls"]
        if expanded["resource_names_present"]:
            resource_name_restriction_present = True
        non_resource_url_count += len(non_resource_urls)

        group_cats = {categorize_api_group(g) for g in groups} if groups else set()
        api_group_categories |= group_cats
        if API_GROUP_WILDCARD in group_cats:
            wildcard_api_group = True

        resource_cats = {categorize_resource(r) for r in resources} if resources else set()
        resource_categories |= resource_cats
        if RESOURCE_CATEGORY_WILDCARD in resource_cats:
            wildcard_resource = True

        verb_set = {v.lower() for v in verbs}
        verb_categories |= verb_set
        if VERB_WILDCARD in verb_set:
            wildcard_verb = True

        nr_cats = {categorize_non_resource_url(u) for u in non_resource_urls} if non_resource_urls else set()
        non_resource_categories |= nr_cats
        if ks.NON_RESOURCE_CATEGORY_WILDCARD in nr_cats:
            wildcard_non_resource_url = True

        is_wildcard_verb = VERB_WILDCARD in verb_set
        read_like = bool(verb_set & READ_VERBS) or is_wildcard_verb
        write_like = bool(verb_set & WRITE_VERBS) or is_wildcard_verb
        any_verb = bool(verb_set)
        has_wc = RESOURCE_CATEGORY_WILDCARD in resource_cats

        if RESOURCE_CATEGORY_SECRETS in resource_cats or has_wc:
            flags["secret_read"] = flags["secret_read"] or read_like
            flags["secret_write"] = flags["secret_write"] or write_like
        if RESOURCE_CATEGORY_CONFIGMAPS in resource_cats or has_wc:
            flags["configmap_read"] = flags["configmap_read"] or read_like
            flags["configmap_write"] = flags["configmap_write"] or write_like
        if RESOURCE_CATEGORY_PODS in resource_cats or has_wc:
            flags["pod_read"] = flags["pod_read"] or read_like
            flags["pod_write"] = flags["pod_write"] or write_like
        if (RESOURCE_CATEGORY_PODS_EXEC in resource_cats or has_wc) and any_verb:
            flags["pod_exec"] = True
        if (RESOURCE_CATEGORY_PODS_ATTACH in resource_cats or has_wc) and any_verb:
            flags["pod_attach"] = True
        if (RESOURCE_CATEGORY_PODS_PORTFORWARD in resource_cats or has_wc) and any_verb:
            flags["pod_port_forward"] = True
        if (RESOURCE_CATEGORY_PODS_LOG in resource_cats or has_wc) and read_like:
            flags["pod_logs"] = True
        if (RESOURCE_CATEGORY_WORKLOADS in resource_cats or has_wc) and write_like:
            flags["workload_write"] = True
        if (RESOURCE_CATEGORY_SERVICES in resource_cats or has_wc) and write_like:
            flags["service_write"] = True
        if (resource_cats & {RESOURCE_CATEGORY_INGRESSES, RESOURCE_CATEGORY_NETWORK_POLICIES} or has_wc) and write_like:
            flags["network_mutation"] = True
        rbac_resources_present = bool(resource_cats & {
            RESOURCE_CATEGORY_ROLES, RESOURCE_CATEGORY_ROLE_BINDINGS,
            RESOURCE_CATEGORY_CLUSTER_ROLES, RESOURCE_CATEGORY_CLUSTER_ROLE_BINDINGS,
        }) or has_wc
        if rbac_resources_present:
            flags["rbac_read"] = flags["rbac_read"] or read_like
            flags["rbac_write"] = flags["rbac_write"] or write_like
        if (RESOURCE_CATEGORY_CLUSTER_ROLE_BINDINGS in resource_cats or has_wc) and write_like:
            flags["cluster_role_binding_write"] = True
        if VERB_BIND in verb_set:
            flags["bind_permission"] = True
        if VERB_ESCALATE in verb_set:
            flags["escalate_permission"] = True
        if VERB_IMPERSONATE in verb_set:
            flags["impersonate_permission"] = True
        if (RESOURCE_CATEGORY_CSR_APPROVAL in resource_cats or has_wc) and any_verb:
            flags["csr_approve_permission"] = True
        if VERB_APPROVE in verb_set:
            flags["csr_approve_permission"] = True
        if (RESOURCE_CATEGORY_NODES_PROXY in resource_cats or has_wc) and any_verb:
            flags["node_proxy_access"] = True
        if RESOURCE_CATEGORY_NODES in resource_cats or has_wc:
            flags["nodes_read"] = flags["nodes_read"] or read_like
            flags["nodes_write"] = flags["nodes_write"] or write_like
        if (RESOURCE_CATEGORY_PERSISTENT_VOLUMES in resource_cats or has_wc) and any_verb:
            flags["persistent_volume_access"] = True
        if (resource_cats & {RESOURCE_CATEGORY_VALIDATING_WEBHOOKS, RESOURCE_CATEGORY_MUTATING_WEBHOOKS} or has_wc) and write_like:
            flags["admission_webhook_modification"] = True
        if (RESOURCE_CATEGORY_CRDS in resource_cats or has_wc) and write_like:
            flags["crd_modification"] = True
        if (RESOURCE_CATEGORY_NAMESPACES in resource_cats or has_wc) and write_like:
            flags["namespace_modification"] = True
        if (RESOURCE_CATEGORY_SERVICE_ACCOUNTS_TOKEN in resource_cats or has_wc) and ("create" in verb_set or is_wildcard_verb):
            flags["service_account_token_creation"] = True
        if (RESOURCE_CATEGORY_SUBJECT_ACCESS_REVIEWS in resource_cats or has_wc) and ("create" in verb_set or is_wildcard_verb):
            flags["subject_access_review_creation"] = True

    full_wildcard = wildcard_api_group and wildcard_resource and wildcard_verb

    high_risk: set[str] = set()
    if full_wildcard:
        high_risk.add(ks.CATEGORY_FULL_WILDCARD)
    if flags["bind_permission"]:
        high_risk.add(ks.CATEGORY_BIND)
    if flags["escalate_permission"]:
        high_risk.add(ks.CATEGORY_ESCALATE)
    if flags["impersonate_permission"]:
        high_risk.add(CATEGORY_IMPERSONATE)
    if flags["service_account_token_creation"]:
        high_risk.add(ks.CATEGORY_TOKEN_CREATION)
    if flags["csr_approve_permission"]:
        high_risk.add(ks.CATEGORY_CSR_APPROVAL)
    if flags["cluster_role_binding_write"]:
        high_risk.add(CATEGORY_CLUSTER_ROLE_BINDING_WRITE)
    if flags["admission_webhook_modification"]:
        high_risk.add(ks.CATEGORY_ADMISSION_WEBHOOK_WRITE)
    if flags["crd_modification"]:
        high_risk.add(ks.CATEGORY_CRD_WRITE)
    if flags["node_proxy_access"]:
        high_risk.add(ks.CATEGORY_NODE_PROXY)
    if flags["secret_read"] and (wildcard_resource or wildcard_api_group) and not full_wildcard:
        high_risk.add(CATEGORY_SECRET_READ_BROAD_SCOPE)
    elif flags["secret_read"]:
        high_risk.add(CATEGORY_SECRET_READ)
    if flags["secret_write"]:
        high_risk.add(CATEGORY_SECRET_WRITE)
    if flags["pod_exec"]:
        high_risk.add(CATEGORY_POD_EXEC)
    if flags["pod_attach"]:
        high_risk.add(ks.CATEGORY_POD_ATTACH)
    if flags["pod_port_forward"]:
        high_risk.add(ks.CATEGORY_POD_PORT_FORWARD)
    if flags["pod_write"]:
        high_risk.add(CATEGORY_POD_WRITE)
    if flags["workload_write"]:
        high_risk.add(CATEGORY_WORKLOAD_WRITE)
    if flags["rbac_write"] and not flags["cluster_role_binding_write"]:
        high_risk.add(CATEGORY_ROLE_OR_CLUSTER_ROLE_WRITE)
    if flags["namespace_modification"]:
        high_risk.add(ks.CATEGORY_NAMESPACE_WRITE)
    if flags["network_mutation"]:
        high_risk.add(ks.CATEGORY_NETWORK_MUTATION)
    if flags["persistent_volume_access"]:
        high_risk.add(ks.CATEGORY_PV_ACCESS)
    if flags["nodes_write"]:
        high_risk.add(ks.CATEGORY_NODES_WRITE)
    if wildcard_verb and not full_wildcard:
        high_risk.add(ks.CATEGORY_WILDCARD_VERB)
    if wildcard_resource and not full_wildcard:
        high_risk.add(ks.CATEGORY_WILDCARD_RESOURCE)
    if flags["configmap_write"]:
        high_risk.add(ks.CATEGORY_CONFIGMAP_WRITE)
    if flags["configmap_read"] and (wildcard_resource or wildcard_api_group):
        high_risk.add(ks.CATEGORY_CONFIGMAP_READ_BROAD)
    if flags["pod_logs"]:
        high_risk.add(ks.CATEGORY_POD_LOGS)
    if flags["service_write"]:
        high_risk.add(ks.CATEGORY_SERVICE_WRITE)
    if flags["nodes_read"]:
        high_risk.add(ks.CATEGORY_NODES_READ)
    if wildcard_non_resource_url:
        high_risk.add(ks.CATEGORY_NON_RESOURCE_BROAD)

    highest = highest_severity(high_risk)

    fingerprint_source = "|".join(sorted(
        [f"g:{c}" for c in api_group_categories]
        + [f"r:{c}" for c in resource_categories]
        + [f"v:{c}" for c in verb_categories]
        + [f"u:{c}" for c in non_resource_categories]
        + [f"h:{c}" for c in high_risk]
        + [f"rn:{resource_name_restriction_present}"]
    ))
    fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()[:16]

    return {
        "rule_count": rule_count,
        "api_group_categories": sorted(api_group_categories),
        "resource_categories": sorted(resource_categories),
        "verb_categories": sorted(verb_categories),
        "resource_name_restriction_present": resource_name_restriction_present,
        "non_resource_url_categories": sorted(non_resource_categories),
        "non_resource_url_count": non_resource_url_count,
        "wildcard_api_group": wildcard_api_group,
        "wildcard_resource": wildcard_resource,
        "wildcard_verb": wildcard_verb,
        "wildcard_non_resource_url": wildcard_non_resource_url,
        **flags,
        "token_request_access": flags["service_account_token_creation"],
        "high_risk_permission_categories": sorted(high_risk),
        "highest_severity_category": highest,
        "permission_fingerprint": fingerprint,
    }


def _extract_allowlisted_role_labels(labels: Optional[dict]) -> dict:
    return {k: v for k, v in (labels or {}).items() if k in SAFE_ROLE_LABEL_KEYS}


def _resolve_aggregated_rules(
    name: str,
    role_labels: dict[str, dict],
    role_rules: dict[str, list],
    role_selectors: dict[str, list],
    visited: frozenset,
    depth: int = 0,
    max_depth: int = 5,
) -> tuple[list, bool]:
    """Recursively resolve a ClusterRole's aggregated rule set via label
    selectors. Cycle-safe (visited set) and depth-capped; a cycle or
    depth-cap hit marks the result incomplete (never silently truncated
    without a signal) rather than raising or looping forever."""
    if name in visited or depth > max_depth:
        return [], False
    visited = visited | {name}
    direct_rules = list(role_rules.get(name, []))
    selectors = role_selectors.get(name) or []
    if not selectors:
        return direct_rules, True

    aggregated = list(direct_rules)
    complete = True
    for match_labels in selectors:
        if not match_labels:
            continue
        for other_name, other_labels in role_labels.items():
            if other_name == name:
                continue
            if all(other_labels.get(k) == v for k, v in match_labels.items()):
                sub_rules, sub_complete = _resolve_aggregated_rules(
                    other_name, role_labels, role_rules, role_selectors,
                    visited, depth + 1, max_depth,
                )
                aggregated.extend(sub_rules)
                complete = complete and sub_complete
    return aggregated, complete


def _normalize_role_object(
    obj: Any,
    *,
    kind: str,
    cluster_id: str,
    cluster_name: str,
    resolved_rules: Optional[list] = None,
    aggregation_complete: bool = True,
) -> dict:
    metadata = obj.metadata
    namespace = getattr(metadata, "namespace", None) if kind == "Role" else None
    name = metadata.name
    uid = getattr(metadata, "uid", None)
    labels = getattr(metadata, "labels", None) or {}

    aggregation_rule = getattr(obj, "aggregation_rule", None)
    aggregation_present = aggregation_rule is not None
    selectors = getattr(aggregation_rule, "cluster_role_selectors", None) or [] if aggregation_rule else []
    selector_count = len(selectors)

    own_rules = getattr(obj, "rules", None) or []
    rules_to_summarize = resolved_rules if resolved_rules is not None else own_rules
    summary = _summarize_rbac_rules(rules_to_summarize)

    built_in = categorize_builtin_role(name)
    allowlisted_labels = _extract_allowlisted_role_labels(labels)
    system_managed = name.startswith("system:") or bool(allowlisted_labels)

    record_id = f"{cluster_id}/{kind.lower()}/{namespace or 'cluster'}/{uid or name}"

    return {
        "record_type": KUBERNETES_ROLE if kind == "Role" else KUBERNETES_CLUSTER_ROLE,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "name": name,
        "uid": uid,
        "kind": kind,
        "built_in_role_category": built_in,
        "system_managed": system_managed,
        "aggregation_rule_present": aggregation_present,
        "aggregation_selector_count": selector_count,
        "collection_completeness_category": "complete" if aggregation_complete else "partial",
        **summary,
    }


def _categorize_subject(subject: Any) -> dict:
    """Normalize one RBAC Subject into safe identity fields. No tokens or
    Secrets are ever read — only kind/name/namespace, which are
    non-secret identifiers."""
    kind = getattr(subject, "kind", None) or ""
    name = getattr(subject, "name", None) or ""
    namespace = getattr(subject, "namespace", None)

    anonymous = unauthenticated_group = authenticated_group = False
    system_group = broad_group = False
    subject_identity = name

    if kind == SUBJECT_KIND_SERVICE_ACCOUNT:
        namespace = namespace or ""
        subject_identity = canonical_service_account_identity(namespace, name)
    elif kind == SUBJECT_KIND_GROUP:
        group_category = categorize_group(name)
        if group_category == GROUP_SYSTEM_UNAUTHENTICATED:
            unauthenticated_group = system_group = broad_group = True
        elif group_category == GROUP_SYSTEM_AUTHENTICATED:
            authenticated_group = system_group = broad_group = True
        elif group_category in (GROUP_SYSTEM_MASTERS, GROUP_SYSTEM_NODES):
            system_group = True
        elif group_category == GROUP_SYSTEM_SERVICEACCOUNTS_PREFIX:
            system_group = True
            broad_group = name == GROUP_SYSTEM_SERVICEACCOUNTS_PREFIX
    elif kind == SUBJECT_KIND_USER:
        if name == USER_SYSTEM_ANONYMOUS:
            anonymous = True

    return {
        "subject_kind": kind,
        "subject_name": name,
        "subject_namespace": namespace,
        "subject_identity": subject_identity,
        "anonymous_subject": anonymous,
        "unauthenticated_group": unauthenticated_group,
        "authenticated_group": authenticated_group,
        "system_group": system_group,
        "broad_group": broad_group,
    }


def _resolve_role_ref(
    role_ref: Any, *, namespace: Optional[str], role_index: dict
) -> tuple[Optional[dict], str, str, str, str]:
    """Returns ``(role_record_or_None, resolution_status, ref_kind, ref_name,
    ref_api_group)``. An unresolved/malformed roleRef is NEVER converted
    into a safe/low-privilege result — callers must use
    ``SEVERITY_UNKNOWN`` for it."""
    try:
        ref_kind = getattr(role_ref, "kind", None) or ""
        ref_name = getattr(role_ref, "name", None) or ""
        ref_api_group = getattr(role_ref, "api_group", None) or ""
    except Exception:  # noqa: BLE001
        return None, ROLE_RESOLUTION_MALFORMED, "", "", ""

    if not ref_kind or not ref_name:
        return None, ROLE_RESOLUTION_MALFORMED, ref_kind, ref_name, ref_api_group
    if ref_kind == "Role":
        key = ("Role", namespace, ref_name)
    elif ref_kind == "ClusterRole":
        key = ("ClusterRole", None, ref_name)
    else:
        return None, ROLE_RESOLUTION_MALFORMED, ref_kind, ref_name, ref_api_group

    role = role_index.get(key)
    if role is None:
        return None, ROLE_RESOLUTION_MISSING, ref_kind, ref_name, ref_api_group
    return role, ROLE_RESOLUTION_RESOLVED, ref_kind, ref_name, ref_api_group


def _normalize_rbac_binding(
    obj: Any,
    *,
    kind: str,
    cluster_id: str,
    cluster_name: str,
    role_index: dict,
    role_collection_denied: bool,
) -> tuple[dict, list[dict]]:
    """Normalize one RoleBinding/ClusterRoleBinding into a coarse binding
    record plus one fine-grained ``kubernetes_rbac_subject_binding`` record
    per subject (so "subject X added to binding Y" is one precise Change).
    """
    metadata = obj.metadata
    namespace = getattr(metadata, "namespace", None) if kind == "RoleBinding" else None
    name = metadata.name
    uid = getattr(metadata, "uid", None)
    role_ref = getattr(obj, "role_ref", None)

    if role_ref is not None:
        role_record, resolution_status, ref_kind, ref_name, ref_api_group = _resolve_role_ref(
            role_ref, namespace=namespace, role_index=role_index,
        )
        if role_record is None and resolution_status == ROLE_RESOLUTION_MISSING and role_collection_denied:
            resolution_status = ROLE_RESOLUTION_ACCESS_DENIED
    else:
        role_record, resolution_status, ref_kind, ref_name, ref_api_group = None, ROLE_RESOLUTION_MALFORMED, "", "", ""

    if role_record is not None:
        resolved_privilege = role_record["highest_severity_category"]
        cluster_admin_binding = role_record["built_in_role_category"] == BUILTIN_ROLE_CLUSTER_ADMIN
        wildcard_binding = (
            role_record["wildcard_api_group"] and role_record["wildcard_resource"] and role_record["wildcard_verb"]
        )
        high_risk_categories = role_record["high_risk_permission_categories"]
    else:
        resolved_privilege = SEVERITY_UNKNOWN
        # Even unresolved, a roleRef literally named "cluster-admin" is a
        # meaningful signal worth surfacing — never silently downgraded.
        cluster_admin_binding = ref_name == BUILTIN_ROLE_CLUSTER_ADMIN
        wildcard_binding = False
        high_risk_categories = []

    raw_subjects = getattr(obj, "subjects", None) or []
    subject_infos: list[dict] = []
    for s in raw_subjects:
        try:
            subject_infos.append(_categorize_subject(s))
        except Exception:  # noqa: BLE001 — malformed subject, skip it
            continue

    record_id = f"{cluster_id}/{kind.lower()}/{namespace or 'cluster'}/{uid or name}"

    subject_kind_counts = {"User": 0, "Group": 0, "ServiceAccount": 0}
    for si in subject_infos:
        if si["subject_kind"] in subject_kind_counts:
            subject_kind_counts[si["subject_kind"]] += 1

    fingerprint_source = (
        "|".join(sorted(f"{si['subject_kind']}:{si['subject_identity']}" for si in subject_infos))
        + f"||{ref_kind}:{ref_name}"
    )
    binding_fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()[:16]

    binding_record = {
        "record_type": KUBERNETES_ROLE_BINDING if kind == "RoleBinding" else KUBERNETES_CLUSTER_ROLE_BINDING,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "name": name,
        "uid": uid,
        "kind": kind,
        "role_ref_kind": ref_kind,
        "role_ref_name": ref_name,
        "role_ref_api_group": ref_api_group,
        "subject_count": len(subject_infos),
        "user_subject_count": subject_kind_counts["User"],
        "group_subject_count": subject_kind_counts["Group"],
        "service_account_subject_count": subject_kind_counts["ServiceAccount"],
        "role_resolved": role_record is not None,
        "role_resolution_status": resolution_status,
        "resolved_privilege_category": resolved_privilege,
        "cluster_admin_binding": cluster_admin_binding,
        "wildcard_permission_binding": wildcard_binding,
        "high_risk_permission_categories": high_risk_categories,
        "binding_fingerprint": binding_fingerprint,
        "collection_completeness_category": "complete",
    }

    subject_binding_records: list[dict] = []
    for si in subject_infos:
        cross_ns = (
            si["subject_kind"] == SUBJECT_KIND_SERVICE_ACCOUNT
            and namespace is not None
            and si["subject_namespace"] != namespace
        )
        sb_record_id = f"{record_id}/subject/{si['subject_kind']}/{si['subject_identity']}"
        subject_binding_records.append({
            "record_type": KUBERNETES_RBAC_SUBJECT_BINDING,
            "record_id": sb_record_id,
            "cluster_id": cluster_id,
            "cluster_name": cluster_name,
            "binding_kind": kind,
            "binding_namespace": namespace,
            "binding_name": name,
            "binding_uid": uid,
            "role_ref_kind": ref_kind,
            "role_ref_name": ref_name,
            "role_ref_api_group": ref_api_group,
            "subject_kind": si["subject_kind"],
            "subject_name": si["subject_name"],
            "subject_namespace": si["subject_namespace"],
            "subject_identity": si["subject_identity"],
            "anonymous_subject": si["anonymous_subject"],
            "unauthenticated_group": si["unauthenticated_group"],
            "authenticated_group": si["authenticated_group"],
            "system_group": si["system_group"],
            "broad_group": si["broad_group"],
            "cross_namespace_service_account": cross_ns,
            "role_resolved": role_record is not None,
            "role_resolution_status": resolution_status,
            "resolved_privilege_category": resolved_privilege,
            "cluster_admin_binding": cluster_admin_binding,
            "wildcard_permission_binding": wildcard_binding,
            "high_risk_permission_categories": high_risk_categories,
        })

    return binding_record, subject_binding_records


def _normalize_service_account(obj: Any, *, cluster_id: str, cluster_name: str) -> dict:
    """Basic ServiceAccount fields only — binding-derived privilege fields
    are filled in by ``_enrich_service_accounts`` after bindings/roles are
    resolved. Never reads ``.secrets[].name`` values beyond a count."""
    metadata = obj.metadata
    namespace = metadata.namespace
    name = metadata.name
    uid = getattr(metadata, "uid", None)
    automount = getattr(obj, "automount_service_account_token", None)
    image_pull_secrets = getattr(obj, "image_pull_secrets", None) or []
    secrets = getattr(obj, "secrets", None) or []

    record_id = f"{cluster_id}/service_account/{namespace}/{uid or name}"

    return {
        "record_type": KUBERNETES_SERVICE_ACCOUNT,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "name": name,
        "uid": uid,
        "automount_service_account_token": automount,
        "image_pull_secret_count": len(image_pull_secrets),
        "secret_reference_count": len(secrets),
        "workload_reference_count": 0,
        "bound_role_binding_count": 0,
        "bound_cluster_role_binding_count": 0,
        "highest_privilege_category": SEVERITY_LOW,
        "cluster_admin_bound": False,
        "wildcard_permission_bound": False,
        "secret_read_permission_bound": False,
        "pod_exec_permission_bound": False,
        "workload_creation_permission_bound": False,
        "rbac_modification_permission_bound": False,
        "impersonation_permission_bound": False,
        "collection_completeness_category": "complete",
    }


def _enrich_service_accounts(
    sa_records: list[dict],
    subject_binding_records: list[dict],
    workload_records: list[dict],
) -> None:
    """Mutates ``sa_records`` in place with binding-derived privilege
    fields and workload-reference counts, resolved locally from
    already-collected records (no additional API calls)."""
    workload_sa_counts: dict[tuple[Optional[str], str], int] = {}
    for w in workload_records:
        key = (w.get("namespace"), w.get("service_account_name"))
        workload_sa_counts[key] = workload_sa_counts.get(key, 0) + 1

    by_identity: dict[str, list[dict]] = {}
    for sb in subject_binding_records:
        if sb["subject_kind"] != SUBJECT_KIND_SERVICE_ACCOUNT:
            continue
        by_identity.setdefault(sb["subject_identity"], []).append(sb)

    for sa in sa_records:
        identity = canonical_service_account_identity(sa["namespace"], sa["name"])
        bindings = by_identity.get(identity, [])
        role_binding_count = sum(1 for b in bindings if b["binding_kind"] == "RoleBinding")
        cluster_role_binding_count = sum(1 for b in bindings if b["binding_kind"] == "ClusterRoleBinding")
        categories: set[str] = set()
        for b in bindings:
            categories.update(b["high_risk_permission_categories"])
        cluster_admin = any(b["cluster_admin_binding"] for b in bindings)
        wildcard = any(b["wildcard_permission_binding"] for b in bindings)

        sa["bound_role_binding_count"] = role_binding_count
        sa["bound_cluster_role_binding_count"] = cluster_role_binding_count
        sa["highest_privilege_category"] = SEVERITY_CRITICAL if cluster_admin else highest_severity(categories)
        sa["cluster_admin_bound"] = cluster_admin
        sa["wildcard_permission_bound"] = wildcard
        sa["secret_read_permission_bound"] = bool(categories & {CATEGORY_SECRET_READ, CATEGORY_SECRET_READ_BROAD_SCOPE})
        sa["pod_exec_permission_bound"] = CATEGORY_POD_EXEC in categories
        sa["workload_creation_permission_bound"] = bool(categories & {CATEGORY_WORKLOAD_WRITE, CATEGORY_POD_WRITE})
        sa["rbac_modification_permission_bound"] = bool(
            categories & {CATEGORY_ROLE_OR_CLUSTER_ROLE_WRITE, CATEGORY_CLUSTER_ROLE_BINDING_WRITE}
        )
        sa["impersonation_permission_bound"] = CATEGORY_IMPERSONATE in categories
        sa["workload_reference_count"] = workload_sa_counts.get((sa["namespace"], sa["name"]), 0)


def resolve_effective_automount(
    *, workload_explicit: Optional[bool], sa_automount_explicit: Optional[bool], sa_status: str,
) -> tuple[str, str]:
    """Resolve effective ``automountServiceAccountToken`` posture.

    Resolution order: workload/Pod template explicit value, then
    ServiceAccount explicit value, then the Kubernetes default (``true``).
    ``sa_status`` must be one of ``"found"``, ``"missing"``,
    ``"access_denied"`` — a missing/denied ServiceAccount is NEVER silently
    treated as "default true"; it produces an explicit unknown state.
    Returns ``(effective_automount_state, automount_source_category)``.
    """
    if workload_explicit is True:
        return AUTOMOUNT_STATE_EXPLICIT_WORKLOAD_TRUE, AUTOMOUNT_SOURCE_WORKLOAD_EXPLICIT
    if workload_explicit is False:
        return AUTOMOUNT_STATE_EXPLICIT_WORKLOAD_FALSE, AUTOMOUNT_SOURCE_WORKLOAD_EXPLICIT
    if sa_status == "missing":
        return AUTOMOUNT_STATE_UNKNOWN_SERVICE_ACCOUNT_MISSING, AUTOMOUNT_SOURCE_UNKNOWN
    if sa_status != "found":
        return AUTOMOUNT_STATE_UNKNOWN_PERMISSION_DENIED, AUTOMOUNT_SOURCE_UNKNOWN
    if sa_automount_explicit is True:
        return AUTOMOUNT_STATE_INHERITED_SERVICE_ACCOUNT_TRUE, AUTOMOUNT_SOURCE_SERVICE_ACCOUNT_EXPLICIT
    if sa_automount_explicit is False:
        return AUTOMOUNT_STATE_INHERITED_SERVICE_ACCOUNT_FALSE, AUTOMOUNT_SOURCE_SERVICE_ACCOUNT_EXPLICIT
    return AUTOMOUNT_STATE_KUBERNETES_DEFAULT_TRUE, AUTOMOUNT_SOURCE_KUBERNETES_DEFAULT


def _enrich_workload_service_accounts(
    rollup_records: list[dict], sa_records: list[dict], sa_collection_status: str,
) -> None:
    """Mutates message-2's ``kubernetes_workload_service_account`` rollup
    records in place with resolved automount posture and bound-privilege
    context now that ServiceAccounts/bindings/roles have been collected."""
    sa_by_key = {(sa["namespace"], sa["name"]): sa for sa in sa_records}

    for rollup in rollup_records:
        key = (rollup["namespace"], rollup["service_account_name"])
        sa = sa_by_key.get(key)
        found = sa is not None
        if found:
            sa_status = "found"
        elif sa_collection_status == "partial":
            sa_status = "access_denied"
        else:
            sa_status = "missing"

        sa_automount_explicit = sa["automount_service_account_token"] if sa else None
        effective_state, source_category = resolve_effective_automount(
            workload_explicit=None, sa_automount_explicit=sa_automount_explicit, sa_status=sa_status,
        )

        risky: set[str] = set()
        if sa:
            if sa["secret_read_permission_bound"]:
                risky.add(CATEGORY_SECRET_READ)
            if sa["pod_exec_permission_bound"]:
                risky.add(CATEGORY_POD_EXEC)
            if sa["workload_creation_permission_bound"]:
                risky.add(CATEGORY_WORKLOAD_WRITE)
            if sa["rbac_modification_permission_bound"]:
                risky.add(CATEGORY_ROLE_OR_CLUSTER_ROLE_WRITE)
            if sa["impersonation_permission_bound"]:
                risky.add(CATEGORY_IMPERSONATE)

        rollup["service_account_found"] = found
        rollup["effective_automount_state"] = effective_state
        rollup["automount_source_category"] = source_category
        rollup["service_account_privilege_summary"] = sa["highest_privilege_category"] if sa else SEVERITY_UNKNOWN
        rollup["bound_role_binding_count"] = sa["bound_role_binding_count"] if sa else 0
        rollup["bound_cluster_role_binding_count"] = sa["bound_cluster_role_binding_count"] if sa else 0
        rollup["risky_permission_categories"] = sorted(risky)
        rollup["collection_completeness_category"] = "complete" if (found or sa_collection_status != "partial") else "partial"


def _build_rbac_permission_summaries(
    subject_binding_records: list[dict], *, cluster_id: str, cluster_name: str,
) -> list[dict]:
    """One rollup record per unique subject identity (User/Group/
    ServiceAccount), aggregating privilege across every binding that
    subject appears in — see kubernetes_schema.py module docstring for why
    this is distinct from the per-binding-subject drift record."""
    buckets: dict[tuple[str, str], dict] = {}
    for sb in subject_binding_records:
        key = (sb["subject_kind"], sb["subject_identity"])
        bucket = buckets.setdefault(key, {
            "namespace": sb.get("subject_namespace"),
            "role_binding_count": 0, "cluster_role_binding_count": 0,
            "cluster_admin": False, "wildcard": False, "categories": set(),
        })
        if sb["binding_kind"] == "RoleBinding":
            bucket["role_binding_count"] += 1
        else:
            bucket["cluster_role_binding_count"] += 1
        bucket["cluster_admin"] = bucket["cluster_admin"] or sb["cluster_admin_binding"]
        bucket["wildcard"] = bucket["wildcard"] or sb["wildcard_permission_binding"]
        bucket["categories"].update(sb["high_risk_permission_categories"])

    records: list[dict] = []
    for (subject_kind, subject_identity), bucket in sorted(buckets.items()):
        categories = bucket["categories"]
        highest = SEVERITY_CRITICAL if bucket["cluster_admin"] else highest_severity(categories)
        records.append({
            "record_type": KUBERNETES_RBAC_PERMISSION_SUMMARY,
            "record_id": f"{cluster_id}/rbac_permission_summary/{subject_kind}/{subject_identity}",
            "cluster_id": cluster_id,
            "cluster_name": cluster_name,
            "subject_kind": subject_kind,
            "subject_identity": subject_identity,
            "namespace": bucket["namespace"],
            "role_binding_count": bucket["role_binding_count"],
            "cluster_role_binding_count": bucket["cluster_role_binding_count"],
            "cluster_admin_bound": bucket["cluster_admin"],
            "wildcard_permission_bound": bucket["wildcard"],
            "secret_read_bound": bool(categories & {CATEGORY_SECRET_READ, CATEGORY_SECRET_READ_BROAD_SCOPE}),
            "secret_write_bound": CATEGORY_SECRET_WRITE in categories,
            "pod_exec_bound": CATEGORY_POD_EXEC in categories,
            "workload_create_bound": bool(categories & {CATEGORY_WORKLOAD_WRITE, CATEGORY_POD_WRITE}),
            "rbac_modification_bound": bool(
                categories & {CATEGORY_ROLE_OR_CLUSTER_ROLE_WRITE, CATEGORY_CLUSTER_ROLE_BINDING_WRITE}
            ),
            "impersonation_bound": CATEGORY_IMPERSONATE in categories,
            "high_risk_permission_categories": sorted(categories),
            "highest_privilege_category": highest,
            "collection_completeness_category": "complete",
        })
    return records


def _collect_service_accounts(
    list_fn: Callable[..., Any], *, cluster_id: str, cluster_name: str,
    namespace_allowlist: Optional[list[str]],
) -> tuple[list[dict], str]:
    raw_items, diag = paginate_list(list_fn)
    records: list[dict] = []
    for item in raw_items:
        try:
            ns = item.metadata.namespace
        except Exception:  # noqa: BLE001
            continue
        if namespace_allowlist is not None and ns not in namespace_allowlist:
            continue
        try:
            records.append(_normalize_service_account(item, cluster_id=cluster_id, cluster_name=cluster_name))
        except Exception:  # noqa: BLE001
            continue

    status = _family_completeness_status(diag)
    for r in records:
        r["collection_completeness_category"] = status
    records.sort(key=lambda r: (r["namespace"], r["name"]))
    return records, status


def _collect_cluster_roles(
    list_fn: Callable[..., Any], *, cluster_id: str, cluster_name: str,
) -> tuple[list[dict], str, dict]:
    """Returns ``(records, status, role_index)``. Resolves aggregation via
    label selectors across the full collected set (see
    ``_resolve_aggregated_rules``)."""
    raw_items, diag = paginate_list(list_fn)
    status = _family_completeness_status(diag)

    role_labels: dict[str, dict] = {}
    role_rules: dict[str, list] = {}
    role_selectors: dict[str, list] = {}
    valid_items = []
    for item in raw_items:
        try:
            name = item.metadata.name
        except Exception:  # noqa: BLE001
            continue
        valid_items.append(item)
        role_labels[name] = getattr(item.metadata, "labels", None) or {}
        role_rules[name] = getattr(item, "rules", None) or []
        agg = getattr(item, "aggregation_rule", None)
        selectors = getattr(agg, "cluster_role_selectors", None) or [] if agg else []
        role_selectors[name] = [(getattr(sel, "match_labels", None) or {}) for sel in selectors]

    records: list[dict] = []
    index: dict = {}
    for item in valid_items:
        try:
            name = item.metadata.name
            resolved_rules, complete = _resolve_aggregated_rules(
                name, role_labels, role_rules, role_selectors, frozenset(),
            )
            record = _normalize_role_object(
                item, kind="ClusterRole", cluster_id=cluster_id, cluster_name=cluster_name,
                resolved_rules=resolved_rules, aggregation_complete=complete,
            )
        except Exception:  # noqa: BLE001
            continue
        # A per-role aggregation-incomplete result must not be silently
        # overwritten by the family-level status — apply the WORSE of the two.
        if record["collection_completeness_category"] == "complete" and status != "complete":
            record["collection_completeness_category"] = status
        records.append(record)
        index[("ClusterRole", None, record["name"])] = record

    records.sort(key=lambda r: r["name"])
    return records, status, index


def _collect_roles(
    list_fn: Callable[..., Any], *, cluster_id: str, cluster_name: str,
    namespace_allowlist: Optional[list[str]],
) -> tuple[list[dict], str, dict]:
    raw_items, diag = paginate_list(list_fn)
    status = _family_completeness_status(diag)

    records: list[dict] = []
    index: dict = {}
    for item in raw_items:
        try:
            ns = item.metadata.namespace
        except Exception:  # noqa: BLE001
            continue
        if namespace_allowlist is not None and ns not in namespace_allowlist:
            continue
        try:
            record = _normalize_role_object(item, kind="Role", cluster_id=cluster_id, cluster_name=cluster_name)
        except Exception:  # noqa: BLE001
            continue
        record["collection_completeness_category"] = status
        records.append(record)
        index[("Role", record["namespace"], record["name"])] = record

    records.sort(key=lambda r: (r["namespace"], r["name"]))
    return records, status, index


def _collect_rbac_bindings(
    list_fn: Callable[..., Any],
    *,
    kind: str,
    cluster_id: str,
    cluster_name: str,
    namespace_allowlist: Optional[list[str]],
    role_index: dict,
    role_collection_denied: bool,
) -> tuple[list[dict], list[dict], str]:
    raw_items, diag = paginate_list(list_fn)
    binding_records: list[dict] = []
    subject_records: list[dict] = []

    for item in raw_items:
        try:
            ns = getattr(item.metadata, "namespace", None) if kind == "RoleBinding" else None
        except Exception:  # noqa: BLE001
            continue
        if kind == "RoleBinding" and namespace_allowlist is not None and ns not in namespace_allowlist:
            continue
        try:
            binding_record, subjects = _normalize_rbac_binding(
                item, kind=kind, cluster_id=cluster_id, cluster_name=cluster_name,
                role_index=role_index, role_collection_denied=role_collection_denied,
            )
        except Exception:  # noqa: BLE001
            continue
        binding_records.append(binding_record)
        subject_records.extend(subjects)

    status = _family_completeness_status(diag)
    for r in binding_records:
        r["collection_completeness_category"] = status
    binding_records.sort(key=lambda r: (r.get("namespace") or "", r["name"]))
    subject_records.sort(key=lambda r: r["record_id"])
    return binding_records, subject_records, status


# ── Network exposure and isolation normalization (message 4) ─────────────────
#
# Public-exposure claims are conservative throughout this section: a
# LoadBalancer-*typed* Service with no assigned `.status.loadBalancer.ingress`
# is "pending", never "confirmed external"; a NodePort Service is "node-level"
# exposure capability, never a claim of internet reachability (that requires
# node-level firewall/cloud-security-group evidence this connector does not
# have). See ``categorize_cidr``/``EXPOSURE_*`` in kubernetes_schema.py for
# the full evidence hierarchy.

def _internal_load_balancer_annotation_present(annotations: dict) -> bool:
    """Only the fixed, well-known internal-load-balancer annotation keys
    for AWS/GCP/Azure are ever inspected — never arbitrary annotations."""
    for key in SAFE_INTERNAL_LOAD_BALANCER_ANNOTATION_KEYS:
        value = (annotations or {}).get(key)
        if value is None:
            continue
        if key == "cloud.google.com/load-balancer-type":
            if str(value).strip().lower() == "internal":
                return True
        elif str(value).strip().lower() == "true":
            return True
    return False


def _categorize_service_exposure(
    *, service_type: str, external_ip_count: int, lb_ingress_count: int,
    internal_lb_annotation: bool, cluster_ip_present: bool,
) -> tuple[str, bool]:
    """Returns ``(exposure_category, mixed_exposure_evidence)``."""
    mixed = False
    if service_type == "ExternalName":
        return ks.EXPOSURE_EXTERNAL_NAME, mixed
    if service_type == "LoadBalancer":
        if external_ip_count > 0:
            mixed = True
        if internal_lb_annotation:
            return ks.EXPOSURE_INTERNAL_LOAD_BALANCER, mixed
        if lb_ingress_count > 0:
            return ks.EXPOSURE_EXTERNAL_LOAD_BALANCER, mixed
        return ks.EXPOSURE_PENDING_LOAD_BALANCER, mixed
    if external_ip_count > 0:
        return ks.EXPOSURE_EXTERNAL_IP, mixed
    if service_type == "NodePort":
        return ks.EXPOSURE_NODE_PORT, mixed
    if not cluster_ip_present:
        return ks.EXPOSURE_HEADLESS_INTERNAL, mixed
    return ks.EXPOSURE_CLUSTER_INTERNAL, mixed


def _selector_fingerprint_keys_only(selector: Optional[dict]) -> str:
    if not selector:
        return stable_fingerprint("empty")
    return stable_fingerprint(*sorted(selector.keys()))


def _categorize_target_port(target_port: Any) -> str:
    if target_port is None:
        return "unset"
    if isinstance(target_port, str):
        return "named"
    return "numeric"


def _normalize_service_port(
    port_obj: Any, *, cluster_id: str, cluster_name: str, namespace: str,
    parent_record_id: str, exposure_category: str,
) -> dict:
    name = getattr(port_obj, "name", None)
    protocol = getattr(port_obj, "protocol", None) or "TCP"
    port = getattr(port_obj, "port", None)
    target_port = getattr(port_obj, "target_port", None)
    node_port = getattr(port_obj, "node_port", None)
    app_protocol = getattr(port_obj, "app_protocol", None)
    sensitive = port in SENSITIVE_SERVICE_PORTS if port is not None else False

    record_id = f"{parent_record_id}/port/{name or port}"
    return {
        "record_type": KUBERNETES_SERVICE_PORT,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "parent_service_record_id": parent_record_id,
        "port_name": name,
        "protocol": protocol,
        "port": port,
        "target_port_category": _categorize_target_port(target_port),
        "node_port": node_port,
        "app_protocol_category": app_protocol,
        "sensitive_port": sensitive,
        "exposure_category": exposure_category,
    }


def _normalize_service(obj: Any, *, cluster_id: str, cluster_name: str) -> tuple[dict, list[dict]]:
    metadata = obj.metadata
    namespace = metadata.namespace
    name = metadata.name
    uid = getattr(metadata, "uid", None)
    annotations = getattr(metadata, "annotations", None) or {}
    spec = getattr(obj, "spec", None)
    status = getattr(obj, "status", None)

    service_type = getattr(spec, "type", None) or "ClusterIP"
    cluster_ip = getattr(spec, "cluster_ip", None)
    cluster_ip_present = bool(cluster_ip) and cluster_ip != "None"
    headless = cluster_ip == "None"
    external_ips = getattr(spec, "external_i_ps", None) or []
    external_name = getattr(spec, "external_name", None)

    lb_status = getattr(status, "load_balancer", None) if status else None
    lb_ingress = (getattr(lb_status, "ingress", None) or []) if lb_status else []

    internal_annotation = _internal_load_balancer_annotation_present(annotations)
    exposure_category, mixed = _categorize_service_exposure(
        service_type=service_type,
        external_ip_count=len(external_ips),
        lb_ingress_count=len(lb_ingress),
        internal_lb_annotation=internal_annotation,
        cluster_ip_present=cluster_ip_present,
    )

    external_name_category = categorize_host(external_name) if service_type == "ExternalName" else None

    selector = getattr(spec, "selector", None) or {}
    ports = getattr(spec, "ports", None) or []
    ip_families = getattr(spec, "ip_families", None) or []

    record_id = f"{cluster_id}/service/{namespace}/{uid or name}"

    record = {
        "record_type": KUBERNETES_SERVICE,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "name": name,
        "uid": uid,
        "service_type": service_type,
        "cluster_ip_present": cluster_ip_present,
        "headless": headless,
        "external_ip_count": len(external_ips),
        "load_balancer_ingress_count": len(lb_ingress),
        "external_name_category": external_name_category,
        "publish_not_ready_addresses": bool(getattr(spec, "publish_not_ready_addresses", False)),
        "external_traffic_policy": getattr(spec, "external_traffic_policy", None),
        "internal_traffic_policy": getattr(spec, "internal_traffic_policy", None),
        "session_affinity": getattr(spec, "session_affinity", None),
        "ip_family_categories": sorted(set(ip_families)),
        "ip_family_policy": getattr(spec, "ip_family_policy", None),
        "selector_key_count": len(selector),
        "selector_fingerprint": _selector_fingerprint_keys_only(selector),
        "internal_load_balancer_annotation_present": internal_annotation,
        "port_count": len(ports),
        "exposure_category": exposure_category,
        "mixed_exposure_evidence": mixed,
        "collection_completeness_category": "complete",
    }

    port_records = [
        _normalize_service_port(
            p, cluster_id=cluster_id, cluster_name=cluster_name, namespace=namespace,
            parent_record_id=record_id, exposure_category=exposure_category,
        )
        for p in ports
    ]
    return record, port_records


def _collect_services(
    list_fn: Callable[..., Any], *, cluster_id: str, cluster_name: str,
    namespace_allowlist: Optional[list[str]],
) -> tuple[list[dict], list[dict], str]:
    raw_items, diag = paginate_list(list_fn)
    service_records: list[dict] = []
    port_records: list[dict] = []
    for item in raw_items:
        try:
            ns = item.metadata.namespace
        except Exception:  # noqa: BLE001
            continue
        if namespace_allowlist is not None and ns not in namespace_allowlist:
            continue
        try:
            record, ports = _normalize_service(item, cluster_id=cluster_id, cluster_name=cluster_name)
        except Exception:  # noqa: BLE001
            continue
        service_records.append(record)
        port_records.extend(ports)

    status = _family_completeness_status(diag)
    for r in service_records:
        r["collection_completeness_category"] = status
    service_records.sort(key=lambda r: (r["namespace"], r["name"]))
    port_records.sort(key=lambda r: r["record_id"])
    return service_records, port_records, status


# ── Ingress normalization ─────────────────────────────────────────────────────

def _normalize_ingress(obj: Any, *, cluster_id: str, cluster_name: str) -> tuple[dict, list[dict]]:
    metadata = obj.metadata
    namespace = metadata.namespace
    name = metadata.name
    uid = getattr(metadata, "uid", None)
    spec = getattr(obj, "spec", None)
    status = getattr(obj, "status", None)

    ingress_class = getattr(spec, "ingress_class_name", None)
    default_backend = getattr(spec, "default_backend", None)
    rules = getattr(spec, "rules", None) or []
    tls_list = getattr(spec, "tls", None) or []

    lb_status = getattr(status, "load_balancer", None) if status else None
    lb_ingress = (getattr(lb_status, "ingress", None) or []) if lb_status else []

    tls_hosts: set[str] = set()
    tls_secret_ref_count = 0
    for tls_entry in tls_list:
        tls_hosts.update(getattr(tls_entry, "hosts", None) or [])
        if getattr(tls_entry, "secret_name", None):
            tls_secret_ref_count += 1

    record_id = f"{cluster_id}/ingress/{namespace}/{uid or name}"
    public_exposure_category = ks.EXPOSURE_EXTERNAL_LOAD_BALANCER if len(lb_ingress) > 0 else ks.EXPOSURE_UNKNOWN

    rule_records: list[dict] = []
    host_count = 0
    wildcard_host_count = 0
    hostless_rule_present = False
    http_path_count = 0
    backend_services: set[str] = set()
    path_type_categories: set[str] = set()
    any_tls_covered = False
    any_plaintext = False

    for rule in rules:
        host = getattr(rule, "host", None)
        host_cat = categorize_host(host)
        if host_cat == ks.HOST_CATEGORY_WILDCARD:
            wildcard_host_count += 1
        if host_cat == ks.HOST_CATEGORY_HOSTLESS:
            hostless_rule_present = True
        else:
            host_count += 1

        tls_covered = bool(host) and host in tls_hosts
        if tls_covered:
            any_tls_covered = True
        else:
            any_plaintext = True

        http = getattr(rule, "http", None)
        paths = (getattr(http, "paths", None) or []) if http else []
        if not paths:
            paths = [None]

        for path_obj in paths:
            http_path_count += 1
            path = getattr(path_obj, "path", None) if path_obj else None
            path_type = getattr(path_obj, "path_type", None) if path_obj else None
            path_type_categories.add(path_type or "unknown")
            backend = getattr(path_obj, "backend", None) if path_obj else None
            service_backend = getattr(backend, "service", None) if backend else None
            backend_name = getattr(service_backend, "name", None) if service_backend else None
            backend_port_obj = getattr(service_backend, "port", None) if service_backend else None
            backend_port = getattr(backend_port_obj, "number", None) if backend_port_obj else None
            if backend_name:
                backend_services.add(backend_name)

            catch_all = is_catch_all_path(path, path_type) and host_cat == ks.HOST_CATEGORY_HOSTLESS

            rule_record_id = f"{record_id}/rule/{host or 'no-host'}/{path or 'no-path'}"
            rule_records.append({
                "record_type": KUBERNETES_INGRESS_RULE,
                "record_id": rule_record_id,
                "cluster_id": cluster_id,
                "cluster_name": cluster_name,
                "namespace": namespace,
                "parent_ingress_record_id": record_id,
                "host_category": host_cat,
                "hostname": host,
                "path_category": categorize_ingress_path(path, path_type),
                "path_type": path_type,
                "backend_service_name": backend_name,
                "backend_port": backend_port,
                "tls_covered": tls_covered,
                "public_exposure_category": public_exposure_category,
                "catch_all_route": catch_all,
                "default_backend": False,
                "route_fingerprint": stable_fingerprint(host_cat, path, path_type, backend_name, backend_port),
            })

    default_backend_present = default_backend is not None
    if default_backend_present:
        db_service = getattr(default_backend, "service", None)
        db_name = getattr(db_service, "name", None) if db_service else None
        db_port_obj = getattr(db_service, "port", None) if db_service else None
        db_port = getattr(db_port_obj, "number", None) if db_port_obj else None
        if db_name:
            backend_services.add(db_name)
        rule_records.append({
            "record_type": KUBERNETES_INGRESS_RULE,
            "record_id": f"{record_id}/rule/default-backend",
            "cluster_id": cluster_id,
            "cluster_name": cluster_name,
            "namespace": namespace,
            "parent_ingress_record_id": record_id,
            "host_category": ks.HOST_CATEGORY_HOSTLESS,
            "hostname": None,
            "path_category": ks.PATH_CATEGORY_ROOT_PREFIX,
            "path_type": None,
            "backend_service_name": db_name,
            "backend_port": db_port,
            "tls_covered": False,
            "public_exposure_category": public_exposure_category,
            "catch_all_route": True,
            "default_backend": True,
            "route_fingerprint": stable_fingerprint("default-backend", db_name, db_port),
        })
        any_plaintext = True

    if not rules and not default_backend_present:
        plaintext_category = "no_rules"
    elif any_tls_covered and not any_plaintext:
        plaintext_category = "tls_covered"
    else:
        plaintext_category = "plaintext_http_present"

    record = {
        "record_type": KUBERNETES_INGRESS,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "name": name,
        "uid": uid,
        "ingress_class": ingress_class,
        "default_backend_present": default_backend_present,
        "rule_count": len(rules),
        "host_count": host_count,
        "wildcard_host_count": wildcard_host_count,
        "hostless_rule_present": hostless_rule_present,
        "tls_block_count": len(tls_list),
        "tls_host_count": len(tls_hosts),
        "tls_secret_reference_count": tls_secret_ref_count,
        "http_path_count": http_path_count,
        "backend_service_count": len(backend_services),
        "cross_namespace_backend_count": 0,  # Ingress backends are always same-namespace by spec
        "path_type_categories": sorted(path_type_categories),
        "plaintext_exposure_category": plaintext_category,
        "public_exposure_category": public_exposure_category,
        "load_balancer_ingress_count": len(lb_ingress),
        "collection_completeness_category": "complete",
    }
    return record, rule_records


def _collect_ingresses(
    list_fn: Callable[..., Any], *, cluster_id: str, cluster_name: str,
    namespace_allowlist: Optional[list[str]],
) -> tuple[list[dict], list[dict], str]:
    raw_items, diag = paginate_list(list_fn)
    ingress_records: list[dict] = []
    rule_records: list[dict] = []
    for item in raw_items:
        try:
            ns = item.metadata.namespace
        except Exception:  # noqa: BLE001
            continue
        if namespace_allowlist is not None and ns not in namespace_allowlist:
            continue
        try:
            record, rules = _normalize_ingress(item, cluster_id=cluster_id, cluster_name=cluster_name)
        except Exception:  # noqa: BLE001
            continue
        ingress_records.append(record)
        rule_records.extend(rules)

    status = _family_completeness_status(diag)
    for r in ingress_records:
        r["collection_completeness_category"] = status
    ingress_records.sort(key=lambda r: (r["namespace"], r["name"]))
    rule_records.sort(key=lambda r: r["record_id"])
    return ingress_records, rule_records, status


# ── Gateway API (dict-based, via CustomObjectsApi) ────────────────────────────

def _paginate_custom_objects(
    list_fn: Callable[..., Any],
    *,
    page_size: int = _DEFAULT_PAGE_SIZE,
    max_pages: int = _MAX_PAGES,
    _sleep_fn: Callable[[float], None] = None,
    **kwargs: Any,
) -> tuple[list[dict], PageDiagnostics]:
    """Adapted ``paginate_list`` for ``CustomObjectsApi``, whose responses
    are raw dicts (``{"items": [...], "metadata": {"continue": ...}}``)
    rather than typed objects with ``.items``/``.metadata._continue``
    attributes. Same safety properties as ``paginate_list``: single 410
    restart, repeated-token detection, page cap, partial-on-any-failure."""
    items: list[dict] = []
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

        outcome = call_k8s(list_fn, _sleep_fn=_sleep_fn, **call_kwargs)

        if not outcome.ok:
            if outcome.category == CATEGORY_CONTINUATION_EXPIRED and not already_restarted:
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
        if not isinstance(page, dict):
            diag.complete = False
            diag.malformed_metadata = True
            break
        page_items = page.get("items")
        if page_items is None:
            diag.complete = False
            diag.malformed_metadata = True
            break
        items.extend(page_items)

        next_token = (page.get("metadata") or {}).get("continue")
        if not next_token:
            break
        if next_token in seen_tokens:
            diag.complete = False
            diag.error_category = "repeated_continuation_token"
            break
        seen_tokens.add(next_token)
        continue_token = next_token

    return items, diag


def _collect_gateway_api_resources(
    custom_api: Any, *, group: str, version: str, plural: str,
    namespace_allowlist: Optional[list[str]],
) -> tuple[list[dict], str]:
    """Fail-soft collection of one Gateway API resource type. A 404 (CRDs
    not installed) is reported as "unsupported", never as an error or an
    empty-but-successful collection."""
    raw_items, diag = _paginate_custom_objects(
        custom_api.list_cluster_custom_object, group=group, version=version, plural=plural,
    )
    status = _family_completeness_status(diag)
    filtered: list[dict] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        ns = (item.get("metadata") or {}).get("namespace")
        if namespace_allowlist is not None and ns not in namespace_allowlist:
            continue
        filtered.append(item)
    return filtered, status


def _gateway_address_category(addresses: list[dict]) -> tuple[int, str]:
    if not addresses:
        return 0, ks.GATEWAY_ADDRESS_UNASSIGNED
    categories: set[str] = set()
    for addr in addresses:
        addr_type = addr.get("type") or "IPAddress"
        value = addr.get("value")
        if addr_type == "IPAddress":
            cat = categorize_ip_address(value)
            if cat == ks.CIDR_CATEGORY_BROAD_PUBLIC_RANGE:
                categories.add(ks.GATEWAY_ADDRESS_EXTERNAL)
            elif cat in (ks.CIDR_CATEGORY_PRIVATE, ks.CIDR_CATEGORY_LOOPBACK, ks.CIDR_CATEGORY_LINK_LOCAL):
                categories.add(ks.GATEWAY_ADDRESS_INTERNAL)
            else:
                categories.add(ks.GATEWAY_ADDRESS_UNKNOWN)
        elif addr_type == "Hostname":
            categories.add(ks.GATEWAY_ADDRESS_DNS_HOSTNAME)
        else:
            categories.add(ks.GATEWAY_ADDRESS_UNKNOWN)

    if ks.GATEWAY_ADDRESS_EXTERNAL in categories:
        return len(addresses), ks.GATEWAY_ADDRESS_EXTERNAL
    if categories == {ks.GATEWAY_ADDRESS_INTERNAL}:
        return len(addresses), ks.GATEWAY_ADDRESS_INTERNAL
    if ks.GATEWAY_ADDRESS_DNS_HOSTNAME in categories:
        return len(addresses), ks.GATEWAY_ADDRESS_DNS_HOSTNAME
    return len(addresses), ks.GATEWAY_ADDRESS_UNKNOWN


def _listener_protocol_flags(listeners: list[dict]) -> dict:
    protocols: set[str] = set()
    http_count = https_count = tls_count = wildcard_hostname_count = 0
    for listener in listeners:
        proto = listener.get("protocol") or ""
        protocols.add(proto)
        if proto == "HTTP":
            http_count += 1
        if proto == "HTTPS":
            https_count += 1
        if proto in ("HTTPS", "TLS"):
            tls_count += 1
        hostname = listener.get("hostname")
        if hostname and categorize_host(hostname) == ks.HOST_CATEGORY_WILDCARD:
            wildcard_hostname_count += 1
    return {
        "protocols": sorted(protocols), "http_count": http_count, "https_count": https_count,
        "tls_count": tls_count, "wildcard_hostname_count": wildcard_hostname_count,
    }


def _allowed_routes_category(allowed_routes: Optional[dict]) -> tuple[str, bool]:
    """Gateway API defaults ``allowedRoutes.namespaces.from`` to ``"Same"``
    when the whole field is omitted."""
    if not allowed_routes:
        return ks.ALLOWED_NAMESPACES_SAME, False
    namespaces = allowed_routes.get("namespaces") or {}
    from_val = namespaces.get("from") or "Same"
    if from_val == "All":
        return ks.ALLOWED_NAMESPACES_ALL, True
    if from_val == "Selector":
        return ks.ALLOWED_NAMESPACES_SELECTOR, True
    if from_val == "Same":
        return ks.ALLOWED_NAMESPACES_SAME, False
    return ks.ALLOWED_NAMESPACES_UNKNOWN, False


def _tls_mode_and_cert_count(tls: Optional[dict]) -> tuple[str, int]:
    if not tls:
        return ks.TLS_MODE_NONE, 0
    mode = tls.get("mode") or ks.TLS_MODE_TERMINATE
    cert_refs = tls.get("certificateRefs") or []
    return mode, len(cert_refs)


def _gateway_status_category(status: Optional[dict]) -> str:
    if not status:
        return ks.GATEWAY_API_STATUS_UNKNOWN
    for cond in status.get("conditions") or []:
        if cond.get("type") in ("Accepted", "Ready"):
            if cond.get("status") == "True":
                return ks.GATEWAY_API_STATUS_READY
            if cond.get("status") == "False":
                return ks.GATEWAY_API_STATUS_NOT_READY
    return ks.GATEWAY_API_STATUS_UNKNOWN


def _attached_route_count(status: Optional[dict]) -> Optional[int]:
    if not status or status.get("listeners") is None:
        return None
    return sum(ls.get("attachedRoutes") or 0 for ls in status["listeners"])


def _normalize_gateway(obj: dict, *, cluster_id: str, cluster_name: str) -> tuple[dict, list[dict]]:
    metadata = obj.get("metadata") or {}
    namespace = metadata.get("namespace")
    name = metadata.get("name")
    uid = metadata.get("uid")
    spec = obj.get("spec") or {}
    status = obj.get("status") or {}

    gateway_class = spec.get("gatewayClassName")
    listeners = spec.get("listeners") or []
    addresses = spec.get("addresses") or status.get("addresses") or []

    address_count, address_category = _gateway_address_category(addresses)
    proto_info = _listener_protocol_flags(listeners)
    attached_routes = _attached_route_count(status)
    status_category = _gateway_status_category(status)

    record_id = f"{cluster_id}/gateway/{namespace}/{uid or name}"

    listener_records: list[dict] = []
    any_cross_namespace_allowance = False
    tls_cert_ref_total = 0
    for listener in listeners:
        listener_name = listener.get("name") or ""
        protocol = listener.get("protocol") or ""
        port = listener.get("port")
        hostname = listener.get("hostname")
        hostname_cat = categorize_host(hostname)
        tls_mode, cert_count = _tls_mode_and_cert_count(listener.get("tls"))
        tls_cert_ref_total += cert_count
        allowed_cat, cross_ns = _allowed_routes_category(listener.get("allowedRoutes"))
        if cross_ns:
            any_cross_namespace_allowance = True

        public_exposure = ks.EXPOSURE_UNKNOWN
        if address_category == ks.GATEWAY_ADDRESS_EXTERNAL and protocol in ("HTTP", "HTTPS", "TLS"):
            public_exposure = ks.EXPOSURE_EXTERNAL_LOAD_BALANCER
        elif address_category == ks.GATEWAY_ADDRESS_INTERNAL:
            public_exposure = ks.EXPOSURE_INTERNAL_LOAD_BALANCER

        listener_record_id = f"{record_id}/listener/{listener_name}"
        listener_records.append({
            "record_type": KUBERNETES_GATEWAY_LISTENER,
            "record_id": listener_record_id,
            "cluster_id": cluster_id,
            "cluster_name": cluster_name,
            "namespace": namespace,
            "parent_gateway_record_id": record_id,
            "listener_name": listener_name,
            "protocol": protocol,
            "port": port,
            "hostname_category": hostname_cat,
            "tls_mode": tls_mode,
            "certificate_reference_count": cert_count,
            "allowed_namespace_policy": allowed_cat,
            "public_exposure_category": public_exposure,
            "listener_fingerprint": stable_fingerprint(protocol, port, hostname_cat, tls_mode, allowed_cat),
        })

    record = {
        "record_type": KUBERNETES_GATEWAY,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "name": name,
        "uid": uid,
        "gateway_class_name": gateway_class,
        "listener_count": len(listeners),
        "attached_route_count": attached_routes,
        "address_count": address_count,
        "public_address_category": address_category,
        "listener_protocol_categories": proto_info["protocols"],
        "http_listener_count": proto_info["http_count"],
        "https_listener_count": proto_info["https_count"],
        "tls_listener_count": proto_info["tls_count"],
        "wildcard_hostname_count": proto_info["wildcard_hostname_count"],
        "allowed_routes_category": ks.ALLOWED_NAMESPACES_ALL if any_cross_namespace_allowance else ks.ALLOWED_NAMESPACES_SAME,
        "cross_namespace_route_allowance": any_cross_namespace_allowance,
        "tls_certificate_reference_count": tls_cert_ref_total,
        "status_category": status_category,
        "collection_completeness_category": "complete",
    }
    return record, listener_records


def _collect_gateways(
    custom_api: Any, *, cluster_id: str, cluster_name: str, namespace_allowlist: Optional[list[str]],
) -> tuple[list[dict], list[dict], str]:
    raw_items, status = _collect_gateway_api_resources(
        custom_api, group="gateway.networking.k8s.io", version="v1", plural="gateways",
        namespace_allowlist=namespace_allowlist,
    )
    gateway_records: list[dict] = []
    listener_records: list[dict] = []
    for item in raw_items:
        try:
            record, listeners = _normalize_gateway(item, cluster_id=cluster_id, cluster_name=cluster_name)
        except Exception:  # noqa: BLE001
            continue
        gateway_records.append(record)
        listener_records.extend(listeners)

    for r in gateway_records:
        r["collection_completeness_category"] = status
    gateway_records.sort(key=lambda r: (r["namespace"] or "", r["name"] or ""))
    listener_records.sort(key=lambda r: r["record_id"])
    return gateway_records, listener_records, status


# ── HTTPRoute (dict-based, via CustomObjectsApi) ──────────────────────────────

def _match_categories_for_rule(matches: list[dict]) -> tuple[set[str], bool, bool, bool]:
    path_cats: set[str] = set()
    method_present = header_present = query_present = False
    for m in matches or []:
        path = m.get("path") or {}
        path_type = path.get("type")
        path_value = path.get("value")
        path_cats.add(categorize_ingress_path(path_value, path_type) if path_type else "unspecified")
        if m.get("method"):
            method_present = True
        if m.get("headers"):
            header_present = True
        if m.get("queryParams"):
            query_present = True
    return path_cats, method_present, header_present, query_present


def _filter_categories_for_rule(filters: list[dict]) -> set[str]:
    return {f.get("type") for f in (filters or []) if f.get("type")}


def _http_route_resolved_refs_status(status: dict) -> str:
    parents = status.get("parents") or []
    if not parents:
        return ks.ROUTE_REFS_UNKNOWN
    results: list[Optional[bool]] = []
    for p in parents:
        resolved = None
        for c in p.get("conditions") or []:
            if c.get("type") == "ResolvedRefs":
                resolved = c.get("status") == "True"
        results.append(resolved)
    if all(r is True for r in results):
        return ks.ROUTE_REFS_ALL_RESOLVED
    if any(r is False for r in results):
        return ks.ROUTE_REFS_SOME_UNRESOLVED
    return ks.ROUTE_REFS_UNKNOWN


def _normalize_http_route(obj: dict, *, cluster_id: str, cluster_name: str) -> tuple[dict, list[dict]]:
    metadata = obj.get("metadata") or {}
    namespace = metadata.get("namespace")
    name = metadata.get("name")
    uid = metadata.get("uid")
    spec = obj.get("spec") or {}
    status = obj.get("status") or {}

    parent_refs = spec.get("parentRefs") or []
    cross_ns_parents = sum(1 for p in parent_refs if p.get("namespace") and p.get("namespace") != namespace)

    hostnames = spec.get("hostnames") or []
    wildcard_hostnames = sum(1 for h in hostnames if categorize_host(h) == ks.HOST_CATEGORY_WILDCARD)

    rules = spec.get("rules") or []
    record_id = f"{cluster_id}/http_route/{namespace}/{uid or name}"

    rule_records: list[dict] = []
    total_backend_refs = 0
    total_cross_ns_backend = 0
    all_path_cats: set[str] = set()
    any_method = any_header = any_query = False
    all_filter_cats: set[str] = set()
    any_redirect = any_rewrite = any_timeout = False

    for idx, rule in enumerate(rules):
        matches = rule.get("matches") or []
        path_cats, method_p, header_p, query_p = _match_categories_for_rule(matches)
        all_path_cats |= path_cats
        any_method = any_method or method_p
        any_header = any_header or header_p
        any_query = any_query or query_p

        backend_refs = rule.get("backendRefs") or []
        cross_ns_backend_count = sum(1 for b in backend_refs if b.get("namespace") and b.get("namespace") != namespace)
        total_backend_refs += len(backend_refs)
        total_cross_ns_backend += cross_ns_backend_count

        filters = rule.get("filters") or []
        filter_cats = _filter_categories_for_rule(filters)
        all_filter_cats |= filter_cats
        redirect_present = "RequestRedirect" in filter_cats
        rewrite_present = "URLRewrite" in filter_cats
        mirror_present = "RequestMirror" in filter_cats
        any_redirect = any_redirect or redirect_present
        any_rewrite = any_rewrite or rewrite_present

        catch_all = not matches or any(
            is_catch_all_path((m.get("path") or {}).get("value"), (m.get("path") or {}).get("type"))
            for m in matches
        )
        timeouts_present = bool(rule.get("timeouts"))
        any_timeout = any_timeout or timeouts_present

        backend_namespaces = {b.get("namespace") for b in backend_refs if b.get("namespace")}

        rule_records.append({
            "record_type": KUBERNETES_HTTP_ROUTE_RULE,
            "record_id": f"{record_id}/rule/{idx}",
            "cluster_id": cluster_id,
            "cluster_name": cluster_name,
            "namespace": namespace,
            "parent_route_record_id": record_id,
            "match_categories": sorted(path_cats) or ["none"],
            "catch_all_path": catch_all,
            "backend_count": len(backend_refs),
            "backend_namespace_count": len(backend_namespaces),
            "cross_namespace_backend": cross_ns_backend_count > 0,
            "redirect_present": redirect_present,
            "rewrite_present": rewrite_present,
            "mirror_present": mirror_present,
            "route_fingerprint": stable_fingerprint(idx, sorted(path_cats), len(backend_refs), sorted(filter_cats)),
        })

    record = {
        "record_type": KUBERNETES_HTTP_ROUTE,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "name": name,
        "uid": uid,
        "parent_ref_count": len(parent_refs),
        "cross_namespace_parent_count": cross_ns_parents,
        "hostname_count": len(hostnames),
        "wildcard_hostname_count": wildcard_hostnames,
        "rule_count": len(rules),
        "backend_ref_count": total_backend_refs,
        "cross_namespace_backend_count": total_cross_ns_backend,
        "path_match_categories": sorted(all_path_cats),
        "method_match_present": any_method,
        "header_match_present": any_header,
        "query_match_present": any_query,
        "filter_categories": sorted(all_filter_cats),
        "redirect_present": any_redirect,
        "rewrite_present": any_rewrite,
        "timeout_configured_present": any_timeout,
        "resolved_refs_status": _http_route_resolved_refs_status(status),
        "route_fingerprint": stable_fingerprint(len(parent_refs), len(hostnames), len(rules), sorted(all_filter_cats)),
        "collection_completeness_category": "complete",
    }
    return record, rule_records


def _collect_http_routes(
    custom_api: Any, *, cluster_id: str, cluster_name: str, namespace_allowlist: Optional[list[str]],
) -> tuple[list[dict], list[dict], str]:
    raw_items, status = _collect_gateway_api_resources(
        custom_api, group="gateway.networking.k8s.io", version="v1", plural="httproutes",
        namespace_allowlist=namespace_allowlist,
    )
    route_records: list[dict] = []
    rule_records: list[dict] = []
    for item in raw_items:
        try:
            record, rules = _normalize_http_route(item, cluster_id=cluster_id, cluster_name=cluster_name)
        except Exception:  # noqa: BLE001
            continue
        route_records.append(record)
        rule_records.extend(rules)

    for r in route_records:
        r["collection_completeness_category"] = status
    route_records.sort(key=lambda r: (r["namespace"] or "", r["name"] or ""))
    rule_records.sort(key=lambda r: r["record_id"])
    return route_records, rule_records, status


# ── NetworkPolicy normalization ────────────────────────────────────────────────

def _peer_flags(peers: Optional[list]) -> dict:
    namespace_selector_present = pod_selector_present = ip_block_present = False
    except_cidr_count = 0
    public_ipv4 = public_ipv6 = False
    broad_cidr_count = 0

    for peer in peers or []:
        if getattr(peer, "namespace_selector", None) is not None:
            namespace_selector_present = True
        if getattr(peer, "pod_selector", None) is not None:
            pod_selector_present = True
        ip_block = getattr(peer, "ip_block", None)
        if ip_block is not None:
            ip_block_present = True
            cidr = getattr(ip_block, "cidr", None)
            except_list = getattr(ip_block, "_except", None) or []
            except_cidr_count += len(except_list)
            category = categorize_cidr(cidr)
            if category == ks.CIDR_CATEGORY_PUBLIC_IPV4_UNRESTRICTED:
                public_ipv4 = True
            if category == ks.CIDR_CATEGORY_PUBLIC_IPV6_UNRESTRICTED:
                public_ipv6 = True
            if is_public_cidr_category(category):
                broad_cidr_count += 1

    return {
        "namespace_selector_present": namespace_selector_present,
        "pod_selector_present": pod_selector_present,
        "ip_block_present": ip_block_present,
        "except_cidr_count": except_cidr_count,
        "public_ipv4": public_ipv4,
        "public_ipv6": public_ipv6,
        "broad_cidr_count": broad_cidr_count,
    }


def _merge_peer_flags(flag_dicts: list[dict]) -> dict:
    result = {
        "namespace_selector_present": False, "pod_selector_present": False, "ip_block_present": False,
        "except_cidr_count": 0, "public_ipv4": False, "public_ipv6": False, "broad_cidr_count": 0,
    }
    for f in flag_dicts:
        result["namespace_selector_present"] = result["namespace_selector_present"] or f["namespace_selector_present"]
        result["pod_selector_present"] = result["pod_selector_present"] or f["pod_selector_present"]
        result["ip_block_present"] = result["ip_block_present"] or f["ip_block_present"]
        result["except_cidr_count"] += f["except_cidr_count"]
        result["public_ipv4"] = result["public_ipv4"] or f["public_ipv4"]
        result["public_ipv6"] = result["public_ipv6"] or f["public_ipv6"]
        result["broad_cidr_count"] += f["broad_cidr_count"]
    return result


def _port_flags(rules: list) -> tuple[bool, set[str]]:
    port_restriction_present = False
    protocols: set[str] = set()
    for rule in rules or []:
        ports = getattr(rule, "ports", None) or []
        if ports:
            port_restriction_present = True
        for p in ports:
            proto = getattr(p, "protocol", None)
            if proto:
                protocols.add(proto)
    return port_restriction_present, protocols


def _pod_selector_empty(selector: Any) -> bool:
    if selector is None:
        return False
    match_labels = getattr(selector, "match_labels", None) or {}
    match_expressions = getattr(selector, "match_expressions", None) or []
    return not match_labels and not match_expressions


def _selector_label_key_count(selector: Any) -> int:
    if selector is None:
        return 0
    match_labels = getattr(selector, "match_labels", None) or {}
    match_expressions = getattr(selector, "match_expressions", None) or []
    return len(match_labels) + len(match_expressions)


def _normalize_network_policy(obj: Any, *, cluster_id: str, cluster_name: str) -> dict:
    """Normalize a NetworkPolicy, preserving the omitted-vs-empty-list
    distinction (``*_rules_declared``) even though Kubernetes itself treats
    both as behaviorally identical (default-deny when the type is
    selected) — see module docstring."""
    metadata = obj.metadata
    namespace = metadata.namespace
    name = metadata.name
    uid = getattr(metadata, "uid", None)
    spec = getattr(obj, "spec", None)

    pod_selector = getattr(spec, "pod_selector", None)
    policy_types = getattr(spec, "policy_types", None) or []

    ingress_declared = getattr(spec, "ingress", None) is not None
    egress_declared = getattr(spec, "egress", None) is not None
    ingress_rules = getattr(spec, "ingress", None) or []
    egress_rules = getattr(spec, "egress", None) or []

    ingress_isolation = "Ingress" in policy_types
    egress_isolation = "Egress" in policy_types

    empty_ingress_list = ingress_isolation and len(ingress_rules) == 0
    empty_egress_list = egress_isolation and len(egress_rules) == 0

    allows_all_ingress = ingress_isolation and any(
        rule_permits_everything(getattr(r, "_from", None), getattr(r, "ports", None))
        for r in ingress_rules
    )
    allows_all_egress = egress_isolation and any(
        rule_permits_everything(getattr(r, "to", None), getattr(r, "ports", None))
        for r in egress_rules
    )

    merged = _merge_peer_flags(
        [_peer_flags(getattr(r, "_from", None)) for r in ingress_rules]
        + [_peer_flags(getattr(r, "to", None)) for r in egress_rules]
    )

    ingress_port_restricted, ingress_protocols = _port_flags(ingress_rules)
    egress_port_restricted, egress_protocols = _port_flags(egress_rules)
    port_restriction_present = ingress_port_restricted or egress_port_restricted
    protocol_categories = sorted(ingress_protocols | egress_protocols)

    pod_selector_empty = _pod_selector_empty(pod_selector)
    selected_label_key_count = _selector_label_key_count(pod_selector)
    selector_fingerprint = stable_fingerprint(pod_selector_empty, selected_label_key_count)

    policy_fingerprint = stable_fingerprint(
        selector_fingerprint, sorted(policy_types), len(ingress_rules), len(egress_rules),
        empty_ingress_list, empty_egress_list, allows_all_ingress, allows_all_egress,
        merged["public_ipv4"], merged["public_ipv6"], merged["broad_cidr_count"],
        port_restriction_present, protocol_categories,
    )

    record_id = f"{cluster_id}/network_policy/{namespace}/{uid or name}"

    return {
        "record_type": KUBERNETES_NETWORK_POLICY,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "name": name,
        "uid": uid,
        "pod_selector_empty_all_pods": pod_selector_empty,
        "selected_label_key_count": selected_label_key_count,
        "policy_types": sorted(policy_types),
        "ingress_rule_count": len(ingress_rules),
        "egress_rule_count": len(egress_rules),
        "ingress_isolation_enabled": ingress_isolation,
        "egress_isolation_enabled": egress_isolation,
        "ingress_rules_declared": ingress_declared,
        "egress_rules_declared": egress_declared,
        "empty_ingress_list": empty_ingress_list,
        "empty_egress_list": empty_egress_list,
        "allows_all_ingress": allows_all_ingress,
        "allows_all_egress": allows_all_egress,
        "public_ipv4_cidr_allowed": merged["public_ipv4"],
        "public_ipv6_cidr_allowed": merged["public_ipv6"],
        "broad_cidr_count": merged["broad_cidr_count"],
        "namespace_selector_present": merged["namespace_selector_present"],
        "pod_selector_present": merged["pod_selector_present"],
        "ip_block_present": merged["ip_block_present"],
        "except_cidr_count": merged["except_cidr_count"],
        "port_restriction_present": port_restriction_present,
        "protocol_categories": protocol_categories,
        "selector_fingerprint": selector_fingerprint,
        "policy_fingerprint": policy_fingerprint,
        "collection_completeness_category": "complete",
    }


def _collect_network_policies(
    list_fn: Callable[..., Any], *, cluster_id: str, cluster_name: str,
    namespace_allowlist: Optional[list[str]],
) -> tuple[list[dict], str]:
    raw_items, diag = paginate_list(list_fn)
    records: list[dict] = []
    for item in raw_items:
        try:
            ns = item.metadata.namespace
        except Exception:  # noqa: BLE001
            continue
        if namespace_allowlist is not None and ns not in namespace_allowlist:
            continue
        try:
            records.append(_normalize_network_policy(item, cluster_id=cluster_id, cluster_name=cluster_name))
        except Exception:  # noqa: BLE001
            continue

    status = _family_completeness_status(diag)
    for r in records:
        r["collection_completeness_category"] = status
    records.sort(key=lambda r: (r["namespace"], r["name"]))
    return records, status


def _build_namespace_network_postures(
    network_policy_records: list[dict], all_namespaces: list[str], *,
    cluster_id: str, cluster_name: str, collection_status: str,
) -> list[dict]:
    """One rollup per namespace. Coverage is honestly reported as
    "partial" whenever a namespace has NetworkPolicies but they don't
    provide comprehensive all-Pod default-deny — exact Pod-level coverage
    is intentionally not claimed since arbitrary workload labels are never
    persisted (see kubernetes.py module docstring)."""
    by_ns: dict[str, list[dict]] = {}
    for r in network_policy_records:
        by_ns.setdefault(r["namespace"], []).append(r)

    records: list[dict] = []
    for ns in sorted(set(all_namespaces) | set(by_ns.keys())):
        policies = by_ns.get(ns, [])
        policy_count = len(policies)
        has_any = policy_count > 0
        ingress_isolation_present = any(p["ingress_isolation_enabled"] for p in policies)
        egress_isolation_present = any(p["egress_isolation_enabled"] for p in policies)
        all_pod_ingress_deny = any(
            p["pod_selector_empty_all_pods"] and p["ingress_isolation_enabled"] and p["empty_ingress_list"]
            for p in policies
        )
        all_pod_egress_deny = any(
            p["pod_selector_empty_all_pods"] and p["egress_isolation_enabled"] and p["empty_egress_list"]
            for p in policies
        )
        public_ingress_allowance = any(
            p["ingress_isolation_enabled"] and (p["allows_all_ingress"] or p["public_ipv4_cidr_allowed"] or p["public_ipv6_cidr_allowed"])
            for p in policies
        )
        public_egress_allowance = any(
            p["egress_isolation_enabled"] and (p["allows_all_egress"] or p["public_ipv4_cidr_allowed"] or p["public_ipv6_cidr_allowed"])
            for p in policies
        )
        broad_ns_selector = any(p["namespace_selector_present"] for p in policies)
        broad_pod_selector = any(p["pod_selector_present"] for p in policies)

        if collection_status == "partial":
            coverage = ks.POLICY_COVERAGE_UNKNOWN
        elif not has_any:
            coverage = ks.POLICY_COVERAGE_NONE
        elif all_pod_ingress_deny and all_pod_egress_deny:
            coverage = ks.POLICY_COVERAGE_BROAD
        else:
            coverage = ks.POLICY_COVERAGE_PARTIAL

        records.append({
            "record_type": KUBERNETES_NAMESPACE_NETWORK_POSTURE,
            "record_id": f"{cluster_id}/namespace_network_posture/{ns}",
            "cluster_id": cluster_id,
            "cluster_name": cluster_name,
            "namespace": ns,
            "policy_count": policy_count,
            "has_any_network_policy": has_any,
            "ingress_isolation_present": ingress_isolation_present,
            "egress_isolation_present": egress_isolation_present,
            "all_pod_ingress_default_deny": all_pod_ingress_deny,
            "all_pod_egress_default_deny": all_pod_egress_deny,
            "policy_coverage_category": coverage,
            "public_ingress_allowance_present": public_ingress_allowance,
            "public_egress_allowance_present": public_egress_allowance,
            "broad_namespace_selector_allowance": broad_ns_selector,
            "broad_pod_selector_allowance": broad_pod_selector,
            "collection_completeness_category": "complete" if collection_status != "partial" else "partial",
        })
    return records


# ── Admission control and configuration governance (message 5) ──────────────
#
# ConfigMap and Secret metadata collection are DELIBERATELY NOT IMPLEMENTED
# in this connector — this is a permanent architectural boundary, not a gap
# to be closed later. The Kubernetes API returns full values alongside
# metadata for both resource types (no field-level RBAC exists to request
# "metadata but not values"), so any read access at all would require
# requesting — and receiving — the ability to read Secret/ConfigMap
# contents. ConfigTrace's default permission contract does not request read
# access to either resource type, and this connector makes zero calls to
# any Secret- or ConfigMap-reading CoreV1Api method (singular or list form,
# any namespace). See kubernetes_schema.py's module docstring for the full
# safety review.

def _categorize_webhook_client(client_config: Any) -> dict:
    """Categorize a webhook's clientConfig without ever persisting CA
    bundle bytes or the literal external URL — only a safe host category
    (reusing the same exact/wildcard/hostless vocabulary as Ingress
    hostnames) and a plaintext-HTTP flag."""
    service = getattr(client_config, "service", None) if client_config else None
    url = getattr(client_config, "url", None) if client_config else None
    ca_bundle = getattr(client_config, "ca_bundle", None) if client_config else None

    client_type = ks.CLIENT_TYPE_UNKNOWN
    service_namespace = service_name = service_path_category = service_port = None
    external_url_host_category = None
    plaintext_http = False

    if service is not None:
        client_type = ks.CLIENT_TYPE_SERVICE
        service_namespace = getattr(service, "namespace", None)
        service_name = getattr(service, "name", None)
        path = getattr(service, "path", None)
        service_path_category = "root" if not path or path == "/" else "specific"
        service_port = getattr(service, "port", None)
    elif url:
        client_type = ks.CLIENT_TYPE_URL
        parsed = urlparse(url)
        external_url_host_category = categorize_host(parsed.hostname)
        plaintext_http = parsed.scheme == "http"

    return {
        "client_type": client_type,
        "service_namespace": service_namespace,
        "service_name": service_name,
        "service_path_category": service_path_category,
        "service_port": service_port,
        "external_url_host_category": external_url_host_category,
        "ca_bundle_present": bool(ca_bundle),
        "plaintext_http": plaintext_http,
    }


def _summarize_scope_categories(categories: set) -> str:
    if not categories:
        return ks.SCOPE_UNKNOWN
    if ks.SCOPE_ALL in categories:
        return ks.SCOPE_ALL
    if len(categories) == 1:
        return next(iter(categories))
    return "mixed"


def _categorize_webhook_rules(rules: list) -> dict:
    """Categorize webhook rules into bounded sets — never Cartesian-
    expanded, never raw rule dicts persisted."""
    operation_categories: set[str] = set()
    api_group_categories: set[str] = set()
    api_version_categories: set[str] = set()
    resource_categories: set[str] = set()
    scope_categories: set[str] = set()
    wildcard_operation = wildcard_api_group = wildcard_api_version = wildcard_resource = False

    for rule in rules or []:
        try:
            operations = getattr(rule, "operations", None) or []
            api_groups = getattr(rule, "api_groups", None) or []
            api_versions = getattr(rule, "api_versions", None) or []
            resources = getattr(rule, "resources", None) or []
            scope = getattr(rule, "scope", None)
        except Exception:  # noqa: BLE001 — malformed rule, skip it
            continue

        for op in operations:
            operation_categories.add(op)
            if op == "*":
                wildcard_operation = True
        for g in api_groups:
            cat = categorize_api_group(g)
            api_group_categories.add(cat)
            if cat == ks.API_GROUP_WILDCARD:
                wildcard_api_group = True
        for v in api_versions:
            api_version_categories.add(v)
            if v == "*":
                wildcard_api_version = True
        for r in resources:
            cat = categorize_resource(r)
            resource_categories.add(cat)
            if cat == ks.RESOURCE_CATEGORY_WILDCARD:
                wildcard_resource = True
        scope_categories.add(categorize_admission_scope(scope))

    return {
        "operation_categories": sorted(operation_categories),
        "api_group_categories": sorted(api_group_categories),
        "api_version_categories": sorted(api_version_categories),
        "resource_categories": sorted(resource_categories),
        "scope_category": _summarize_scope_categories(scope_categories),
        "wildcard_operation": wildcard_operation,
        "wildcard_api_group": wildcard_api_group,
        "wildcard_api_version": wildcard_api_version,
        "wildcard_resource": wildcard_resource,
    }


def _normalize_admission_webhook(
    webhook: Any, *, webhook_type: str, cluster_id: str, cluster_name: str, parent_record_id: str,
) -> dict:
    name = getattr(webhook, "name", "") or ""
    client_info = _categorize_webhook_client(getattr(webhook, "client_config", None))

    failure_policy = categorize_failure_policy(getattr(webhook, "failure_policy", None))
    match_policy = categorize_match_policy(getattr(webhook, "match_policy", None))
    side_effects = categorize_side_effects(getattr(webhook, "side_effects", None))
    timeout = getattr(webhook, "timeout_seconds", None)

    ns_selector = getattr(webhook, "namespace_selector", None)
    ns_selector_info = categorize_selector_presence(
        getattr(ns_selector, "match_labels", None) if ns_selector else None,
        getattr(ns_selector, "match_expressions", None) if ns_selector else None,
        present=ns_selector is not None,
    )
    obj_selector = getattr(webhook, "object_selector", None)
    obj_selector_info = categorize_selector_presence(
        getattr(obj_selector, "match_labels", None) if obj_selector else None,
        getattr(obj_selector, "match_expressions", None) if obj_selector else None,
        present=obj_selector is not None,
    )

    rules = getattr(webhook, "rules", None) or []
    rule_info = _categorize_webhook_rules(rules)

    admission_review_versions = sorted(getattr(webhook, "admission_review_versions", None) or [])
    reinvocation_policy = None
    if webhook_type == "mutating":
        reinvocation_policy = categorize_reinvocation_policy(getattr(webhook, "reinvocation_policy", None))

    record_id = f"{parent_record_id}/webhook/{name}"
    fingerprint = stable_fingerprint(
        client_info["client_type"], failure_policy, match_policy, side_effects, timeout,
        ns_selector_info["fingerprint"], obj_selector_info["fingerprint"],
        rule_info["operation_categories"], rule_info["api_group_categories"],
        rule_info["resource_categories"], rule_info["scope_category"],
        admission_review_versions, reinvocation_policy,
    )

    return {
        "record_type": KUBERNETES_VALIDATING_WEBHOOK if webhook_type == "validating" else KUBERNETES_MUTATING_WEBHOOK,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "parent_configuration_record_id": parent_record_id,
        "webhook_name": name,
        "webhook_type": webhook_type,
        "client_type": client_info["client_type"],
        "service_namespace": client_info["service_namespace"],
        "service_name": client_info["service_name"],
        "service_path_category": client_info["service_path_category"],
        "service_port": client_info["service_port"],
        "external_url_host_category": client_info["external_url_host_category"],
        "plaintext_http_client": client_info["plaintext_http"],
        "failure_policy": failure_policy,
        "match_policy": match_policy,
        "side_effects": side_effects,
        "timeout_seconds": timeout,
        "namespace_selector_category": ns_selector_info["category"],
        "object_selector_category": obj_selector_info["category"],
        "rules_count": len(rules),
        "operation_categories": rule_info["operation_categories"],
        "api_group_categories": rule_info["api_group_categories"],
        "api_version_categories": rule_info["api_version_categories"],
        "resource_categories": rule_info["resource_categories"],
        "scope_category": rule_info["scope_category"],
        "admission_review_versions": admission_review_versions,
        "ca_bundle_present": client_info["ca_bundle_present"],
        "reinvocation_policy": reinvocation_policy,
        "wildcard_operation": rule_info["wildcard_operation"],
        "wildcard_api_group": rule_info["wildcard_api_group"],
        "wildcard_api_version": rule_info["wildcard_api_version"],
        "wildcard_resource": rule_info["wildcard_resource"],
        "webhook_fingerprint": fingerprint,
        "collection_completeness_category": "complete",
    }


def _normalize_webhook_configuration(
    obj: Any, *, kind: str, cluster_id: str, cluster_name: str,
) -> tuple[dict, list[dict]]:
    metadata = obj.metadata
    name = metadata.name
    uid = getattr(metadata, "uid", None)
    webhooks_raw = getattr(obj, "webhooks", None) or []

    kind_label = "validating_webhook_configuration" if kind == "validating" else "mutating_webhook_configuration"
    record_id = f"{cluster_id}/{kind_label}/{uid or name}"

    webhook_records: list[dict] = []
    for webhook in webhooks_raw:
        try:
            webhook_records.append(_normalize_admission_webhook(
                webhook, webhook_type=kind, cluster_id=cluster_id, cluster_name=cluster_name,
                parent_record_id=record_id,
            ))
        except Exception:  # noqa: BLE001 — malformed webhook, skip it
            logger.info("Skipping malformed %s webhook", kind)

    fail_open = sum(1 for w in webhook_records if w["failure_policy"] == ks.FAILURE_POLICY_IGNORE)
    fail_closed = sum(1 for w in webhook_records if w["failure_policy"] == ks.FAILURE_POLICY_FAIL)
    no_side_effects = sum(
        1 for w in webhook_records if w["side_effects"] in (ks.SIDE_EFFECTS_NONE, ks.SIDE_EFFECTS_NONE_ON_DRY_RUN)
    )
    unknown_side_effects = sum(1 for w in webhook_records if w["side_effects"] == ks.SIDE_EFFECTS_UNKNOWN)
    ns_selector_present = sum(1 for w in webhook_records if w["namespace_selector_category"] != ks.SELECTOR_ABSENT)
    obj_selector_present = sum(1 for w in webhook_records if w["object_selector_category"] != ks.SELECTOR_ABSENT)
    external_url_count = sum(1 for w in webhook_records if w["client_type"] == ks.CLIENT_TYPE_URL)
    service_client_count = sum(1 for w in webhook_records if w["client_type"] == ks.CLIENT_TYPE_SERVICE)
    ca_bundle_count = sum(1 for w in webhook_records if w["ca_bundle_present"])
    timeouts = [w["timeout_seconds"] for w in webhook_records if w["timeout_seconds"] is not None]

    admission_versions: set[str] = set()
    for w in webhook_records:
        admission_versions.update(w["admission_review_versions"])
    match_policies = {w["match_policy"] for w in webhook_records}
    reinvocation_policies = {w["reinvocation_policy"] for w in webhook_records if w["reinvocation_policy"]}

    if not webhook_records:
        posture = ks.WEBHOOK_SECURITY_POSTURE_UNKNOWN
    elif fail_open == len(webhook_records):
        posture = ks.WEBHOOK_SECURITY_POSTURE_FAIL_OPEN
    elif fail_closed == len(webhook_records):
        broad = any(
            w["wildcard_operation"] or w["wildcard_api_group"] or w["wildcard_resource"]
            for w in webhook_records
        )
        posture = ks.WEBHOOK_SECURITY_POSTURE_FAIL_CLOSED_BROAD if broad else ks.WEBHOOK_SECURITY_POSTURE_FAIL_CLOSED_NARROW
    else:
        posture = ks.WEBHOOK_SECURITY_POSTURE_MIXED

    fingerprint = stable_fingerprint(
        len(webhook_records), fail_open, fail_closed, sorted(admission_versions),
        sorted(match_policies), sorted(reinvocation_policies), ca_bundle_count,
    )

    record = {
        "record_type": (
            KUBERNETES_VALIDATING_WEBHOOK_CONFIGURATION if kind == "validating"
            else KUBERNETES_MUTATING_WEBHOOK_CONFIGURATION
        ),
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "name": name,
        "uid": uid,
        "kind": "ValidatingWebhookConfiguration" if kind == "validating" else "MutatingWebhookConfiguration",
        "webhook_count": len(webhook_records),
        "admission_review_version_categories": sorted(admission_versions),
        "fail_open_webhook_count": fail_open,
        "fail_closed_webhook_count": fail_closed,
        "no_side_effects_webhook_count": no_side_effects,
        "unknown_side_effects_webhook_count": unknown_side_effects,
        "namespace_selector_present_count": ns_selector_present,
        "object_selector_present_count": obj_selector_present,
        "external_url_client_count": external_url_count,
        "in_cluster_service_client_count": service_client_count,
        "ca_bundle_present_count": ca_bundle_count,
        "timeout_seconds_min": min(timeouts) if timeouts else None,
        "timeout_seconds_max": max(timeouts) if timeouts else None,
        "match_policy_categories": sorted(match_policies),
        "reinvocation_policy_categories": sorted(reinvocation_policies),
        "security_posture_summary": posture,
        "configuration_fingerprint": fingerprint,
        "collection_completeness_category": "complete",
    }
    return record, webhook_records


def _collect_webhook_configurations(
    list_fn: Callable[..., Any], *, kind: str, cluster_id: str, cluster_name: str,
) -> tuple[list[dict], list[dict], str]:
    raw_items, diag = paginate_list(list_fn)
    config_records: list[dict] = []
    webhook_records: list[dict] = []
    for item in raw_items:
        try:
            record, webhooks = _normalize_webhook_configuration(
                item, kind=kind, cluster_id=cluster_id, cluster_name=cluster_name,
            )
        except Exception:  # noqa: BLE001 — malformed configuration, skip it
            logger.info("Skipping malformed %s configuration", kind)
            continue
        config_records.append(record)
        webhook_records.extend(webhooks)

    status = _family_completeness_status(diag)
    for r in config_records:
        r["collection_completeness_category"] = status
    for r in webhook_records:
        r["collection_completeness_category"] = status
    config_records.sort(key=lambda r: r["name"])
    webhook_records.sort(key=lambda r: r["record_id"])
    return config_records, webhook_records, status


def _webhook_coverage_category(webhook_records: list[dict]) -> str:
    """Cluster-wide coverage category (applied to every namespace's
    governance rollup, since resolving exact per-namespace applicability
    for a narrow-selector webhook would require evaluating arbitrary
    namespace labels, which this connector never persists). "full" only
    when at least one webhook has no selector restriction (applies to
    every namespace); otherwise "partial" — never silently assumed full."""
    if not webhook_records:
        return "none"
    if any(w["namespace_selector_category"] in (ks.SELECTOR_ABSENT, ks.SELECTOR_EMPTY_ALL) for w in webhook_records):
        return "full"
    return "partial"


# ── Pod Security Admission posture ────────────────────────────────────────────

def _normalize_pod_security_admission(
    namespace_record: dict, *, cluster_id: str, cluster_name: str, cluster_major_minor: Optional[str],
) -> dict:
    ns_name = namespace_record["name"]
    enforce = ks.categorize_psa_level(namespace_record.get("psa_enforce"))
    audit = ks.categorize_psa_level(namespace_record.get("psa_audit"))
    warn = ks.categorize_psa_level(namespace_record.get("psa_warn"))
    enforce_version_cat = ks.categorize_psa_version(namespace_record.get("psa_enforce_version"), cluster_major_minor)
    audit_version_cat = ks.categorize_psa_version(namespace_record.get("psa_audit_version"), cluster_major_minor)
    warn_version_cat = ks.categorize_psa_version(namespace_record.get("psa_warn_version"), cluster_major_minor)

    enforcement_enabled = enforce != ks.PSA_ENFORCE_CATEGORY_UNSET
    audit_enabled = audit != ks.PSA_ENFORCE_CATEGORY_UNSET
    warning_enabled = warn != ks.PSA_ENFORCE_CATEGORY_UNSET

    enforce_rank = ks.PSA_LEVEL_RANK.get(enforce, 0)
    weaker_than_audit = audit_enabled and enforce_rank < ks.PSA_LEVEL_RANK.get(audit, 0)
    weaker_than_warn = warning_enabled and enforce_rank < ks.PSA_LEVEL_RANK.get(warn, 0)

    record_id = f"{cluster_id}/pod_security_admission/{ns_name}"
    fingerprint = stable_fingerprint(enforce, enforce_version_cat, audit, audit_version_cat, warn, warn_version_cat)

    return {
        "record_type": KUBERNETES_POD_SECURITY_ADMISSION,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": ns_name,
        "enforce_level": enforce,
        "enforce_version_category": enforce_version_cat,
        "audit_level": audit,
        "audit_version_category": audit_version_cat,
        "warn_level": warn,
        "warn_version_category": warn_version_cat,
        "effective_posture_category": enforce,
        "enforcement_enabled": enforcement_enabled,
        "audit_enabled": audit_enabled,
        "warning_enabled": warning_enabled,
        "enforcement_weaker_than_audit": weaker_than_audit,
        "enforcement_weaker_than_warning": weaker_than_warn,
        "namespace_context_category": ks.categorize_namespace_context(ns_name),
        "posture_fingerprint": fingerprint,
        "collection_completeness_category": "complete",
    }


def _build_pod_security_admission_records(
    namespace_records: list[dict], *, cluster_id: str, cluster_name: str, cluster_major_minor: Optional[str],
) -> list[dict]:
    records = [
        _normalize_pod_security_admission(
            ns, cluster_id=cluster_id, cluster_name=cluster_name, cluster_major_minor=cluster_major_minor,
        )
        for ns in namespace_records
    ]
    records.sort(key=lambda r: r["namespace"])
    return records


# ── ResourceQuota ──────────────────────────────────────────────────────────────

_QUOTA_SERVICES_KEY = "services"
_QUOTA_LOAD_BALANCER_KEY = "services.loadbalancers"
_QUOTA_PVC_KEY = "persistentvolumeclaims"
_QUOTA_STORAGE_REQUEST_KEY = "requests.storage"
_QUOTA_EPHEMERAL_STORAGE_KEYS = ("ephemeral-storage", "limits.ephemeral-storage", "requests.ephemeral-storage")
_QUOTA_SECRET_KEYS = ("count/secrets", "secrets")
_QUOTA_CONFIGMAP_KEYS = ("count/configmaps", "configmaps")


def _normalize_resource_quota(obj: Any, *, cluster_id: str, cluster_name: str) -> dict:
    metadata = obj.metadata
    namespace = metadata.namespace
    name = metadata.name
    uid = getattr(metadata, "uid", None)
    spec = getattr(obj, "spec", None)
    hard = getattr(spec, "hard", None) or {}
    scopes = getattr(spec, "scopes", None) or []
    scope_selector = getattr(spec, "scope_selector", None)

    def _first_present(keys: tuple[str, ...]) -> Optional[str]:
        for k in keys:
            if k in hard:
                return hard[k]
        return None

    cpu_raw = _first_present(ks._QUOTA_CPU_KEYS)
    request_cpu_raw = _first_present(ks._QUOTA_CPU_REQUEST_KEYS)
    memory_raw = _first_present(ks._QUOTA_MEMORY_KEYS)
    request_memory_raw = _first_present(ks._QUOTA_MEMORY_REQUEST_KEYS)

    pod_count = None
    if "pods" in hard:
        try:
            pod_count = int(str(hard["pods"]))
        except (ValueError, TypeError):
            pod_count = None

    hard_cpu_present = ks._quantity_present(hard, ks._QUOTA_CPU_KEYS)
    hard_memory_present = ks._quantity_present(hard, ks._QUOTA_MEMORY_KEYS)
    request_cpu_present = ks._quantity_present(hard, ks._QUOTA_CPU_REQUEST_KEYS)
    request_memory_present = ks._quantity_present(hard, ks._QUOTA_MEMORY_REQUEST_KEYS)
    pod_count_present = "pods" in hard
    service_count_present = _QUOTA_SERVICES_KEY in hard
    lb_count_present = _QUOTA_LOAD_BALANCER_KEY in hard
    pvc_count_present = _QUOTA_PVC_KEY in hard
    storage_request_present = _QUOTA_STORAGE_REQUEST_KEY in hard
    ephemeral_present = ks._quantity_present(hard, _QUOTA_EPHEMERAL_STORAGE_KEYS)
    secret_count_present = ks._quantity_present(hard, _QUOTA_SECRET_KEYS)
    configmap_count_present = ks._quantity_present(hard, _QUOTA_CONFIGMAP_KEYS)

    coverage_flags = [
        hard_cpu_present, hard_memory_present, request_cpu_present, request_memory_present,
        pod_count_present, service_count_present, lb_count_present, pvc_count_present,
        storage_request_present, ephemeral_present, secret_count_present, configmap_count_present,
    ]
    covered = sum(coverage_flags)
    if covered == 0:
        coverage = ks.POLICY_COVERAGE_NONE
    elif covered >= 4:
        coverage = ks.POLICY_COVERAGE_BROAD
    else:
        coverage = ks.POLICY_COVERAGE_PARTIAL

    record_id = f"{cluster_id}/resource_quota/{namespace}/{uid or name}"
    fingerprint = stable_fingerprint(
        hard_cpu_present, hard_memory_present, request_cpu_present, request_memory_present,
        pod_count, service_count_present, lb_count_present, pvc_count_present,
        storage_request_present, ephemeral_present, secret_count_present, configmap_count_present,
        sorted(scopes), scope_selector is not None,
    )

    return {
        "record_type": KUBERNETES_RESOURCE_QUOTA,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "name": name,
        "uid": uid,
        "hard_limit_key_count": len(hard),
        "hard_cpu_limit_present": hard_cpu_present,
        "hard_cpu_limit_millicores": parse_cpu_quantity_millicores(cpu_raw) if hard_cpu_present else None,
        "hard_memory_limit_present": hard_memory_present,
        "hard_memory_limit_bytes": parse_memory_quantity_bytes(memory_raw) if hard_memory_present else None,
        "request_cpu_limit_present": request_cpu_present,
        "request_cpu_limit_millicores": parse_cpu_quantity_millicores(request_cpu_raw) if request_cpu_present else None,
        "request_memory_limit_present": request_memory_present,
        "request_memory_limit_bytes": parse_memory_quantity_bytes(request_memory_raw) if request_memory_present else None,
        "pod_count_limit_present": pod_count_present,
        "pod_count_limit": pod_count,
        "service_count_limit_present": service_count_present,
        "load_balancer_count_limit_present": lb_count_present,
        "pvc_count_limit_present": pvc_count_present,
        "storage_request_limit_present": storage_request_present,
        "ephemeral_storage_limit_present": ephemeral_present,
        "secret_count_limit_present": secret_count_present,
        "configmap_count_limit_present": configmap_count_present,
        "scope_categories": sorted(scopes),
        "scope_selector_present": scope_selector is not None,
        "resource_control_coverage_category": coverage,
        "quota_fingerprint": fingerprint,
        "collection_completeness_category": "complete",
    }


def _collect_resource_quotas(
    list_fn: Callable[..., Any], *, cluster_id: str, cluster_name: str,
    namespace_allowlist: Optional[list[str]],
) -> tuple[list[dict], str]:
    raw_items, diag = paginate_list(list_fn)
    records: list[dict] = []
    for item in raw_items:
        try:
            ns = item.metadata.namespace
        except Exception:  # noqa: BLE001
            continue
        if namespace_allowlist is not None and ns not in namespace_allowlist:
            continue
        try:
            records.append(_normalize_resource_quota(item, cluster_id=cluster_id, cluster_name=cluster_name))
        except Exception:  # noqa: BLE001
            continue

    status = _family_completeness_status(diag)
    for r in records:
        r["collection_completeness_category"] = status
    records.sort(key=lambda r: (r["namespace"], r["name"]))
    return records, status


# ── LimitRange ─────────────────────────────────────────────────────────────────

def _normalize_limit_range(obj: Any, *, cluster_id: str, cluster_name: str) -> dict:
    metadata = obj.metadata
    namespace = metadata.namespace
    name = metadata.name
    uid = getattr(metadata, "uid", None)
    spec = getattr(obj, "spec", None)
    items = getattr(spec, "limits", None) or []

    container_default_present = container_default_request_present = False
    pod_max_present = pod_min_present = False
    container_max_present = container_min_present = False
    pvc_min_present = pvc_max_present = False
    ratio_present = False
    cpu_seen: set[str] = set()
    memory_seen: set[str] = set()
    ephemeral_seen: set[str] = set()

    for item in items:
        try:
            item_type = getattr(item, "type", None)
            default = getattr(item, "default", None) or {}
            default_request = getattr(item, "default_request", None) or {}
            max_ = getattr(item, "max", None) or {}
            min_ = getattr(item, "min", None) or {}
            ratio = getattr(item, "max_limit_request_ratio", None) or {}
        except Exception:  # noqa: BLE001 — malformed item, skip it
            continue

        if item_type == ks.LIMIT_RANGE_TYPE_CONTAINER:
            container_default_present = container_default_present or bool(default)
            container_default_request_present = container_default_request_present or bool(default_request)
            container_max_present = container_max_present or bool(max_)
            container_min_present = container_min_present or bool(min_)
        elif item_type == ks.LIMIT_RANGE_TYPE_POD:
            pod_max_present = pod_max_present or bool(max_)
            pod_min_present = pod_min_present or bool(min_)
        elif item_type == ks.LIMIT_RANGE_TYPE_PVC:
            pvc_min_present = pvc_min_present or bool(min_)
            pvc_max_present = pvc_max_present or bool(max_)

        ratio_present = ratio_present or bool(ratio)

        for bucket, field_dict in (
            ("default", default), ("default_request", default_request), ("max", max_), ("min", min_),
        ):
            if "cpu" in field_dict:
                cpu_seen.add(bucket)
            if "memory" in field_dict:
                memory_seen.add(bucket)
            if "ephemeral-storage" in field_dict:
                ephemeral_seen.add(bucket)

    def _coverage(seen: set) -> str:
        if not seen:
            return ks.POLICY_COVERAGE_NONE
        if len(seen) >= 3:
            return ks.POLICY_COVERAGE_BROAD
        return ks.POLICY_COVERAGE_PARTIAL

    cpu_coverage = _coverage(cpu_seen)
    memory_coverage = _coverage(memory_seen)
    ephemeral_coverage = _coverage(ephemeral_seen)

    defaulting_true_count = sum([
        container_default_present, container_default_request_present,
        pod_max_present, pod_min_present, container_max_present, container_min_present,
    ])
    if defaulting_true_count == 0:
        defaulting_coverage = ks.POLICY_COVERAGE_NONE
    elif defaulting_true_count >= 4:
        defaulting_coverage = ks.POLICY_COVERAGE_BROAD
    else:
        defaulting_coverage = ks.POLICY_COVERAGE_PARTIAL

    record_id = f"{cluster_id}/limit_range/{namespace}/{uid or name}"
    fingerprint = stable_fingerprint(
        container_default_present, container_default_request_present, pod_max_present, pod_min_present,
        container_max_present, container_min_present, pvc_min_present, pvc_max_present, ratio_present,
        cpu_coverage, memory_coverage, ephemeral_coverage,
    )

    return {
        "record_type": KUBERNETES_LIMIT_RANGE,
        "record_id": record_id,
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "namespace": namespace,
        "name": name,
        "uid": uid,
        "item_count": len(items),
        "container_default_present": container_default_present,
        "container_default_request_present": container_default_request_present,
        "pod_max_present": pod_max_present,
        "pod_min_present": pod_min_present,
        "container_max_present": container_max_present,
        "container_min_present": container_min_present,
        "pvc_min_present": pvc_min_present,
        "pvc_max_present": pvc_max_present,
        "request_to_limit_ratio_present": ratio_present,
        "cpu_policy_coverage_category": cpu_coverage,
        "memory_policy_coverage_category": memory_coverage,
        "ephemeral_storage_policy_coverage_category": ephemeral_coverage,
        "defaulting_coverage_category": defaulting_coverage,
        "limit_fingerprint": fingerprint,
        "collection_completeness_category": "complete",
    }


def _collect_limit_ranges(
    list_fn: Callable[..., Any], *, cluster_id: str, cluster_name: str,
    namespace_allowlist: Optional[list[str]],
) -> tuple[list[dict], str]:
    raw_items, diag = paginate_list(list_fn)
    records: list[dict] = []
    for item in raw_items:
        try:
            ns = item.metadata.namespace
        except Exception:  # noqa: BLE001
            continue
        if namespace_allowlist is not None and ns not in namespace_allowlist:
            continue
        try:
            records.append(_normalize_limit_range(item, cluster_id=cluster_id, cluster_name=cluster_name))
        except Exception:  # noqa: BLE001
            continue

    status = _family_completeness_status(diag)
    for r in records:
        r["collection_completeness_category"] = status
    records.sort(key=lambda r: (r["namespace"], r["name"]))
    return records, status


# ── Namespace governance rollup ───────────────────────────────────────────────

def _build_namespace_governance_postures(
    *,
    namespace_records: list[dict],
    psa_records: list[dict],
    validating_webhook_records: list[dict],
    mutating_webhook_records: list[dict],
    quota_records: list[dict],
    limit_range_records: list[dict],
    network_posture_records: list[dict],
    workload_records: list[dict],
    service_account_records: list[dict],
    cluster_id: str,
    cluster_name: str,
    admission_collection_status: str,
    quota_collection_status: str,
    limit_range_collection_status: str,
) -> list[dict]:
    """Compact cross-control rollup — NOT a Finding engine (message 6 owns
    that). Represents webhook coverage as full/partial/unknown rather than
    resolving exact per-namespace label-selector applicability, since
    arbitrary namespace labels are never persisted."""
    psa_by_ns = {p["namespace"]: p for p in psa_records}
    quota_count_by_ns: dict[str, int] = {}
    for q in quota_records:
        quota_count_by_ns[q["namespace"]] = quota_count_by_ns.get(q["namespace"], 0) + 1
    limit_count_by_ns: dict[str, int] = {}
    for lr in limit_range_records:
        limit_count_by_ns[lr["namespace"]] = limit_count_by_ns.get(lr["namespace"], 0) + 1
    netpost_by_ns = {n["namespace"]: n for n in network_posture_records}
    privileged_ns = {
        w["namespace"] for w in workload_records
        if w.get("security_posture_summary") == SECURITY_POSTURE_PRIVILEGED_OR_HOST_ACCESS
    }
    high_priv_sa_ns = {
        sa["namespace"] for sa in service_account_records
        if sa.get("cluster_admin_bound") or sa.get("highest_privilege_category") in ("high", "critical")
    }

    validating_coverage = _webhook_coverage_category(validating_webhook_records)
    mutating_coverage = _webhook_coverage_category(mutating_webhook_records)

    records: list[dict] = []
    for ns in namespace_records:
        ns_name = ns["name"]
        psa = psa_by_ns.get(ns_name)
        psa_category = psa["enforce_level"] if psa else "unknown"
        quota_count = quota_count_by_ns.get(ns_name, 0)
        limit_count = limit_count_by_ns.get(ns_name, 0)
        netpost = netpost_by_ns.get(ns_name)
        net_coverage = netpost["policy_coverage_category"] if netpost else "unknown"
        privileged_present = ns_name in privileged_ns
        high_priv_present = ns_name in high_priv_sa_ns

        if quota_collection_status == "partial" or limit_range_collection_status == "partial":
            quota_coverage = "unknown"
        elif quota_count == 0 and limit_count == 0:
            quota_coverage = "none"
        elif quota_count > 0 and limit_count > 0:
            quota_coverage = "broad"
        else:
            quota_coverage = "partial"

        default_resource_control = "present" if limit_count > 0 else "absent"
        governance_completeness = (
            "partial" if "partial" in (admission_collection_status, quota_collection_status, limit_range_collection_status)
            else "complete"
        )

        risk_bits: list[str] = []
        if privileged_present and psa_category in (
            ks.PSA_ENFORCE_CATEGORY_PRIVILEGED, ks.PSA_ENFORCE_CATEGORY_UNSET, ks.PSA_ENFORCE_CATEGORY_INVALID,
        ):
            risk_bits.append("privileged_workload_weak_psa")
        if high_priv_present and net_coverage in ("none", "partial") and quota_coverage == "none":
            risk_bits.append("high_privilege_identity_weak_governance")
        governance_risk_summary = ",".join(sorted(risk_bits)) if risk_bits else "standard"

        records.append({
            "record_type": KUBERNETES_NAMESPACE_GOVERNANCE_POSTURE,
            "record_id": f"{cluster_id}/namespace_governance_posture/{ns_name}",
            "cluster_id": cluster_id,
            "cluster_name": cluster_name,
            "namespace": ns_name,
            "psa_enforcement_category": psa_category,
            "validating_webhook_coverage_category": validating_coverage,
            "mutating_webhook_coverage_category": mutating_coverage,
            "resource_quota_count": quota_count,
            "limit_range_count": limit_count,
            "quota_coverage_category": quota_coverage,
            "default_resource_control_category": default_resource_control,
            "network_policy_coverage_category": net_coverage,
            "privileged_workload_present": privileged_present,
            "high_privilege_service_account_present": high_priv_present,
            "governance_completeness_category": governance_completeness,
            "governance_risk_summary": governance_risk_summary,
        })
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

            # ── RBAC and identity (message 3) ────────────────────────────────
            # ClusterRoles are collected first (needed to resolve both
            # RoleBindings-to-ClusterRoles and ClusterRoleBindings). Each
            # family remains independently fail-soft: a 403 on one never
            # affects another, and an unresolved roleRef is never silently
            # treated as safe/low privilege.
            rbac_v1 = k8s_client.RbacAuthorizationV1Api(api_client)

            cluster_role_records, cluster_role_status, cluster_role_index = _collect_cluster_roles(
                rbac_v1.list_cluster_role, cluster_id=cluster_id, cluster_name=display_cluster_name,
            )
            role_records, role_status, role_index = _collect_roles(
                rbac_v1.list_role_for_all_namespaces,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )
            combined_role_index = {**cluster_role_index, **role_index}
            roles_collection_denied = cluster_role_status == "partial" or role_status == "partial"

            service_account_full_records, sa_collection_status = _collect_service_accounts(
                core_v1.list_service_account_for_all_namespaces,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )

            role_binding_records, role_binding_subject_records, role_binding_status = _collect_rbac_bindings(
                rbac_v1.list_role_binding_for_all_namespaces,
                kind="RoleBinding", cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist, role_index=combined_role_index,
                role_collection_denied=roles_collection_denied,
            )
            cluster_role_binding_records, cluster_role_binding_subject_records, cluster_role_binding_status = (
                _collect_rbac_bindings(
                    rbac_v1.list_cluster_role_binding,
                    kind="ClusterRoleBinding", cluster_id=cluster_id, cluster_name=display_cluster_name,
                    namespace_allowlist=allowlist, role_index=combined_role_index,
                    role_collection_denied=roles_collection_denied,
                )
            )

            if "partial" in (
                cluster_role_status, role_status, sa_collection_status,
                role_binding_status, cluster_role_binding_status,
            ):
                partial_permission = True

            all_subject_binding_records = role_binding_subject_records + cluster_role_binding_subject_records

            _enrich_service_accounts(
                service_account_full_records, all_subject_binding_records, all_workload_records,
            )
            _enrich_workload_service_accounts(
                service_account_records, service_account_full_records, sa_collection_status,
            )
            rbac_permission_summary_records = _build_rbac_permission_summaries(
                all_subject_binding_records, cluster_id=cluster_id, cluster_name=display_cluster_name,
            )

            all_rbac_records = (
                service_account_full_records + role_records + cluster_role_records
                + role_binding_records + cluster_role_binding_records
                + all_subject_binding_records + rbac_permission_summary_records
            )

            # ── Network exposure and isolation (message 4) ───────────────────
            # Each family is collected independently; Gateway API's absence
            # (no CRDs installed) is "unsupported", never an error, and
            # never suppresses Service/Ingress/NetworkPolicy collection.
            networking_v1 = k8s_client.NetworkingV1Api(api_client)
            custom_objects_api = k8s_client.CustomObjectsApi(api_client)

            service_records, service_port_records, service_status = _collect_services(
                core_v1.list_service_for_all_namespaces,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )
            ingress_records, ingress_rule_records, ingress_status = _collect_ingresses(
                networking_v1.list_ingress_for_all_namespaces,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )
            gateway_records, gateway_listener_records, gateway_status = _collect_gateways(
                custom_objects_api, cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )
            http_route_records, http_route_rule_records, http_route_status = _collect_http_routes(
                custom_objects_api, cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )
            network_policy_records, network_policy_status = _collect_network_policies(
                networking_v1.list_network_policy_for_all_namespaces,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )

            # Gateway API "unsupported" (CRDs absent) never marks the
            # overall cluster collection partial — only a real error does.
            if "partial" in (service_status, ingress_status, network_policy_status):
                partial_permission = True
            if gateway_status == "partial" or http_route_status == "partial":
                partial_permission = True

            namespace_names_for_posture = [ns["name"] for ns in namespace_records]
            namespace_network_posture_records = _build_namespace_network_postures(
                network_policy_records, namespace_names_for_posture,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                collection_status=network_policy_status,
            )

            all_network_records = (
                service_records + service_port_records
                + ingress_records + ingress_rule_records
                + gateway_records + gateway_listener_records
                + http_route_records + http_route_rule_records
                + network_policy_records + namespace_network_posture_records
            )

            # ── Admission control and configuration governance (message 5) ──
            # ConfigMap and Secret metadata are deliberately NOT collected —
            # see this file's module docstring for the full safety review.
            admissionregistration_v1 = k8s_client.AdmissionregistrationV1Api(api_client)

            validating_config_records, validating_webhook_records, validating_status = _collect_webhook_configurations(
                admissionregistration_v1.list_validating_webhook_configuration,
                kind="validating", cluster_id=cluster_id, cluster_name=display_cluster_name,
            )
            mutating_config_records, mutating_webhook_records, mutating_status = _collect_webhook_configurations(
                admissionregistration_v1.list_mutating_webhook_configuration,
                kind="mutating", cluster_id=cluster_id, cluster_name=display_cluster_name,
            )
            resource_quota_records, resource_quota_status = _collect_resource_quotas(
                core_v1.list_resource_quota_for_all_namespaces,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )
            limit_range_records, limit_range_status = _collect_limit_ranges(
                core_v1.list_limit_range_for_all_namespaces,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                namespace_allowlist=allowlist,
            )
            pod_security_admission_records = _build_pod_security_admission_records(
                namespace_records, cluster_id=cluster_id, cluster_name=display_cluster_name,
                cluster_major_minor=major_minor(kubernetes_version),
            )

            if "partial" in (validating_status, mutating_status, resource_quota_status, limit_range_status):
                partial_permission = True

            namespace_governance_posture_records = _build_namespace_governance_postures(
                namespace_records=namespace_records,
                psa_records=pod_security_admission_records,
                validating_webhook_records=validating_webhook_records,
                mutating_webhook_records=mutating_webhook_records,
                quota_records=resource_quota_records,
                limit_range_records=limit_range_records,
                network_posture_records=namespace_network_posture_records,
                workload_records=all_workload_records,
                service_account_records=service_account_full_records,
                cluster_id=cluster_id, cluster_name=display_cluster_name,
                admission_collection_status=("partial" if validating_status == "partial" or mutating_status == "partial" else "complete"),
                quota_collection_status=resource_quota_status,
                limit_range_collection_status=limit_range_status,
            )

            all_admission_records = (
                validating_config_records + validating_webhook_records
                + mutating_config_records + mutating_webhook_records
                + pod_security_admission_records
                + resource_quota_records + limit_range_records
                + namespace_governance_posture_records
            )

            collection_completeness = "complete" if not partial_permission else "partial"

            # ── Family-level completeness map (message 8) ────────────────────
            #
            # Reliability-critical: this is the ONLY signal `compute_diff()`
            # uses to decide whether an absent kubernetes_* record reflects a
            # real deletion or a temporary/permission-related collection gap
            # for that record's family. It is intentionally carried as fields
            # on the always-present, real `kubernetes_cluster` record — never
            # as a synthetic/fake resource record of its own — so it never
            # shows up as if it were cluster configuration, and it diffs like
            # any other cluster-record field (routed through the existing
            # dedicated `_classify_cluster_change` classifier).
            #
            # Keyed by the exact `record_type` string so `compute_diff()` can
            # do a simple dict lookup per candidate-removed record. Namespaced
            # families are collected via a single cluster-wide List call in
            # the current architecture (never one call per namespace), so
            # "namespace partial" is not a distinct failure mode from "family
            # partial" today — seeing DIFFERENT per-namespace outcomes would
            # require N per-namespace API calls, which message 8 deliberately
            # does not introduce (would multiply API calls against real
            # clusters). Namespace-scoped safety is instead provided via
            # `configured_namespace_allowlist` below (see 13. namespace
            # allowlist behavior) — an allowlist shrink is a deliberate scope
            # change, not a signal that resources in the de-scoped namespace
            # were deleted from the cluster.
            family_completeness: dict[str, str] = {
                KUBERNETES_NAMESPACE: "complete" if ns_diag.complete else "partial",
                KUBERNETES_API_CAPABILITY: discovery_status,
                KUBERNETES_DEPLOYMENT: deployment_status,
                KUBERNETES_STATEFULSET: statefulset_status,
                KUBERNETES_DAEMONSET: daemonset_status,
                KUBERNETES_JOB: job_status,
                KUBERNETES_CRONJOB: cronjob_status,
                KUBERNETES_POD: pod_status,
                # Container/workload-service-account records are emitted only
                # alongside their parent workload family, so they share its
                # completeness rather than tracking a separate one.
                KUBERNETES_CONTAINER_SECURITY_CONTEXT: (
                    "partial" if "partial" in (
                        deployment_status, statefulset_status, daemonset_status,
                        job_status, cronjob_status, pod_status,
                    ) else "complete"
                ),
                KUBERNETES_WORKLOAD_SERVICE_ACCOUNT: (
                    "partial" if "partial" in (
                        deployment_status, statefulset_status, daemonset_status,
                        job_status, cronjob_status, pod_status,
                    ) else "complete"
                ),
                KUBERNETES_CLUSTER_ROLE: cluster_role_status,
                KUBERNETES_ROLE: role_status,
                KUBERNETES_SERVICE_ACCOUNT: sa_collection_status,
                KUBERNETES_ROLE_BINDING: role_binding_status,
                KUBERNETES_CLUSTER_ROLE_BINDING: cluster_role_binding_status,
                KUBERNETES_RBAC_SUBJECT_BINDING: (
                    "partial" if "partial" in (role_binding_status, cluster_role_binding_status) else "complete"
                ),
                KUBERNETES_RBAC_PERMISSION_SUMMARY: (
                    "partial" if "partial" in (
                        cluster_role_status, role_status, sa_collection_status,
                        role_binding_status, cluster_role_binding_status,
                    ) else "complete"
                ),
                KUBERNETES_SERVICE: service_status,
                KUBERNETES_SERVICE_PORT: service_status,
                KUBERNETES_INGRESS: ingress_status,
                KUBERNETES_INGRESS_RULE: ingress_status,
                KUBERNETES_GATEWAY: gateway_status,
                KUBERNETES_GATEWAY_LISTENER: gateway_status,
                KUBERNETES_HTTP_ROUTE: http_route_status,
                KUBERNETES_HTTP_ROUTE_RULE: http_route_status,
                KUBERNETES_NETWORK_POLICY: network_policy_status,
                KUBERNETES_NAMESPACE_NETWORK_POSTURE: (
                    "partial" if "partial" in (network_policy_status,) else "complete"
                ),
                KUBERNETES_VALIDATING_WEBHOOK_CONFIGURATION: validating_status,
                KUBERNETES_VALIDATING_WEBHOOK: validating_status,
                KUBERNETES_MUTATING_WEBHOOK_CONFIGURATION: mutating_status,
                KUBERNETES_MUTATING_WEBHOOK: mutating_status,
                KUBERNETES_POD_SECURITY_ADMISSION: "complete" if ns_diag.complete else "partial",
                KUBERNETES_RESOURCE_QUOTA: resource_quota_status,
                KUBERNETES_LIMIT_RANGE: limit_range_status,
                KUBERNETES_NAMESPACE_GOVERNANCE_POSTURE: (
                    "partial" if "partial" in (
                        validating_status, mutating_status, resource_quota_status,
                        limit_range_status, network_policy_status,
                    ) else "complete"
                ),
            }

            # Sorted allowlist snapshot (or None = unrestricted). Lets
            # `compute_diff()` distinguish "namespace de-scoped by an
            # intentional allowlist change" from "namespace's resources were
            # actually deleted" by comparing this field across two
            # consecutive kubernetes_cluster records.
            configured_namespace_allowlist = sorted(allowlist) if allowlist else None

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
                "family_completeness": family_completeness,
                "configured_namespace_allowlist": configured_namespace_allowlist,
            }

            return (
                [cluster_record] + selected_namespace_records + capability_records
                + all_workload_records + all_container_records + service_account_records
                + all_rbac_records + all_network_records + all_admission_records
            )
        finally:
            api_client.rest_client.pool_manager.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Permission diagnostics (message 8)
#
# A redacted, human-readable summary of what ConfigTrace could and could not
# read on a Kubernetes cluster — built entirely from the same normalized
# records `fetch()` already returns (or, for the "live" harness below, from a
# fresh `fetch()` call). Never re-fetches raw API responses, never includes
# a kubeconfig/token/certificate byte, and never reproduces a raw exception
# message (which could embed a request URL, query string, or internal host).
# ─────────────────────────────────────────────────────────────────────────────

# Friendly display names for the family_completeness keys, grouped exactly
# as the task's example report groups them (Namespaces/Workloads/RBAC/
# Networking/Admission). Order here defines report section order.
_DIAGNOSTIC_FAMILY_GROUPS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    ("Namespaces", ((KUBERNETES_NAMESPACE, "Namespaces"),)),
    ("Workloads", (
        (KUBERNETES_DEPLOYMENT, "Deployments"),
        (KUBERNETES_STATEFULSET, "StatefulSets"),
        (KUBERNETES_DAEMONSET, "DaemonSets"),
        (KUBERNETES_JOB, "Jobs"),
        (KUBERNETES_CRONJOB, "CronJobs"),
        (KUBERNETES_POD, "standalone Pods"),
    )),
    ("RBAC", (
        (KUBERNETES_ROLE, "Roles"),
        (KUBERNETES_CLUSTER_ROLE, "ClusterRoles"),
        (KUBERNETES_ROLE_BINDING, "RoleBindings"),
        (KUBERNETES_CLUSTER_ROLE_BINDING, "ClusterRoleBindings"),
        (KUBERNETES_SERVICE_ACCOUNT, "ServiceAccounts"),
    )),
    ("Networking", (
        (KUBERNETES_SERVICE, "Services"),
        (KUBERNETES_INGRESS, "Ingresses"),
        (KUBERNETES_GATEWAY, "Gateway API"),
        (KUBERNETES_HTTP_ROUTE, "HTTPRoutes"),
        (KUBERNETES_NETWORK_POLICY, "NetworkPolicies"),
    )),
    ("Admission", (
        (KUBERNETES_VALIDATING_WEBHOOK_CONFIGURATION, "Validating webhooks"),
        (KUBERNETES_MUTATING_WEBHOOK_CONFIGURATION, "Mutating webhooks"),
        (KUBERNETES_POD_SECURITY_ADMISSION, "Pod Security Admission"),
        (KUBERNETES_RESOURCE_QUOTA, "ResourceQuotas"),
        (KUBERNETES_LIMIT_RANGE, "LimitRanges"),
    )),
)

_DIAGNOSTIC_STATUS_LABEL = {
    "complete": "available",
    "partial": "partially available",
    "unsupported": "unsupported (API group not present on this cluster)",
    "unknown": "status unknown",
}


def build_permission_diagnostics(records: list[dict]) -> dict:
    """Build a redacted, user-facing permission/coverage diagnostics report
    from a normalized Kubernetes record list (the output of ``fetch()``).

    Never includes kubeconfig content, tokens, certificate bytes, private
    keys, Secret/ConfigMap contents, or arbitrary raw API payloads/URLs —
    only category labels, booleans, and counts already present on the
    ``kubernetes_cluster`` record's ``family_completeness`` map.
    """
    cluster_record = next((r for r in records if r.get("record_type") == KUBERNETES_CLUSTER), None)
    if cluster_record is None:
        return {
            "cluster_reachable": False,
            "coverage": "unavailable",
            "sections": [],
            "security_findings_note": (
                "Security Findings were not evaluated — the cluster could not be reached."
            ),
            "change_detection_note": "Change detection is unavailable without a successful sync.",
        }

    family_completeness = cluster_record.get("family_completeness") or {}
    sections: list[dict] = []
    any_partial = cluster_record.get("partial_permission_indicator") is True
    for section_name, families in _DIAGNOSTIC_FAMILY_GROUPS:
        entries = []
        for record_type, label in families:
            status = family_completeness.get(record_type, "unknown")
            entries.append({
                "resource": label,
                "status": status,
                "status_label": _DIAGNOSTIC_STATUS_LABEL.get(status, "status unknown"),
            })
            if status not in ("complete",):
                any_partial = True
        sections.append({"name": section_name, "resources": entries})

    coverage = "partial" if any_partial else "complete"

    return {
        "cluster_reachable": True,
        "cluster_id": cluster_record.get("cluster_id"),
        "cluster_name": cluster_record.get("cluster_name"),
        "kubernetes_version": cluster_record.get("kubernetes_version"),
        "api_server_host_category": cluster_record.get("api_server_host_category"),
        "server_certificate_verification_enabled": cluster_record.get(
            "server_certificate_verification_enabled"
        ),
        "namespace_scope": (
            "all namespaces" if not cluster_record.get("configured_namespace_allowlist")
            else f"{len(cluster_record['configured_namespace_allowlist'])} allowlisted namespace(s)"
        ),
        "sections": sections,
        "coverage": coverage,
        "security_findings_note": (
            "Security Findings are evaluated only for resources ConfigTrace could read; "
            "denied/unsupported families are excluded, never assumed safe."
        ),
        "change_detection_note": (
            "Change detection is available for every family marked available above; "
            "denied/unsupported/partial families never generate false removal Changes."
        ),
        "record_count": len(records),
    }


def format_permission_diagnostics_text(report: dict) -> str:
    """Render ``build_permission_diagnostics()``'s output as the plain-text
    report shape shown in the message-8 task description. Purely a display
    helper — contains no information not already in the structured report."""
    if not report.get("cluster_reachable"):
        return "Kubernetes connection could not be validated.\n\n" + report.get("security_findings_note", "")

    lines = ["Kubernetes connection validated", "", "Cluster:", "  reachable"]
    for section in report["sections"]:
        lines.append("")
        lines.append(f"{section['name']}:")
        for entry in section["resources"]:
            lines.append(f"  {entry['resource']}: {entry['status_label']}")
    lines.append("")
    lines.append(f"Coverage:\n  {report['coverage'].capitalize()}")
    lines.append("")
    lines.append(f"Security Findings:\n  {report['security_findings_note']}")
    return "\n".join(lines)


def run_live_kubernetes_validation(kubeconfig_path: str, *, context_name: Optional[str] = None) -> dict:
    """Live-cluster validation harness (message 8).

    Loads a real kubeconfig from *kubeconfig_path*, runs the same
    ``KubernetesConnector.fetch()`` pipeline used in production, and returns
    a redacted diagnostics report via ``build_permission_diagnostics()``.

    Intended for local/manual use against a real cluster (kind/minikube/k3d
    or any reachable cluster) — never invoked automatically in CI. Callers
    are expected to gate invocation behind an opt-in environment variable
    (see ``CONFIGTRACE_KUBERNETES_LIVE_KUBECONFIG`` in the test suite) so
    normal test runs never require or read a real kubeconfig.
    """
    with open(kubeconfig_path, "r", encoding="utf-8") as fh:
        kubeconfig_content = fh.read()

    credentials = {"kubeconfig": kubeconfig_content}
    if context_name:
        credentials["context"] = context_name

    connector = KubernetesConnector()
    records = connector.fetch(credentials)
    report = build_permission_diagnostics(records)
    report["records_observed_count"] = len(records)
    return report
