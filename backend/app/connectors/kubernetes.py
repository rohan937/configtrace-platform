"""Kubernetes connector — foundation (message 1 of a 9-message arc).

This connector establishes the durable architecture for the Kubernetes
provider: client initialization, cluster identity, namespace scoping, API
discovery, a fail-soft API-call wrapper, and a pagination helper. Only three
record types are emitted (``kubernetes_cluster``, ``kubernetes_namespace``,
``kubernetes_api_capability`` — see ``kubernetes_schema.py``). Workload,
RBAC, networking, and admission-control collection are NOT implemented yet;
they are built in later messages against this same foundation.

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
    KUBERNETES_API_CAPABILITY,
    KUBERNETES_CLUSTER,
    KUBERNETES_NAMESPACE,
    PSA_LABEL_AUDIT,
    PSA_LABEL_AUDIT_VERSION,
    PSA_LABEL_ENFORCE,
    PSA_LABEL_ENFORCE_VERSION,
    PSA_LABEL_WARN,
    PSA_LABEL_WARN_VERSION,
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

            return [cluster_record] + selected_namespace_records + capability_records
        finally:
            api_client.rest_client.pool_manager.clear()
