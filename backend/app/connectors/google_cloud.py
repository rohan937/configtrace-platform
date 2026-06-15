"""Google Cloud drift provider connector — M78A: Project, IAM policy summary,
VPC networks, firewall rules, Cloud Storage buckets.

Fetches safe configuration metadata from the Google Cloud REST APIs using a
service-account credential and the RFC 7523 JWT bearer flow against
``https://oauth2.googleapis.com/token`` (mirroring the existing Firebase
connector pattern at ``app/connectors/firebase.py``). The access token is
short-lived and scoped to read-only Cloud Resource Manager / Compute /
Storage APIs.

PRIVACY / SECURITY — what is NEVER stored or logged
----------------------------------------------------
- service_account_json, private_key, private_key_id, OAuth bearer tokens,
  refresh tokens, or any signed JWT assertion material.
- Raw HTTP request or response bodies.
- IAM principal identities: member emails (user, serviceAccount, group,
  domain), object IDs, or any field that could re-identify a person.
- The raw IAM `bindings` array or the policy `etag`.
- IAM condition expressions (CEL strings may carry sensitive resource IDs).
- Cloud Storage object names, object contents, customer-supplied encryption
  keys, signed URLs, HMAC keys, or bucket ACL grantee identities.
- Cloud SQL admin login names, passwords, database row data, or connection
  strings (Cloud SQL is deferred to M78C anyway).
- VPC flow log packets or any /proxy data-plane traffic.
- Project label VALUES (user-controlled and may contain PII or secrets);
  only label KEY names are stored.
- IP addresses unless safely coarsened.

Records fetched (M78A only)
---------------------------
GOOGLE_CLOUD_PROJECT
    Safe fields: project_id, project_number, display_name, lifecycle_state,
    parent_type (organization/folder/none — never the parent id), create_time,
    label_keys (key names only).

GOOGLE_CLOUD_IAM_POLICY_SUMMARY
    Safe fields: project_id, binding_count, role_count, role_names (capped at
    20; well-known canonical strings only), broad_role_count, user_member_count,
    group_member_count, service_account_member_count, domain_member_count,
    allusers_binding_present, allauthenticatedusers_binding_present,
    conditional_binding_count.

GOOGLE_CLOUD_VPC_NETWORK
    Safe fields: network_id (selfLink), network_name, auto_create_subnetworks,
    routing_mode, mtu, subnet_count, peering_count.

GOOGLE_CLOUD_FIREWALL_RULE
    Safe fields: firewall_id (selfLink), firewall_name, network_name,
    direction, priority, disabled, source_ranges_summary (capped at 20),
    destination_ranges_summary (capped at 20), allowed_summary (per-rule
    IPProtocol + ports capped), denied_summary, target_tag_count,
    target_service_account_count (count only — emails never stored),
    has_log_config (bool).

GOOGLE_CLOUD_STORAGE_BUCKET
    Safe fields: bucket_id, bucket_name, location, location_type,
    storage_class, uniform_bucket_level_access_enabled, public_access_prevention,
    versioning_enabled, retention_policy_seconds, retention_policy_locked,
    lifecycle_rule_count, encryption_default_kms_key_present (bool),
    iam_configuration_summary (uniform_access + public_access_prevention).

Deferred (not in M78A)
-----------------------
Cloud SQL instances, Cloud Run services, GKE clusters, Service Account keys,
and Secret Manager secrets — see the M78C scope in
``google_cloud_schema.py``.

Auth / credentials dict
-----------------------
    service_account_json : dict | str  — full service-account JSON. If passed
                                          as a string it is parsed to a dict
                                          once per call and never logged.
    project_id           : str          — Google Cloud project ID to monitor.
                                          Optional override; if absent, the
                                          ``project_id`` field of the service
                                          account JSON is used.

The service account must have at MINIMUM the following read-only roles on the
target project: ``roles/viewer`` (or the surface-specific viewer roles:
``roles/resourcemanager.projectViewer``,
``roles/compute.viewer``, ``roles/storage.objectViewer``). This connector
never performs a write/delete operation against any Google Cloud API.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.google_cloud_schema import (
    GOOGLE_CLOUD_FIREWALL_RULE,
    GOOGLE_CLOUD_IAM_POLICY_SUMMARY,
    GOOGLE_CLOUD_PROJECT,
    GOOGLE_CLOUD_STORAGE_BUCKET,
    GOOGLE_CLOUD_VPC_NETWORK,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ────────────────────────────────────────────────────

_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"

# Read-only OAuth scopes (project metadata + IAM + Compute + Storage).
# We deliberately scope these to the smallest set needed for the five M78A
# surfaces; future Cloud SQL / Cloud Run / GKE surfaces will request scope
# extensions in M78C.
_SCOPES: tuple[str, ...] = (
    "https://www.googleapis.com/auth/cloud-platform.read-only",
)

_CRM_BASE = "https://cloudresourcemanager.googleapis.com"
_COMPUTE_BASE = "https://compute.googleapis.com"
_STORAGE_BASE = "https://storage.googleapis.com"

_TIMEOUT = 30.0
_MAX_PAGES = 10
_MAX_STR_LEN = 200

# Per-surface caps (mirror Azure's per-surface caps).
_MAX_FIREWALL_RULES = 200
_MAX_VPC_NETWORKS = 50
_MAX_STORAGE_BUCKETS = 200
# IAM policy summary caps: at most 20 role names surfaced and at most 100
# bindings considered before stopping the principal-type bucketing.
_MAX_IAM_ROLE_NAMES = 20
_MAX_IAM_BINDINGS_SCANNED = 100
# Per-firewall-rule summarisation caps.
_MAX_FW_RANGES_PER_RULE = 20
_MAX_FW_ALLOWED_PER_RULE = 20

# Well-known broad / privileged IAM role names that warrant counting
# separately for M78A drift posture. These are public Google role names —
# storing them is no different from storing well-known Azure role names.
_BROAD_IAM_ROLES: frozenset[str] = frozenset({
    "roles/owner",
    "roles/editor",
    "roles/viewer",
    "roles/iam.securityAdmin",
    "roles/iam.organizationRoleAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/resourcemanager.organizationAdmin",
    "roles/resourcemanager.folderAdmin",
    "roles/resourcemanager.projectIamAdmin",
})


# ── String safety helper ──────────────────────────────────────────────────────


def _trunc(value: Any) -> Any:
    """Truncate string values to _MAX_STR_LEN characters; pass through others."""
    if isinstance(value, str):
        return value[:_MAX_STR_LEN]
    return value


# ── Safe label-key extraction ─────────────────────────────────────────────────


def _safe_label_keys(labels: Any) -> list[str]:
    """Return only the label KEY names from a Google Cloud labels dict.

    Label VALUES are user-controlled and may contain PII, secrets, or env
    metadata. Only key names are stored.
    """
    if not isinstance(labels, dict):
        return []
    return [_trunc(k) for k in labels.keys() if isinstance(k, str)]


# ── Resource-name parsing helpers ─────────────────────────────────────────────


def _parse_segment_after(self_link: str, label: str) -> str:
    """Extract the segment immediately following ``label`` in a GCP selfLink.

    Google Cloud selfLinks follow the pattern:
        https://<host>/compute/v1/projects/{project}/global/networks/{name}
        https://<host>/compute/v1/projects/{project}/regions/{region}/...

    Returns empty string if the label is missing.
    """
    if not isinstance(self_link, str):
        return ""
    parts = self_link.split("/")
    for i, p in enumerate(parts):
        if p.lower() == label.lower() and i + 1 < len(parts):
            return _trunc(parts[i + 1])
    return ""


def _parse_project_from_self_link(self_link: str) -> str:
    return _parse_segment_after(self_link, "projects")


def _parse_network_from_self_link(self_link: str) -> str:
    return _parse_segment_after(self_link, "networks")


# ── IAM principal-type bucketing (counts only — never identifiers) ───────────


_IAM_MEMBER_PREFIXES: tuple[tuple[str, str], ...] = (
    ("user:", "user"),
    ("group:", "group"),
    ("serviceAccount:", "service_account"),
    ("domain:", "domain"),
)


def _iam_member_type_counts(members: Any) -> dict[str, Any]:
    """Bucket IAM members by prefix and return counts only.

    Returns a dict with:
        user_count, group_count, service_account_count, domain_count,
        other_count, allusers_present, allauthenticatedusers_present.

    Never stores the member identifier itself (the segment after the ``:``).
    """
    user_count = group_count = sa_count = domain_count = other_count = 0
    all_users = False
    all_auth = False
    if not isinstance(members, list):
        return {
            "user_count": 0, "group_count": 0,
            "service_account_count": 0, "domain_count": 0,
            "other_count": 0,
            "allusers_present": False,
            "allauthenticatedusers_present": False,
        }
    for m in members:
        if not isinstance(m, str):
            other_count += 1
            continue
        # Special "all users" / "all authenticated" sentinels — public exposure.
        if m == "allUsers":
            all_users = True
            continue
        if m == "allAuthenticatedUsers":
            all_auth = True
            continue
        matched = False
        for prefix, _label in _IAM_MEMBER_PREFIXES:
            if m.startswith(prefix):
                if prefix == "user:":
                    user_count += 1
                elif prefix == "group:":
                    group_count += 1
                elif prefix == "serviceAccount:":
                    sa_count += 1
                elif prefix == "domain:":
                    domain_count += 1
                matched = True
                break
        if not matched:
            other_count += 1
    return {
        "user_count": user_count,
        "group_count": group_count,
        "service_account_count": sa_count,
        "domain_count": domain_count,
        "other_count": other_count,
        "allusers_present": all_users,
        "allauthenticatedusers_present": all_auth,
    }


# ── Firewall rule summarization helpers ─────────────────────────────────────


def _cap_str_list(values: Any, cap: int) -> list[str]:
    """Return a capped list of stringified, truncated values."""
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for v in values[:cap]:
        if isinstance(v, str):
            out.append(_trunc(v))
    return out


def _summarize_firewall_protocol_list(items: Any, cap: int) -> list[dict[str, Any]]:
    """Summarize the ``allowed`` / ``denied`` per-rule lists.

    Each list entry is a dict like ``{"IPProtocol": "tcp", "ports": ["22", "80"]}``.
    We retain only the protocol string and the ports list (capped + truncated).
    """
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for item in items[:cap]:
        if not isinstance(item, dict):
            continue
        proto = _trunc(item.get("IPProtocol", "") or "")
        ports = _cap_str_list(item.get("ports"), cap=_MAX_FW_ALLOWED_PER_RULE)
        out.append({"protocol": proto, "ports": ports})
    return out


# ── Connector ────────────────────────────────────────────────────────────────


class GoogleCloudConnector(BaseConnector):
    """Google Cloud REST connector for ConfigTrace drift tracking (M78A).

    Stateless: credentials are passed at call time; nothing is stored on the
    instance. An OAuth bearer token is fetched per-call and used only within
    that call's lifetime — it is never stored on the instance, never returned
    in records, and never logged.
    """

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _get_token(self, credentials: dict) -> str:
        """Exchange service-account credentials for a short-lived access token.

        Uses the RFC 7523 JWT bearer grant (same pattern as the Firebase
        connector at ``app/connectors/firebase.py``).

        SECURITY: credentials["private_key"] is NEVER logged here or anywhere
        in the call chain. The returned access_token is also NEVER logged.

        Raises:
            AuthenticationError: signing failed, or the token endpoint rejected
                the assertion (400/401).
            ConnectorError: token endpoint returned a non-200 non-401 status,
                or the response body was malformed.
            NetworkError: transport-level failure before a response arrived.
        """
        from jose import jwt as jose_jwt  # python-jose[cryptography]

        sa = self._extract_service_account(credentials)
        token_uri = sa.get("token_uri") or _OAUTH_TOKEN_URL
        client_email = sa.get("client_email", "")
        # private_key is referenced once below and never logged.
        private_key = sa.get("private_key", "")

        if not client_email or not private_key:
            raise AuthenticationError(
                "gcp: service account credentials missing client_email or "
                "private_key",
                status_code=None,
            )

        now = int(time.time())
        claims = {
            "iss": client_email,
            "sub": client_email,
            "aud": token_uri,
            "iat": now,
            "exp": now + 3600,
            "scope": " ".join(_SCOPES),
        }

        try:
            assertion = jose_jwt.encode(claims, private_key, algorithm="RS256")
        except Exception as exc:  # noqa: BLE001
            # SECURITY: do not include the underlying exception message; the
            # python-jose error can echo key material on malformed input.
            raise AuthenticationError(
                "gcp: failed to sign service-account JWT — check that the "
                "private_key in the service-account JSON is valid",
                status_code=None,
            ) from exc

        try:
            resp = httpx.post(
                token_uri,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": assertion,
                },
                timeout=_TIMEOUT,
            )
        except httpx.ConnectError as exc:
            raise NetworkError(f"gcp: token request network error: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise NetworkError(f"gcp: token request timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            raise NetworkError(f"gcp: token request failed: {exc}") from exc

        if resp.status_code in (400, 401):
            raise AuthenticationError(
                "gcp: token request rejected — check the service-account JSON "
                f"(HTTP {resp.status_code})",
                status_code=resp.status_code,
            )
        if resp.status_code != 200:
            raise ConnectorError(
                f"gcp: token endpoint returned HTTP {resp.status_code}",
                status_code=resp.status_code,
            )

        try:
            data = resp.json()
        except ValueError as exc:
            raise ConnectorError(
                "gcp: token response was not valid JSON"
            ) from exc

        token = data.get("access_token", "")
        if not token:
            raise ConnectorError("gcp: token response missing access_token field")

        # Log only that a token was obtained — never the value.
        logger.info("gcp: token obtained")
        return token

    @staticmethod
    def _extract_service_account(credentials: dict) -> dict:
        """Pull the service-account dict out of the credentials envelope.

        Accepts either a parsed dict on ``service_account_json`` or a raw JSON
        string. Returns an empty dict if neither is present (token acquisition
        will then raise AuthenticationError, never silently degrade).
        """
        if not isinstance(credentials, dict):
            return {}
        sa = credentials.get("service_account_json")
        if isinstance(sa, dict):
            return sa
        if isinstance(sa, str):
            try:
                import json as _json
                return _json.loads(sa)
            except (ValueError, TypeError):
                return {}
        # Fallback: accept the top-level credentials dict itself if it carries
        # client_email + private_key directly (legacy shape).
        if "client_email" in credentials and "private_key" in credentials:
            return credentials
        return {}

    @staticmethod
    def _project_id(credentials: dict) -> str:
        """Resolve the project id from the credentials envelope.

        Explicit ``project_id`` override wins; otherwise falls back to the
        service-account JSON's ``project_id``.
        """
        if not isinstance(credentials, dict):
            return ""
        explicit = credentials.get("project_id")
        if isinstance(explicit, str) and explicit.strip():
            return _trunc(explicit.strip())
        sa = GoogleCloudConnector._extract_service_account(credentials)
        sa_pid = sa.get("project_id") if isinstance(sa, dict) else ""
        return _trunc(sa_pid or "")

    # ── HTTP GET helper ───────────────────────────────────────────────────────

    def _get(
        self,
        token: str,
        url: str,
        params: dict | None = None,
    ) -> Any:
        """Perform a single authenticated GET against a Google Cloud REST API.

        The Authorization header (bearer token) is constructed inline and is
        never stored or logged.

        Raises:
            AuthenticationError: HTTP 401.
            ConnectorError: HTTP 403, 404, 422, 5xx, or unparseable response.
            RateLimitError: HTTP 429 (Retry-After is surfaced if present).
            NetworkError: Network-level failure before a response was received.
        """
        headers = {
            # Bearer token is used only in the header — never stored elsewhere.
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        try:
            resp = httpx.get(
                url,
                headers=headers,
                params=params,
                timeout=_TIMEOUT,
            )
        except httpx.ConnectError as exc:
            raise NetworkError(
                f"gcp: GET network error for {_trunc(url)}: {exc}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise NetworkError(f"gcp: GET timed out for {_trunc(url)}") from exc
        except httpx.HTTPError as exc:
            raise NetworkError(f"gcp: GET request error: {exc}") from exc

        if resp.status_code == 401:
            raise AuthenticationError(
                "gcp: API returned 401 — credentials may be expired or invalid",
                status_code=401,
            )
        if resp.status_code == 429:
            retry_after: float | None = None
            try:
                retry_after = float(resp.headers.get("Retry-After", ""))
            except (ValueError, TypeError):
                retry_after = None
            raise RateLimitError(
                "gcp: rate limit hit (429)",
                retry_after=retry_after,
            )
        if resp.status_code in (403, 404, 422):
            raise ConnectorError(
                f"gcp: API returned HTTP {resp.status_code} for {_trunc(url)}",
                status_code=resp.status_code,
            )
        if resp.status_code >= 500:
            raise ConnectorError(
                f"gcp: API returned server error HTTP {resp.status_code}",
                status_code=resp.status_code,
            )
        if resp.status_code >= 400:
            raise ConnectorError(
                f"gcp: API returned HTTP {resp.status_code}",
                status_code=resp.status_code,
            )

        try:
            return resp.json()
        except ValueError as exc:
            raise ConnectorError(
                "gcp: response was not valid JSON"
            ) from exc

    # ── Paginated list helper ─────────────────────────────────────────────────

    def _paginate(
        self,
        token: str,
        initial_url: str,
        items_key: str,
        params: dict | None = None,
    ) -> list[Any]:
        """Follow Google Cloud ``nextPageToken`` pagination, bounded to MAX_PAGES.

        Google Cloud list responses use either:
            { "<items_key>": [...], "nextPageToken": "abc" }
        where ``items_key`` is API-specific (``projects``, ``items``,
        ``bindings``).

        Args:
            token:        Bearer token (in-scope only).
            initial_url:  URL of the first page.
            items_key:    Which key in the response body holds the list.
            params:       Base query parameters for every page (we add
                          ``pageToken`` automatically on subsequent pages).

        Returns:
            Flat list of all items across all pages (up to _MAX_PAGES pages).
        """
        items: list[Any] = []
        page = 0
        page_token: str | None = None
        base_params = dict(params or {})

        while page < _MAX_PAGES:
            this_params = dict(base_params)
            if page_token:
                this_params["pageToken"] = page_token
            data = self._get(token, initial_url, params=this_params or None)
            page += 1

            if not isinstance(data, dict):
                break
            page_items = data.get(items_key, [])
            if isinstance(page_items, list):
                items.extend(page_items)
            page_token = data.get("nextPageToken") or None
            if not page_token:
                break

        if page_token and page >= _MAX_PAGES:
            logger.warning(
                "gcp: pagination cap (%d pages) reached for %s; "
                "remaining pages skipped",
                _MAX_PAGES,
                _trunc(initial_url),
            )

        return items

    # ── Credential validation ────────────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate credentials by fetching the project metadata endpoint.

        Makes a single lightweight GET against the Cloud Resource Manager v3
        API to confirm both the token and the project id are valid.

        Returns:
            True if credentials are accepted and the project is accessible.

        Raises:
            AuthenticationError: token request failed or project returned 401.
            ConnectorError: project returned 403/404/422/5xx.
        """
        token = self._get_token(credentials)
        project_id = self._project_id(credentials)
        url = f"{_CRM_BASE}/v3/projects/{project_id}"
        self._get(token, url)
        return True

    # ── Normalizers ──────────────────────────────────────────────────────────

    def _normalize_project(self, raw: dict) -> dict:
        """Normalise a raw Cloud Resource Manager project to safe fields only.

        Raw shape (Cloud Resource Manager v3 ``Project`` resource):
            { "name": "projects/123", "projectId": "...", "displayName": "...",
              "state": "ACTIVE", "labels": {...}, "parent": "organizations/456",
              "createTime": "..." }

        Label VALUES are never stored — only key names.
        """
        project_id = _trunc(raw.get("projectId", ""))
        # `name` is `projects/{project_number}` — we keep only the number suffix
        # as `project_number` (safe identifier).
        name = raw.get("name", "")
        project_number = ""
        if isinstance(name, str) and "/" in name:
            project_number = _trunc(name.split("/", 1)[1])

        parent = raw.get("parent", "")
        parent_type = ""
        if isinstance(parent, str) and "/" in parent:
            # `parent` is e.g. `organizations/123` or `folders/456`. Surface
            # only the type, never the id.
            parent_type = _trunc(parent.split("/", 1)[0])

        return {
            "record_type": GOOGLE_CLOUD_PROJECT,
            "record_id": f"gcp_project_{project_id}",
            "project_id": project_id,
            "project_number": project_number,
            "display_name": _trunc(raw.get("displayName", "")),
            "lifecycle_state": _trunc(raw.get("state", "")),
            "parent_type": parent_type,
            "create_time": _trunc(raw.get("createTime", "")),
            # Only label KEY names; values may contain PII or secrets.
            "label_keys": _safe_label_keys(raw.get("labels")),
        }

    def _normalize_iam_policy_summary(self, raw: dict, project_id: str) -> dict:
        """Normalise a Cloud Resource Manager IAM policy into safe counts only.

        Raw shape (Policy resource):
            { "version": 3, "bindings": [
                {"role": "roles/owner", "members": ["user:...", ...],
                 "condition": {"expression": "...", "title": "..."}},
                ...
              ], "etag": "..." }

        SECURITY: principal identifiers (`members` after the colon) are
        NEVER stored. Conditions are surfaced as a presence COUNT only — the
        CEL expressions themselves are not stored (they can carry sensitive
        resource IDs).
        """
        bindings = raw.get("bindings", [])
        if not isinstance(bindings, list):
            bindings = []

        binding_count = len(bindings)
        role_names: list[str] = []
        broad_role_count = 0
        conditional_binding_count = 0
        agg = {
            "user_count": 0, "group_count": 0,
            "service_account_count": 0, "domain_count": 0,
            "other_count": 0,
            "allusers_present": False,
            "allauthenticatedusers_present": False,
        }

        scanned = 0
        for b in bindings:
            if not isinstance(b, dict):
                continue
            scanned += 1
            if scanned > _MAX_IAM_BINDINGS_SCANNED:
                # Stop principal-type aggregation past the cap; we still count
                # the total binding_count (computed above).
                break
            role = _trunc(b.get("role", ""))
            if role and role not in role_names and len(role_names) < _MAX_IAM_ROLE_NAMES:
                role_names.append(role)
            if role.lower() in _BROAD_IAM_ROLES:
                broad_role_count += 1
            if b.get("condition"):
                conditional_binding_count += 1
            counts = _iam_member_type_counts(b.get("members"))
            for k in ("user_count", "group_count",
                      "service_account_count", "domain_count", "other_count"):
                agg[k] += counts[k]
            if counts["allusers_present"]:
                agg["allusers_present"] = True
            if counts["allauthenticatedusers_present"]:
                agg["allauthenticatedusers_present"] = True

        role_count = len({_trunc(b.get("role", "")) for b in bindings
                          if isinstance(b, dict) and b.get("role")})

        return {
            "record_type": GOOGLE_CLOUD_IAM_POLICY_SUMMARY,
            "record_id": f"gcp_iam_policy_{project_id}",
            "provider_resource_id": f"projects/{project_id}/iamPolicy",
            "project_id": project_id,
            "binding_count": binding_count,
            "role_count": role_count,
            "role_names": role_names,
            "broad_role_count": broad_role_count,
            "user_member_count": agg["user_count"],
            "group_member_count": agg["group_count"],
            "service_account_member_count": agg["service_account_count"],
            "domain_member_count": agg["domain_count"],
            "other_member_count": agg["other_count"],
            "allusers_binding_present": agg["allusers_present"],
            "allauthenticatedusers_binding_present": agg["allauthenticatedusers_present"],
            "conditional_binding_count": conditional_binding_count,
        }

    def _normalize_vpc_network(self, raw: dict) -> dict:
        """Normalise a Compute v1 ``networks`` resource to safe fields only.

        Raw shape:
            { "id": "...", "name": "...", "selfLink": "...",
              "autoCreateSubnetworks": true, "routingConfig": {...},
              "mtu": 1460, "subnetworks": [...], "peerings": [...] }

        Subnetworks and peerings are reduced to counts only — we never store
        the full subnet list or peering principal identifiers.
        """
        self_link = raw.get("selfLink", "")
        routing_cfg = raw.get("routingConfig") if isinstance(raw.get("routingConfig"), dict) else {}

        subnets = raw.get("subnetworks", [])
        subnet_count = len(subnets) if isinstance(subnets, list) else 0
        peerings = raw.get("peerings", [])
        peering_count = len(peerings) if isinstance(peerings, list) else 0

        return {
            "record_type": GOOGLE_CLOUD_VPC_NETWORK,
            "record_id": f"gcp_vpc_{_trunc(self_link)}",
            "network_id": _trunc(self_link),
            "provider_resource_id": _trunc(self_link),
            "network_name": _trunc(raw.get("name", "")),
            "project_id": _parse_project_from_self_link(self_link),
            "auto_create_subnetworks": raw.get("autoCreateSubnetworks"),
            "routing_mode": _trunc(routing_cfg.get("routingMode", "")),
            "mtu": raw.get("mtu"),
            "subnet_count": subnet_count,
            "peering_count": peering_count,
        }

    def _normalize_firewall_rule(self, raw: dict) -> dict:
        """Normalise a Compute v1 ``firewalls`` resource to safe fields only.

        Raw shape:
            { "id": "...", "name": "...", "selfLink": "...",
              "network": "https://.../networks/{name}",
              "direction": "INGRESS"|"EGRESS", "priority": 1000,
              "disabled": false, "sourceRanges": ["..."],
              "destinationRanges": ["..."],
              "allowed": [{"IPProtocol":"tcp","ports":["22"]}, ...],
              "denied":  [...],
              "targetTags": [...], "targetServiceAccounts": [...],
              "logConfig": {"enable": true} }

        Target service-account emails are NEVER stored — only the count.
        Source/destination ranges and allowed/denied lists are capped.
        """
        self_link = raw.get("selfLink", "")
        network_link = raw.get("network", "")
        log_cfg = raw.get("logConfig") if isinstance(raw.get("logConfig"), dict) else {}

        target_tags = raw.get("targetTags", [])
        target_sas = raw.get("targetServiceAccounts", [])

        return {
            "record_type": GOOGLE_CLOUD_FIREWALL_RULE,
            "record_id": f"gcp_firewall_{_trunc(self_link)}",
            "firewall_id": _trunc(self_link),
            "provider_resource_id": _trunc(self_link),
            "firewall_name": _trunc(raw.get("name", "")),
            "network_name": _parse_network_from_self_link(network_link),
            "project_id": _parse_project_from_self_link(self_link),
            "direction": _trunc(raw.get("direction", "")),
            "priority": raw.get("priority"),
            "disabled": raw.get("disabled"),
            "source_ranges_summary": _cap_str_list(
                raw.get("sourceRanges"), cap=_MAX_FW_RANGES_PER_RULE,
            ),
            "destination_ranges_summary": _cap_str_list(
                raw.get("destinationRanges"), cap=_MAX_FW_RANGES_PER_RULE,
            ),
            "allowed_summary": _summarize_firewall_protocol_list(
                raw.get("allowed"), cap=_MAX_FW_ALLOWED_PER_RULE,
            ),
            "denied_summary": _summarize_firewall_protocol_list(
                raw.get("denied"), cap=_MAX_FW_ALLOWED_PER_RULE,
            ),
            "target_tag_count": len(target_tags) if isinstance(target_tags, list) else 0,
            # SECURITY: never the service-account emails themselves; the COUNT
            # is enough to surface "this firewall scopes to N service accounts".
            "target_service_account_count": len(target_sas) if isinstance(target_sas, list) else 0,
            "has_log_config": bool(log_cfg.get("enable")) if log_cfg else False,
        }

    def _normalize_storage_bucket(self, raw: dict) -> dict:
        """Normalise a Cloud Storage v1 ``Bucket`` resource to safe fields only.

        Object names, object contents, signed URLs, HMAC keys, customer-supplied
        encryption keys, and ACL grantee identities are NEVER accessed.
        """
        iam_cfg = raw.get("iamConfiguration") if isinstance(raw.get("iamConfiguration"), dict) else {}
        uniform = iam_cfg.get("uniformBucketLevelAccess") if isinstance(iam_cfg.get("uniformBucketLevelAccess"), dict) else {}
        public_prev = iam_cfg.get("publicAccessPrevention", "")

        versioning = raw.get("versioning") if isinstance(raw.get("versioning"), dict) else {}
        retention = raw.get("retentionPolicy") if isinstance(raw.get("retentionPolicy"), dict) else {}
        lifecycle = raw.get("lifecycle") if isinstance(raw.get("lifecycle"), dict) else {}
        lifecycle_rules = lifecycle.get("rule", []) if isinstance(lifecycle.get("rule"), list) else []
        encryption = raw.get("encryption") if isinstance(raw.get("encryption"), dict) else {}

        bucket_name = _trunc(raw.get("name", ""))
        return {
            "record_type": GOOGLE_CLOUD_STORAGE_BUCKET,
            "record_id": f"gcp_storage_{bucket_name}",
            "bucket_id": _trunc(raw.get("id", "")),
            "provider_resource_id": f"buckets/{bucket_name}" if bucket_name else "",
            "bucket_name": bucket_name,
            "location": _trunc(raw.get("location", "")),
            "location_type": _trunc(raw.get("locationType", "")),
            "storage_class": _trunc(raw.get("storageClass", "")),
            "uniform_bucket_level_access_enabled": bool(uniform.get("enabled")) if uniform else False,
            "public_access_prevention": _trunc(public_prev) if isinstance(public_prev, str) else "",
            "versioning_enabled": bool(versioning.get("enabled")) if versioning else False,
            "retention_policy_seconds": retention.get("retentionPeriod") if retention else None,
            "retention_policy_locked": bool(retention.get("isLocked")) if retention else False,
            "lifecycle_rule_count": len(lifecycle_rules),
            # Surface presence of a default KMS key — never the key resource id.
            "encryption_default_kms_key_present": bool(encryption.get("defaultKmsKeyName")),
        }

    # ── Main fetch ────────────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all M78A resources and return a flat list of safe records.

        Fail-soft per surface: if a single resource type fails, a warning is
        logged and collection continues for the remaining types. The caller
        receives all records that were successfully fetched.

        Records never contain credentials, bearer tokens, secret values, raw
        API response bodies, IAM principal emails / object IDs, or any of the
        data listed in the module-level privacy docstring.

        Args:
            credentials: Dict carrying ``service_account_json`` (or
                ``client_email`` + ``private_key`` + ``token_uri``) plus an
                optional ``project_id`` override.

        Returns:
            Flat list of normalised record dicts, each JSON-serialisable.
        """
        project_id = self._project_id(credentials)
        records: list[dict] = []

        # Obtain a short-lived token for this fetch run only. Auth/network
        # failures on the token request re-raise (nothing to continue).
        try:
            token = self._get_token(credentials)
        except (AuthenticationError, ConnectorError, NetworkError):
            raise

        # ── 1. Project metadata ───────────────────────────────────────────────
        try:
            url = f"{_CRM_BASE}/v3/projects/{project_id}"
            raw = self._get(token, url)
            if isinstance(raw, dict):
                records.append(self._normalize_project(raw))
        except Exception as exc:
            logger.warning(
                "gcp: failed to fetch project %s: %s",
                _trunc(project_id), _trunc(str(exc)),
            )

        # ── 2. IAM policy summary ─────────────────────────────────────────────
        try:
            url = f"{_CRM_BASE}/v3/projects/{project_id}:getIamPolicy"
            # getIamPolicy is a POST in CRM v3, but the connector helper only
            # implements GET. Use httpx.post directly with the same error
            # mapping. This is the only surface that needs a POST.
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            try:
                resp = httpx.post(url, headers=headers, json={
                    "options": {"requestedPolicyVersion": 3},
                }, timeout=_TIMEOUT)
            except httpx.ConnectError as exc:
                raise NetworkError(
                    f"gcp: getIamPolicy network error: {exc}"
                ) from exc
            except httpx.TimeoutException as exc:
                raise NetworkError(
                    f"gcp: getIamPolicy timed out for {_trunc(url)}"
                ) from exc
            except httpx.HTTPError as exc:
                raise NetworkError(
                    f"gcp: getIamPolicy request error: {exc}"
                ) from exc
            if resp.status_code == 401:
                raise AuthenticationError(
                    "gcp: getIamPolicy returned 401", status_code=401,
                )
            if resp.status_code == 429:
                raise RateLimitError("gcp: getIamPolicy rate limit", retry_after=None)
            if resp.status_code in (403, 404, 422):
                raise ConnectorError(
                    f"gcp: getIamPolicy returned {resp.status_code}",
                    status_code=resp.status_code,
                )
            if resp.status_code != 200:
                raise ConnectorError(
                    f"gcp: getIamPolicy returned {resp.status_code}",
                    status_code=resp.status_code,
                )
            try:
                raw = resp.json()
            except ValueError as exc:
                raise ConnectorError(
                    "gcp: getIamPolicy response was not JSON"
                ) from exc
            if isinstance(raw, dict):
                records.append(self._normalize_iam_policy_summary(raw, project_id))
        except Exception as exc:
            logger.warning(
                "gcp: failed to fetch IAM policy for %s: %s",
                _trunc(project_id), _trunc(str(exc)),
            )

        # ── 3. VPC networks ───────────────────────────────────────────────────
        try:
            url = f"{_COMPUTE_BASE}/compute/v1/projects/{project_id}/global/networks"
            items = self._paginate(token, url, items_key="items")
            for raw in items[:_MAX_VPC_NETWORKS]:
                if isinstance(raw, dict):
                    try:
                        records.append(self._normalize_vpc_network(raw))
                    except Exception as exc:
                        logger.warning(
                            "gcp: failed to normalise VPC network %s: %s",
                            _trunc(raw.get("name", "")), _trunc(str(exc)),
                        )
        except Exception as exc:
            logger.warning(
                "gcp: failed to fetch VPC networks: %s",
                _trunc(str(exc)),
            )

        # ── 4. Firewall rules ─────────────────────────────────────────────────
        try:
            url = f"{_COMPUTE_BASE}/compute/v1/projects/{project_id}/global/firewalls"
            items = self._paginate(token, url, items_key="items")
            for raw in items[:_MAX_FIREWALL_RULES]:
                if isinstance(raw, dict):
                    try:
                        records.append(self._normalize_firewall_rule(raw))
                    except Exception as exc:
                        logger.warning(
                            "gcp: failed to normalise firewall rule %s: %s",
                            _trunc(raw.get("name", "")), _trunc(str(exc)),
                        )
        except Exception as exc:
            logger.warning(
                "gcp: failed to fetch firewall rules: %s",
                _trunc(str(exc)),
            )

        # ── 5. Cloud Storage buckets ──────────────────────────────────────────
        try:
            url = f"{_STORAGE_BASE}/storage/v1/b"
            items = self._paginate(
                token, url, items_key="items",
                params={"project": project_id},
            )
            for raw in items[:_MAX_STORAGE_BUCKETS]:
                if isinstance(raw, dict):
                    try:
                        records.append(self._normalize_storage_bucket(raw))
                    except Exception as exc:
                        logger.warning(
                            "gcp: failed to normalise storage bucket %s: %s",
                            _trunc(raw.get("name", "")), _trunc(str(exc)),
                        )
        except Exception as exc:
            logger.warning(
                "gcp: failed to fetch storage buckets: %s",
                _trunc(str(exc)),
            )

        logger.info(
            "gcp: fetch complete — %d records collected for project %s",
            len(records),
            _trunc(project_id),
        )
        return records
