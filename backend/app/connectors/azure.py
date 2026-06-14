"""Azure drift provider connector — M77A / M77C.

M77A: Subscription, Resource Groups, NSGs, Storage Accounts, Key Vaults.
M77C: Role Assignments, App Services, SQL Servers, AKS Clusters.

Fetches safe configuration metadata from the Azure Resource Manager REST API
using a service principal with client credentials (OAuth 2.0 client_credentials
grant against Azure AD / Entra ID).

PRIVACY / SECURITY — what is NEVER stored or logged
----------------------------------------------------
- client_secret, access tokens, bearer tokens, or any auth credential material.
- Raw HTTP request or response bodies.
- Key Vault secret names, secret values, or certificate material.
- Storage account keys, SAS tokens, or connection strings.
- Tag VALUES (only tag key names are stored; values are user-controlled and may
  contain PII or secrets).
- NSG rule packet data or log-profile data.
- VM user data, database passwords, or any customer workload content.
- Principal IDs, email addresses, or permission assignments from Key Vault
  access policies.

Records fetched (M77A only)
---------------------------
AZURE_SUBSCRIPTION
    Safe fields: subscription_id, display_name, state, tenant_id (opaque
    identifier), authorization_source.

AZURE_RESOURCE_GROUP
    Safe fields: name, location, provisioning_state, tag_keys (key names only).

AZURE_NETWORK_SECURITY_GROUP
    Safe fields: nsg_id, nsg_name, resource_group, location, rule_count,
    inbound_allow_rule_count, public_inbound_rule_count, rules_summary (capped
    at 50 rules; each rule contains only: rule_name, direction, access,
    priority, protocol, source_address_prefix, source_port_range,
    destination_address_prefix, destination_port_range).

AZURE_STORAGE_ACCOUNT
    Safe fields: account_id, account_name, resource_group, location, kind,
    sku_name, allow_blob_public_access, public_network_access,
    minimum_tls_version, supports_https_traffic_only, shared_access_key_enabled,
    network_default_action.

AZURE_KEY_VAULT
    Safe fields: vault_id, vault_name, resource_group, location,
    enable_rbac_authorization, public_network_access, soft_delete_enabled,
    purge_protection_enabled, access_policy_count (integer only),
    network_default_action.

Deferred (not in M77A)
-----------------------
App Services, SQL servers, AKS clusters, App Registrations.

Auth / credentials dict
-----------------------
    tenant_id       : str  — Azure AD / Entra ID tenant GUID
    client_id       : str  — Service principal application (client) ID
    client_secret   : str  — Service principal secret; used ONLY for the token
                             request; NEVER stored or returned in any record
    subscription_id : str  — Azure subscription GUID to monitor

Required RBAC: Reader role on the subscription (read-only; no write operations
are ever performed by this connector).
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.connectors.azure_schema import (
    AZURE_AKS_CLUSTER,
    AZURE_APP_SERVICE,
    AZURE_KEY_VAULT,
    AZURE_NETWORK_SECURITY_GROUP,
    AZURE_RESOURCE_GROUP,
    AZURE_ROLE_ASSIGNMENT,
    AZURE_SQL_SERVER,
    AZURE_STORAGE_ACCOUNT,
    AZURE_SUBSCRIPTION,
)
from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ────────────────────────────────────────────────────

_MANAGEMENT_SCOPE = "https://management.azure.com/.default"
_TOKEN_URL_TEMPLATE = (
    "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
)
_MGMT_BASE = "https://management.azure.com"

_TIMEOUT = 30.0
_MAX_PAGES = 10
_MAX_RULES_PER_NSG = 50
_MAX_STR_LEN = 200

# Azure Resource Manager API versions per resource type
_API_VERSION_SUBSCRIPTION = "2022-12-01"
_API_VERSION_RESOURCE_GROUPS = "2021-04-01"
_API_VERSION_NSG = "2023-05-01"
_API_VERSION_STORAGE = "2023-01-01"
_API_VERSION_KEY_VAULT = "2023-02-01"
# M77C additions
_API_VERSION_ROLE_ASSIGNMENTS = "2022-04-01"
_API_VERSION_APP_SERVICE = "2023-01-01"
_API_VERSION_SQL_SERVER = "2021-11-01"
_API_VERSION_AKS = "2023-10-01"

# Per-subscription caps to avoid excessive API calls (M77C surfaces require
# sub-resource requests for App Service site config and SQL firewall rules).
_MAX_APP_SERVICE_CONFIG_FETCHES = 20
_MAX_SQL_FIREWALL_FETCHES = 20
_MAX_ROLE_ASSIGNMENTS = 200

# ── Well-known Azure built-in role GUIDs → human names ───────────────────────
# These are public constants documented by Microsoft; resolving the name here
# avoids an additional API call per role assignment. Only the GUID (the last
# segment of the roleDefinitionId path) is looked up.
_BUILTIN_ROLE_NAMES: dict[str, str] = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
    "974c5e8b-45b9-4653-ba55-5f855dd0fb88": "Storage Queue Data Contributor",
    "f25e0fa2-a7c8-4377-a976-54943a77a395": "Key Vault Contributor",
    "14b46e9e-c2b7-41b4-b07b-48a6ebf60603": "Key Vault Secrets Officer",
    "4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User",
    "6d8ee4ec-f05a-4a1d-8b00-a9b17e38b437": "SQL Server Contributor",
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c": "Virtual Machine Contributor",
    "de139f84-1756-47ae-9be6-808fbbe84772": "Website Contributor",
    "1c0163c0-47e6-4577-8991-ea5c82e286e4": "Virtual Machine Administrator Login",
}


def _resolve_role_name(role_definition_id: str) -> str:
    """Return the human name for a built-in Azure role, or '' for unknown roles.

    Extracts the GUID (final segment of the roleDefinitionId path) and looks it
    up in the static built-in role map.  Custom / unknown roles return ''.
    """
    if not isinstance(role_definition_id, str):
        return ""
    parts = role_definition_id.rstrip("/").split("/")
    guid = parts[-1].lower() if parts else ""
    return _BUILTIN_ROLE_NAMES.get(guid, "")


def _derive_scope_type(scope: str) -> str:
    """Classify an Azure role assignment scope string into a broad category.

    Returns one of: "subscription", "resource_group", "resource",
    "management_group", or "" for unrecognised patterns.
    """
    if not isinstance(scope, str):
        return ""
    stripped = scope.strip("/")
    if not stripped:
        return "global"
    parts = [p for p in stripped.split("/") if p]
    low0 = parts[0].lower() if parts else ""
    if low0 == "managementgroups":
        return "management_group"
    if low0 == "subscriptions" and len(parts) == 2:
        return "subscription"
    if len(parts) >= 4 and parts[2].lower() == "resourcegroups":
        # Exactly 4 parts → resource group scope; more → sub-resource scope
        return "resource_group" if len(parts) == 4 else "resource"
    return "resource"


# ── String safety helper ──────────────────────────────────────────────────────

def _trunc(value: Any) -> Any:
    """Truncate string values to _MAX_STR_LEN characters; pass through others."""
    if isinstance(value, str):
        return value[:_MAX_STR_LEN]
    return value


# ── Safe tag extraction ───────────────────────────────────────────────────────

def _safe_tag_keys(tags: Any) -> list[str]:
    """Return only the tag KEY names from an Azure tags dict.

    Tag values are user-controlled and may contain PII, secrets, or sensitive
    environment data. Only key names are stored.
    """
    if not isinstance(tags, dict):
        return []
    return [_trunc(k) for k in tags.keys() if isinstance(k, str)]


# ── NSG rule safety ───────────────────────────────────────────────────────────

_SAFE_RULE_FIELDS = {
    "name",
    "direction",
    "access",
    "priority",
    "protocol",
    "sourceAddressPrefix",
    "sourcePortRange",
    "destinationAddressPrefix",
    "destinationPortRange",
}


def _safe_rule_summary(rule: dict) -> dict:
    """Extract only safe metadata fields from a single NSG security rule.

    Never stores packet data, log data, or any field outside the explicit
    allowlist.
    """
    props = rule.get("properties", {}) if isinstance(rule.get("properties"), dict) else {}
    return {
        "rule_name": _trunc(rule.get("name", "")),
        "direction": _trunc(props.get("direction", "")),
        "access": _trunc(props.get("access", "")),
        "priority": props.get("priority"),
        "protocol": _trunc(props.get("protocol", "")),
        "source_address_prefix": _trunc(props.get("sourceAddressPrefix", "")),
        "source_port_range": _trunc(props.get("sourcePortRange", "")),
        "destination_address_prefix": _trunc(props.get("destinationAddressPrefix", "")),
        "destination_port_range": _trunc(props.get("destinationPortRange", "")),
    }


# ── Resource group parsing helper ─────────────────────────────────────────────

def _parse_resource_group_from_id(resource_id: str) -> str:
    """Extract resource group name from an Azure resource ID string.

    Azure resource IDs follow the pattern:
    /subscriptions/{sub}/resourceGroups/{rg}/providers/...
    Returns empty string if the pattern is not found.
    """
    if not isinstance(resource_id, str):
        return ""
    parts = resource_id.split("/")
    try:
        rg_index = next(
            i for i, p in enumerate(parts) if p.lower() == "resourcegroups"
        )
        return _trunc(parts[rg_index + 1]) if rg_index + 1 < len(parts) else ""
    except StopIteration:
        return ""


# ── Connector ─────────────────────────────────────────────────────────────────

class AzureConnector(BaseConnector):
    """Azure Resource Manager connector for ConfigTrace drift tracking (M77A).

    Stateless: credentials are passed at call time; nothing is stored on the
    instance. A bearer token is fetched per-call and used only within that
    call's lifetime — it is never stored on the instance, never returned in
    records, and never logged.
    """

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _get_token(self, credentials: dict) -> str:
        """Obtain a bearer token via the client_credentials OAuth 2.0 flow.

        The token value is NEVER stored as an instance attribute, NEVER
        returned in a record dict, and NEVER logged. Only the log line
        "azure: token obtained" is emitted.

        Returns:
            The raw bearer token string (used only for in-call HTTP headers).

        Raises:
            AuthenticationError: The tenant/client rejected the credentials.
            ConnectorError: An unexpected error occurred during the token fetch.
            NetworkError: A network-level failure prevented the request.
        """
        tenant_id = credentials.get("tenant_id", "")
        client_id = credentials.get("client_id", "")
        # client_secret is used here only; never stored or logged
        client_secret = credentials.get("client_secret", "")

        url = _TOKEN_URL_TEMPLATE.format(tenant_id=tenant_id)
        payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": _MANAGEMENT_SCOPE,
        }

        try:
            resp = httpx.post(url, data=payload, timeout=_TIMEOUT)
        except httpx.ConnectError as exc:
            raise NetworkError(f"azure: token request network error: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise NetworkError(f"azure: token request timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            raise NetworkError(f"azure: token request failed: {exc}") from exc

        if resp.status_code == 401:
            raise AuthenticationError(
                "azure: token request rejected (401) — check tenant_id, "
                "client_id, and client_secret",
                status_code=401,
            )
        if resp.status_code != 200:
            raise ConnectorError(
                f"azure: token endpoint returned HTTP {resp.status_code}",
                status_code=resp.status_code,
            )

        try:
            data = resp.json()
        except ValueError as exc:
            raise ConnectorError(
                "azure: token response was not valid JSON"
            ) from exc

        token = data.get("access_token", "")
        if not token:
            raise ConnectorError("azure: token response missing access_token field")

        # Log only that a token was obtained — never the value
        logger.info("azure: token obtained")
        return token

    # ── HTTP GET helper ───────────────────────────────────────────────────────

    def _get(
        self,
        token: str,
        url: str,
        params: dict | None = None,
    ) -> Any:
        """Perform a single authenticated GET against the Azure Management API.

        The Authorization header (bearer token) is constructed inline and is
        never stored or logged.

        Args:
            token: Bearer token string (in-scope only; not stored).
            url:   Full Azure Management API URL.
            params: Optional query parameters.

        Returns:
            Parsed JSON response body (any JSON type).

        Raises:
            AuthenticationError: HTTP 401.
            ConnectorError: HTTP 403, 404, 422, 5xx, or unparseable response.
            RateLimitError: HTTP 429 (Retry-After is surfaced if present).
            NetworkError: Network-level failure before a response was received.
        """
        headers = {
            # Bearer token is used only in the header — never stored elsewhere
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
            raise NetworkError(f"azure: GET network error for {_trunc(url)}: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise NetworkError(f"azure: GET timed out for {_trunc(url)}") from exc
        except httpx.HTTPError as exc:
            raise NetworkError(f"azure: GET request error: {exc}") from exc

        if resp.status_code == 401:
            raise AuthenticationError(
                "azure: API returned 401 — credentials may be expired or invalid",
                status_code=401,
            )
        if resp.status_code == 429:
            retry_after: float | None = None
            try:
                retry_after = float(resp.headers.get("Retry-After", ""))
            except (ValueError, TypeError):
                retry_after = None
            raise RateLimitError(
                "azure: rate limit hit (429)",
                retry_after=retry_after,
            )
        if resp.status_code in (403, 404, 422):
            raise ConnectorError(
                f"azure: API returned HTTP {resp.status_code} for {_trunc(url)}",
                status_code=resp.status_code,
            )
        if resp.status_code >= 500:
            raise ConnectorError(
                f"azure: API returned server error HTTP {resp.status_code}",
                status_code=resp.status_code,
            )
        if resp.status_code >= 400:
            raise ConnectorError(
                f"azure: API returned HTTP {resp.status_code}",
                status_code=resp.status_code,
            )

        try:
            return resp.json()
        except ValueError as exc:
            raise ConnectorError(
                "azure: response was not valid JSON"
            ) from exc

    # ── Paginated list helper ─────────────────────────────────────────────────

    def _paginate(
        self,
        token: str,
        initial_url: str,
        params: dict | None = None,
    ) -> list[Any]:
        """Follow Azure ARM nextLink pagination, bounded to MAX_PAGES pages.

        Azure ARM list responses use the shape:
            { "value": [...], "nextLink": "https://..." }

        Args:
            token:       Bearer token (in-scope only).
            initial_url: URL of the first page.
            params:      Query parameters for the first request only; nextLink
                         URLs are followed verbatim.

        Returns:
            Flat list of all items across all pages (up to _MAX_PAGES pages).
        """
        items: list[Any] = []
        url: str | None = initial_url
        page = 0
        first = True

        while url and page < _MAX_PAGES:
            data = self._get(token, url, params=params if first else None)
            first = False
            page += 1

            if isinstance(data, dict):
                page_items = data.get("value", [])
                if isinstance(page_items, list):
                    items.extend(page_items)
                url = data.get("nextLink") or None
            else:
                break

        if url and page >= _MAX_PAGES:
            logger.warning(
                "azure: pagination cap (%d pages) reached for %s; "
                "remaining pages skipped",
                _MAX_PAGES,
                _trunc(initial_url),
            )

        return items

    # ── Credential validation ─────────────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate credentials by fetching the subscription endpoint.

        Makes a single lightweight GET request to confirm both the token and
        the subscription_id are valid.

        Returns:
            True if credentials are accepted and the subscription is accessible.

        Raises:
            AuthenticationError: Token request failed (401) or subscription
                returned 401.
            ConnectorError: The subscription returned an unexpected error.
        """
        token = self._get_token(credentials)
        subscription_id = credentials.get("subscription_id", "")
        url = (
            f"{_MGMT_BASE}/subscriptions/{subscription_id}"
            f"?api-version={_API_VERSION_SUBSCRIPTION}"
        )
        self._get(token, url)
        return True

    # ── Normalizers ───────────────────────────────────────────────────────────

    def _normalize_subscription(self, raw: dict) -> dict:
        """Normalise a raw Azure subscription object to safe fields only."""
        props = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
        return {
            "record_type": AZURE_SUBSCRIPTION,
            "record_id": f"azure_subscription_{_trunc(raw.get('subscriptionId', ''))}",
            "subscription_id": _trunc(raw.get("subscriptionId", "")),
            "display_name": _trunc(raw.get("displayName", "")),
            "state": _trunc(raw.get("state", "")),
            # tenant_id stored only as an opaque identifier for correlation
            "tenant_id": _trunc(raw.get("tenantId", "")),
            "authorization_source": _trunc(props.get("authorizationSource", "")),
        }

    def _normalize_resource_group(self, raw: dict, subscription_id: str) -> dict:
        """Normalise a raw Azure resource group object to safe fields only.

        Tag values are never stored — only tag key names.
        """
        props = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
        return {
            "record_type": AZURE_RESOURCE_GROUP,
            "record_id": (
                f"azure_rg_{_trunc(subscription_id)}"
                f"_{_trunc(raw.get('name', ''))}"
            ),
            "name": _trunc(raw.get("name", "")),
            "location": _trunc(raw.get("location", "")),
            "provisioning_state": _trunc(props.get("provisioningState", "")),
            # Only tag KEY names — values may contain PII or secrets
            "tag_keys": _safe_tag_keys(raw.get("tags")),
        }

    def _normalize_nsg(self, raw: dict) -> dict:
        """Normalise a raw Azure NSG object to safe fields only.

        rules_summary is capped at _MAX_RULES_PER_NSG entries. Only the
        explicit safe fields per rule are included; packet data and log data
        are never stored.
        """
        props = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
        resource_id = raw.get("id", "")
        resource_group = _parse_resource_group_from_id(resource_id)

        # Merge default rules and effective rules (defaultSecurityRules +
        # securityRules) for counting purposes; only securityRules (custom)
        # are included in rules_summary per privacy guidance.
        security_rules: list[dict] = []
        if isinstance(props.get("securityRules"), list):
            security_rules = props["securityRules"]

        default_rules: list[dict] = []
        if isinstance(props.get("defaultSecurityRules"), list):
            default_rules = props["defaultSecurityRules"]

        all_rules = security_rules + default_rules

        # Aggregate posture counts
        inbound_allow_count = 0
        public_inbound_count = 0
        _public_prefixes = {"*", "Internet", "0.0.0.0/0", "::/0"}

        for rule in all_rules:
            rule_props = rule.get("properties", {}) if isinstance(rule.get("properties"), dict) else {}
            direction = rule_props.get("direction", "")
            access = rule_props.get("access", "")
            src_prefix = rule_props.get("sourceAddressPrefix", "")

            if direction == "Inbound" and access == "Allow":
                inbound_allow_count += 1
                if src_prefix in _public_prefixes:
                    public_inbound_count += 1

        # Cap rules_summary at _MAX_RULES_PER_NSG
        rules_summary = [
            _safe_rule_summary(r)
            for r in all_rules[:_MAX_RULES_PER_NSG]
        ]

        return {
            "record_type": AZURE_NETWORK_SECURITY_GROUP,
            "record_id": f"azure_nsg_{_trunc(resource_id)}",
            "nsg_id": _trunc(resource_id),
            "nsg_name": _trunc(raw.get("name", "")),
            "resource_group": resource_group,
            "location": _trunc(raw.get("location", "")),
            "rule_count": len(all_rules),
            "inbound_allow_rule_count": inbound_allow_count,
            "public_inbound_rule_count": public_inbound_count,
            "rules_summary": rules_summary,
        }

    def _normalize_storage_account(self, raw: dict) -> dict:
        """Normalise a raw Azure storage account object to safe fields only.

        Storage keys, SAS tokens, and connection strings are NEVER fetched
        or stored. Only configuration/posture metadata is included.
        """
        props = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
        sku = raw.get("sku") if isinstance(raw.get("sku"), dict) else {}
        resource_id = raw.get("id", "")
        resource_group = _parse_resource_group_from_id(resource_id)

        network_rule_set = (
            props.get("networkAcls")
            if isinstance(props.get("networkAcls"), dict)
            else {}
        )
        network_default_action = _trunc(
            network_rule_set.get("defaultAction", "")
        )

        return {
            "record_type": AZURE_STORAGE_ACCOUNT,
            "record_id": f"azure_storage_{_trunc(resource_id)}",
            "account_id": _trunc(resource_id),
            "account_name": _trunc(raw.get("name", "")),
            "resource_group": resource_group,
            "location": _trunc(raw.get("location", "")),
            "kind": _trunc(raw.get("kind", "")),
            "sku_name": _trunc(sku.get("name", "")),
            "allow_blob_public_access": props.get("allowBlobPublicAccess"),
            "public_network_access": _trunc(
                props.get("publicNetworkAccess", "")
            ),
            "minimum_tls_version": _trunc(props.get("minimumTlsVersion", "")),
            "supports_https_traffic_only": props.get("supportsHttpsTrafficOnly"),
            "shared_access_key_enabled": props.get("allowSharedKeyAccess"),
            "network_default_action": network_default_action,
        }

    def _normalize_key_vault(self, raw: dict) -> dict:
        """Normalise a raw Azure Key Vault object to safe fields only.

        Secret names, secret values, certificate material, principal IDs,
        email addresses, and permission assignments from access policies are
        NEVER stored. access_policy_count is an integer only.
        """
        props = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
        resource_id = raw.get("id", "")
        resource_group = _parse_resource_group_from_id(resource_id)

        # Count only — never store principal IDs, emails, or permission values
        access_policies = props.get("accessPolicies", [])
        access_policy_count = (
            len(access_policies) if isinstance(access_policies, list) else 0
        )

        network_acls = (
            props.get("networkAcls")
            if isinstance(props.get("networkAcls"), dict)
            else {}
        )
        network_default_action = _trunc(
            network_acls.get("defaultAction", "")
        )

        return {
            "record_type": AZURE_KEY_VAULT,
            "record_id": f"azure_kv_{_trunc(resource_id)}",
            "vault_id": _trunc(resource_id),
            "vault_name": _trunc(raw.get("name", "")),
            "resource_group": resource_group,
            "location": _trunc(raw.get("location", "")),
            "enable_rbac_authorization": props.get("enableRbacAuthorization"),
            "public_network_access": _trunc(
                props.get("publicNetworkAccess", "")
            ),
            "soft_delete_enabled": props.get("enableSoftDelete"),
            "purge_protection_enabled": props.get("enablePurgeProtection"),
            # Integer count only — no principal IDs, emails, or permission values
            "access_policy_count": access_policy_count,
            "network_default_action": network_default_action,
        }

    def _normalize_role_assignment(self, raw: dict) -> dict:
        """Normalise a raw Azure role assignment to safe fields only.

        SECURITY: principalId (the assignee's object ID) is intentionally
        excluded — it is an opaque GUID that maps to a user/group/SP identity
        and is therefore PII-adjacent. Only principalType (the category string:
        User / Group / ServicePrincipal / ForeignGroup / Device) is retained.
        """
        assignment_id = _trunc(raw.get("id", ""))
        props = raw.get("properties", {}) if isinstance(raw.get("properties"), dict) else {}

        role_definition_id = _trunc(props.get("roleDefinitionId", ""))
        role_definition_name = _resolve_role_name(role_definition_id)

        scope = props.get("scope", "")
        scope_type = _derive_scope_type(scope)
        # Extract resource group if scope is at resource-group level
        resource_group = ""
        if scope_type in ("resource_group", "resource"):
            resource_group = _parse_resource_group_from_id(scope)

        # condition_present: True when an ABAC condition string is set
        condition = props.get("condition")
        condition_present: bool | None = (
            isinstance(condition, str) and bool(condition.strip())
            if condition is not None
            else None
        )

        return {
            "record_type": AZURE_ROLE_ASSIGNMENT,
            "record_id": f"azure_ra_{assignment_id}",
            "assignment_id": assignment_id,
            "scope_type": scope_type,
            "resource_group": resource_group,
            # role_definition_id stored as opaque GUID only (no full ARM path)
            "role_definition_id": _trunc(role_definition_id.rstrip("/").split("/")[-1]),
            "role_definition_name": role_definition_name,
            # principalType is a category string (User/Group/SP) — not PII
            "principal_type": _trunc(props.get("principalType", "")),
            "condition_present": condition_present,
            "created_on": _trunc(props.get("createdOn", "")),
            "updated_on": _trunc(props.get("updatedOn", "")),
        }

    def _normalize_app_service(self, raw: dict, site_config: dict | None) -> dict:
        """Normalise a raw Azure App Service / Web App site to safe fields only.

        app_settings and connection_strings are NEVER stored — only their counts.
        ftps_state and min_tls_version come from the site config sub-request;
        they are None when the config request was skipped or failed.
        """
        props = raw.get("properties", {}) if isinstance(raw.get("properties"), dict) else {}
        resource_id = _trunc(raw.get("id", ""))
        resource_group = _parse_resource_group_from_id(resource_id)

        # Fields available in the list API response
        https_only: bool | None = props.get("httpsOnly")
        client_cert_enabled: bool | None = props.get("clientCertEnabled")
        public_network_access = _trunc(props.get("publicNetworkAccess", ""))

        # Fields from the site config sub-request (may be None if fetch failed)
        ftps_state: str | None = None
        min_tls_version: str | None = None
        auth_enabled: bool | None = None
        app_settings_count: int | None = None
        connection_string_count: int | None = None

        if isinstance(site_config, dict):
            sc_props = site_config.get("properties", {}) if isinstance(site_config.get("properties"), dict) else {}
            ftps_state = _trunc(sc_props.get("ftpsState", "") or "")
            min_tls_version = _trunc(sc_props.get("minTlsVersion", "") or "")
            auth_enabled = sc_props.get("siteAuthEnabled")
            # Counts only — never store names or values
            app_settings_raw = sc_props.get("appSettings")
            if isinstance(app_settings_raw, list):
                app_settings_count = len(app_settings_raw)
            conn_strings_raw = sc_props.get("connectionStrings")
            if isinstance(conn_strings_raw, list):
                connection_string_count = len(conn_strings_raw)

        return {
            "record_type": AZURE_APP_SERVICE,
            "record_id": f"azure_app_{resource_id}",
            "app_id": resource_id,
            "app_name": _trunc(raw.get("name", "")),
            "resource_group": resource_group,
            "location": _trunc(raw.get("location", "")),
            "kind": _trunc(raw.get("kind", "")),
            "https_only": https_only,
            "public_network_access": public_network_access,
            "client_cert_enabled": client_cert_enabled,
            # From site config (None if config not fetched or failed)
            "ftps_state": ftps_state,
            "min_tls_version": min_tls_version,
            "auth_enabled": auth_enabled,
            "app_settings_count": app_settings_count,
            "connection_string_count": connection_string_count,
        }

    def _normalize_sql_server(
        self,
        raw: dict,
        firewall_rules: list[dict] | None,
    ) -> dict:
        """Normalise a raw Azure SQL logical server to safe fields only.

        Administrator login name and password are NEVER stored. Database names
        and firewall rule creator identities are excluded. Firewall rule data is
        aggregated to a count and a safe boolean flag only.
        """
        props = raw.get("properties", {}) if isinstance(raw.get("properties"), dict) else {}
        resource_id = _trunc(raw.get("id", ""))
        resource_group = _parse_resource_group_from_id(resource_id)

        # administrator block — extract only what is safe
        admin_block = props.get("administrators", {}) if isinstance(props.get("administrators"), dict) else {}
        azure_ad_only: bool | None = admin_block.get("azureADOnlyAuthentication")

        # Firewall aggregates (from sub-request, may be None if not fetched)
        firewall_rule_count: int | None = None
        has_allow_azure_services_rule: bool | None = None
        if isinstance(firewall_rules, list):
            firewall_rule_count = len(firewall_rules)
            # The "Allow Azure services" pseudo-rule has startIpAddress=0.0.0.0
            # and endIpAddress=0.0.0.0 by Azure convention.
            has_allow_azure_services_rule = any(
                isinstance(r, dict)
                and isinstance(r.get("properties"), dict)
                and r["properties"].get("startIpAddress") == "0.0.0.0"
                and r["properties"].get("endIpAddress") == "0.0.0.0"
                for r in firewall_rules
            )

        return {
            "record_type": AZURE_SQL_SERVER,
            "record_id": f"azure_sql_{resource_id}",
            "server_id": resource_id,
            "server_name": _trunc(raw.get("name", "")),
            "resource_group": resource_group,
            "location": _trunc(raw.get("location", "")),
            "public_network_access": _trunc(props.get("publicNetworkAccess", "")),
            # API field is "minimalTlsVersion" (Azure naming), normalised here
            "minimum_tls_version": _trunc(props.get("minimalTlsVersion", "") or ""),
            "azure_ad_only_authentication": azure_ad_only,
            "firewall_rule_count": firewall_rule_count,
            "has_allow_azure_services_rule": has_allow_azure_services_rule,
        }

    def _normalize_aks_cluster(self, raw: dict) -> dict:
        """Normalise a raw Azure AKS managed cluster to safe fields only.

        Kubeconfig, cluster credentials, certificates, node names, and pod/
        workload data are NEVER accessible from the management-plane list API
        and are therefore impossible to leak.  Only count and boolean posture
        fields are stored.
        """
        props = raw.get("properties", {}) if isinstance(raw.get("properties"), dict) else {}
        resource_id = _trunc(raw.get("id", ""))
        resource_group = _parse_resource_group_from_id(resource_id)

        # API access profile
        api_profile = (
            props.get("apiServerAccessProfile", {})
            if isinstance(props.get("apiServerAccessProfile"), dict)
            else {}
        )
        private_cluster_enabled: bool | None = api_profile.get("enablePrivateCluster")
        authorized_ranges = api_profile.get("authorizedIPRanges")
        ip_range_count = len(authorized_ranges) if isinstance(authorized_ranges, list) else 0

        # AAD / RBAC profile
        aad_profile = (
            props.get("aadProfile", {})
            if isinstance(props.get("aadProfile"), dict)
            else {}
        )
        azure_rbac_enabled: bool | None = aad_profile.get("enableAzureRBAC")

        # Local accounts
        local_account_disabled: bool | None = props.get("disableLocalAccounts")

        # Network profile
        net_profile = (
            props.get("networkProfile", {})
            if isinstance(props.get("networkProfile"), dict)
            else {}
        )
        network_plugin = _trunc(net_profile.get("networkPlugin", "") or "")
        network_policy = _trunc(net_profile.get("networkPolicy", "") or "")

        public_network_access = _trunc(props.get("publicNetworkAccess", "") or "")

        return {
            "record_type": AZURE_AKS_CLUSTER,
            "record_id": f"azure_aks_{resource_id}",
            "cluster_id": resource_id,
            "cluster_name": _trunc(raw.get("name", "")),
            "resource_group": resource_group,
            "location": _trunc(raw.get("location", "")),
            "private_cluster_enabled": private_cluster_enabled,
            "local_account_disabled": local_account_disabled,
            "azure_rbac_enabled": azure_rbac_enabled,
            "network_plugin": network_plugin,
            "network_policy": network_policy,
            "public_network_access": public_network_access,
            "api_server_authorized_ip_range_count": ip_range_count,
        }

    # ── Main fetch ────────────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all M77A resources and return a flat list of safe records.

        Fail-soft per surface: if a single resource type fails, a warning is
        logged and collection continues for the remaining types. The caller
        receives all records that were successfully fetched.

        Records never contain credentials, bearer tokens, secret values, raw
        API response bodies, or any of the data listed in the module-level
        privacy docstring.

        Args:
            credentials: Dict with keys tenant_id, client_id, client_secret,
                subscription_id.

        Returns:
            Flat list of normalised record dicts, each JSON-serialisable.
        """
        subscription_id = credentials.get("subscription_id", "")
        records: list[dict] = []

        # Obtain a short-lived token for this fetch run only.
        # The token is a local variable; it is never stored on self or in any
        # record, and is never logged.
        try:
            token = self._get_token(credentials)
        except (AuthenticationError, ConnectorError, NetworkError):
            # Re-raise auth/network failures on token fetch — nothing to continue
            raise

        # ── 1. Subscription ───────────────────────────────────────────────────
        try:
            sub_url = (
                f"{_MGMT_BASE}/subscriptions/{subscription_id}"
                f"?api-version={_API_VERSION_SUBSCRIPTION}"
            )
            sub_raw = self._get(token, sub_url)
            if isinstance(sub_raw, dict):
                records.append(self._normalize_subscription(sub_raw))
        except Exception as exc:
            logger.warning(
                "azure: failed to fetch subscription %s: %s",
                _trunc(subscription_id),
                _trunc(str(exc)),
            )

        # ── 2. Resource groups ────────────────────────────────────────────────
        try:
            rg_url = (
                f"{_MGMT_BASE}/subscriptions/{subscription_id}"
                f"/resourcegroups?api-version={_API_VERSION_RESOURCE_GROUPS}"
            )
            rg_items = self._paginate(token, rg_url)
            for raw_rg in rg_items:
                if isinstance(raw_rg, dict):
                    try:
                        records.append(
                            self._normalize_resource_group(raw_rg, subscription_id)
                        )
                    except Exception as exc:
                        logger.warning(
                            "azure: failed to normalise resource group %s: %s",
                            _trunc(raw_rg.get("name", "")),
                            _trunc(str(exc)),
                        )
        except Exception as exc:
            logger.warning(
                "azure: failed to fetch resource groups: %s",
                _trunc(str(exc)),
            )

        # ── 3. Network Security Groups ────────────────────────────────────────
        try:
            nsg_url = (
                f"{_MGMT_BASE}/subscriptions/{subscription_id}"
                f"/providers/Microsoft.Network/networkSecurityGroups"
                f"?api-version={_API_VERSION_NSG}"
            )
            nsg_items = self._paginate(token, nsg_url)
            for raw_nsg in nsg_items:
                if isinstance(raw_nsg, dict):
                    try:
                        records.append(self._normalize_nsg(raw_nsg))
                    except Exception as exc:
                        logger.warning(
                            "azure: failed to normalise NSG %s: %s",
                            _trunc(raw_nsg.get("name", "")),
                            _trunc(str(exc)),
                        )
        except Exception as exc:
            logger.warning(
                "azure: failed to fetch NSGs: %s",
                _trunc(str(exc)),
            )

        # ── 4. Storage accounts ───────────────────────────────────────────────
        try:
            storage_url = (
                f"{_MGMT_BASE}/subscriptions/{subscription_id}"
                f"/providers/Microsoft.Storage/storageAccounts"
                f"?api-version={_API_VERSION_STORAGE}"
            )
            storage_items = self._paginate(token, storage_url)
            for raw_sa in storage_items:
                if isinstance(raw_sa, dict):
                    try:
                        records.append(self._normalize_storage_account(raw_sa))
                    except Exception as exc:
                        logger.warning(
                            "azure: failed to normalise storage account %s: %s",
                            _trunc(raw_sa.get("name", "")),
                            _trunc(str(exc)),
                        )
        except Exception as exc:
            logger.warning(
                "azure: failed to fetch storage accounts: %s",
                _trunc(str(exc)),
            )

        # ── 5. Key Vaults ─────────────────────────────────────────────────────
        try:
            kv_url = (
                f"{_MGMT_BASE}/subscriptions/{subscription_id}"
                f"/providers/Microsoft.KeyVault/vaults"
                f"?api-version={_API_VERSION_KEY_VAULT}"
            )
            kv_items = self._paginate(token, kv_url)
            for raw_kv in kv_items:
                if isinstance(raw_kv, dict):
                    try:
                        records.append(self._normalize_key_vault(raw_kv))
                    except Exception as exc:
                        logger.warning(
                            "azure: failed to normalise key vault %s: %s",
                            _trunc(raw_kv.get("name", "")),
                            _trunc(str(exc)),
                        )
        except Exception as exc:
            logger.warning(
                "azure: failed to fetch key vaults: %s",
                _trunc(str(exc)),
            )

        # ── 6. Role assignments (M77C) ────────────────────────────────────────
        try:
            ra_url = (
                f"{_MGMT_BASE}/subscriptions/{subscription_id}"
                f"/providers/Microsoft.Authorization/roleAssignments"
                f"?api-version={_API_VERSION_ROLE_ASSIGNMENTS}"
            )
            ra_items = self._paginate(token, ra_url)
            # Cap to avoid storing an unbounded number of assignments
            for raw_ra in ra_items[:_MAX_ROLE_ASSIGNMENTS]:
                if isinstance(raw_ra, dict):
                    try:
                        records.append(self._normalize_role_assignment(raw_ra))
                    except Exception as exc:
                        logger.warning(
                            "azure: failed to normalise role assignment %s: %s",
                            _trunc(raw_ra.get("id", "")),
                            _trunc(str(exc)),
                        )
            if len(ra_items) > _MAX_ROLE_ASSIGNMENTS:
                logger.warning(
                    "azure: role assignment cap (%d) reached; "
                    "%d assignments skipped",
                    _MAX_ROLE_ASSIGNMENTS,
                    len(ra_items) - _MAX_ROLE_ASSIGNMENTS,
                )
        except Exception as exc:
            logger.warning(
                "azure: failed to fetch role assignments: %s",
                _trunc(str(exc)),
            )

        # ── 7. App Services / Web Apps (M77C) ────────────────────────────────
        try:
            sites_url = (
                f"{_MGMT_BASE}/subscriptions/{subscription_id}"
                f"/providers/Microsoft.Web/sites"
                f"?api-version={_API_VERSION_APP_SERVICE}"
            )
            site_items = self._paginate(token, sites_url)
            for idx, raw_site in enumerate(site_items):
                if not isinstance(raw_site, dict):
                    continue
                # Fetch individual site config (ftpsState, minTlsVersion, etc.)
                # Only for the first N sites to cap sub-request count.
                site_config: dict | None = None
                if idx < _MAX_APP_SERVICE_CONFIG_FETCHES:
                    site_rg = _parse_resource_group_from_id(
                        raw_site.get("id", "")
                    )
                    site_name = raw_site.get("name", "")
                    if site_rg and site_name:
                        config_url = (
                            f"{_MGMT_BASE}/subscriptions/{subscription_id}"
                            f"/resourceGroups/{site_rg}"
                            f"/providers/Microsoft.Web/sites/{site_name}"
                            f"/config/web"
                            f"?api-version={_API_VERSION_APP_SERVICE}"
                        )
                        try:
                            site_config = self._get(token, config_url)
                            if not isinstance(site_config, dict):
                                site_config = None
                        except Exception as exc:
                            logger.warning(
                                "azure: failed to fetch site config for %s: %s",
                                _trunc(site_name),
                                _trunc(str(exc)),
                            )
                try:
                    records.append(
                        self._normalize_app_service(raw_site, site_config)
                    )
                except Exception as exc:
                    logger.warning(
                        "azure: failed to normalise app service %s: %s",
                        _trunc(raw_site.get("name", "")),
                        _trunc(str(exc)),
                    )
        except Exception as exc:
            logger.warning(
                "azure: failed to fetch app services: %s",
                _trunc(str(exc)),
            )

        # ── 8. SQL Servers (M77C) ─────────────────────────────────────────────
        try:
            sql_url = (
                f"{_MGMT_BASE}/subscriptions/{subscription_id}"
                f"/providers/Microsoft.Sql/servers"
                f"?api-version={_API_VERSION_SQL_SERVER}"
            )
            sql_items = self._paginate(token, sql_url)
            for idx, raw_sql in enumerate(sql_items):
                if not isinstance(raw_sql, dict):
                    continue
                firewall_rules: list[dict] | None = None
                if idx < _MAX_SQL_FIREWALL_FETCHES:
                    sql_rg = _parse_resource_group_from_id(
                        raw_sql.get("id", "")
                    )
                    sql_name = raw_sql.get("name", "")
                    if sql_rg and sql_name:
                        fw_url = (
                            f"{_MGMT_BASE}/subscriptions/{subscription_id}"
                            f"/resourceGroups/{sql_rg}"
                            f"/providers/Microsoft.Sql/servers/{sql_name}"
                            f"/firewallRules"
                            f"?api-version={_API_VERSION_SQL_SERVER}"
                        )
                        try:
                            fw_resp = self._get(token, fw_url)
                            if isinstance(fw_resp, dict):
                                fw_list = fw_resp.get("value", [])
                                if isinstance(fw_list, list):
                                    firewall_rules = fw_list
                        except Exception as exc:
                            logger.warning(
                                "azure: failed to fetch firewall rules for %s: %s",
                                _trunc(sql_name),
                                _trunc(str(exc)),
                            )
                try:
                    records.append(
                        self._normalize_sql_server(raw_sql, firewall_rules)
                    )
                except Exception as exc:
                    logger.warning(
                        "azure: failed to normalise SQL server %s: %s",
                        _trunc(raw_sql.get("name", "")),
                        _trunc(str(exc)),
                    )
        except Exception as exc:
            logger.warning(
                "azure: failed to fetch SQL servers: %s",
                _trunc(str(exc)),
            )

        # ── 9. AKS clusters (M77C) ────────────────────────────────────────────
        try:
            aks_url = (
                f"{_MGMT_BASE}/subscriptions/{subscription_id}"
                f"/providers/Microsoft.ContainerService/managedClusters"
                f"?api-version={_API_VERSION_AKS}"
            )
            aks_items = self._paginate(token, aks_url)
            for raw_aks in aks_items:
                if isinstance(raw_aks, dict):
                    try:
                        records.append(self._normalize_aks_cluster(raw_aks))
                    except Exception as exc:
                        logger.warning(
                            "azure: failed to normalise AKS cluster %s: %s",
                            _trunc(raw_aks.get("name", "")),
                            _trunc(str(exc)),
                        )
        except Exception as exc:
            logger.warning(
                "azure: failed to fetch AKS clusters: %s",
                _trunc(str(exc)),
            )

        logger.info(
            "azure: fetch complete — %d records collected for subscription %s",
            len(records),
            _trunc(subscription_id),
        )
        return records
