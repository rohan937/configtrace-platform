"""Azure drift provider connector — M77A: Subscription, Resource Groups, NSGs,
Storage Accounts, Key Vaults.

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
            "record_type": "AZURE_SUBSCRIPTION",
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
            "record_type": "AZURE_RESOURCE_GROUP",
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
            "record_type": "AZURE_NETWORK_SECURITY_GROUP",
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
            "record_type": "AZURE_STORAGE_ACCOUNT",
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
            "record_type": "AZURE_KEY_VAULT",
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

        logger.info(
            "azure: fetch complete — %d records collected for subscription %s",
            len(records),
            _trunc(subscription_id),
        )
        return records
