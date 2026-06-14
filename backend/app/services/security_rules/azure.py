"""Azure security / configuration-risk rules — M77B + M77C.

Every rule fires only on explicit, reliable normalized fields produced by the
Azure connector (app/connectors/azure.py + azure_schema.py). Evidence is
metadata-only: resource group + location + posture booleans + setting NAMES.
Customer data, database contents, app setting names/values, connection strings,
Key Vault secret names/values, certificate material, key material, storage
account keys, SAS tokens, principal IDs/emails/object IDs, kubeconfig, raw API
responses, bearer tokens, authorization headers, request/response bodies, and
PII are NEVER read, stored, or surfaced by the connector.

CLAIM DISCIPLINE
----------------
These are configuration risks, not confirmed incidents. Copy says "may
expose attached resources", "may broaden access", "may increase
configuration risk", "evidence for review", and "does not confirm
compromise, unauthorized access, or data exposure". It never asserts that
secrets were leaked, customer data was disclosed, an attacker is present,
data was exposed, or a breach / attack occurred.

M77B record types (10 rules)
-----------------------------
- ``azure_network_security_group`` → public admin ingress / broad public ingress
- ``azure_storage_account``        → public blob access / public network access /
                                      weak TLS / shared-key authorization
- ``azure_key_vault``              → public network access / purge protection /
                                      soft delete / legacy access policies

M77C record types (10 rules)
-----------------------------
- ``azure_role_assignment``  → broad privilege (Owner/Contributor/UAA at
                               subscription or resource-group scope)
- ``azure_app_service``      → HTTPS disabled / FTP enabled / weak TLS /
                               public network access
- ``azure_sql_server``       → public network access / weak TLS
- ``azure_aks_cluster``      → local accounts enabled / public API access /
                               network policy missing

Explicitly deferred
-------------------
* azure_role_assignment_no_condition — ABAC condition fields are an optional
  Azure preview feature; absent condition is the normal state for most
  assignments, so this rule would be too noisy. Deferred to M77D+.
* azure_app_registration_* (3 rules) — Requires the Microsoft Graph API scope
  (https://graph.microsoft.com/.default), a different token endpoint and base
  URL. The ARM connector uses a single management-plane scope; mixing Graph API
  scope into the same connector would require a separate credential grant.
  Deferred to a dedicated Graph API expansion milestone.
* azure_subscription / azure_resource_group rules — no actionable posture
  surface available at these record types.
"""

from __future__ import annotations

from typing import Any

from app.connectors.azure_schema import (
    AZURE_AKS_CLUSTER,
    AZURE_APP_SERVICE,
    AZURE_KEY_VAULT,
    AZURE_NETWORK_SECURITY_GROUP,
    AZURE_ROLE_ASSIGNMENT,
    AZURE_SQL_SERVER,
    AZURE_STORAGE_ACCOUNT,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule keys ────────────────────────────────────────────────────────────────

_RULE_NSG_PUBLIC_ADMIN_INGRESS = "azure_nsg_public_admin_ingress"
_RULE_NSG_PUBLIC_BROAD_INGRESS = "azure_nsg_public_broad_ingress"
_RULE_STORAGE_PUBLIC_BLOB_ACCESS = "azure_storage_public_blob_access"
_RULE_STORAGE_PUBLIC_NETWORK_ACCESS = "azure_storage_public_network_access"
_RULE_STORAGE_WEAK_TLS = "azure_storage_weak_tls"
_RULE_STORAGE_SHARED_KEY_ENABLED = "azure_storage_shared_key_enabled"
_RULE_KEY_VAULT_PUBLIC_NETWORK_ACCESS = "azure_key_vault_public_network_access"
_RULE_KEY_VAULT_PURGE_PROTECTION_DISABLED = "azure_key_vault_purge_protection_disabled"
_RULE_KEY_VAULT_SOFT_DELETE_DISABLED = "azure_key_vault_soft_delete_disabled"
_RULE_KEY_VAULT_RBAC_DISABLED = "azure_key_vault_rbac_disabled"

# ── M77C rule keys ────────────────────────────────────────────────────────────

_RULE_ROLE_ASSIGNMENT_BROAD_PRIVILEGE = "azure_role_assignment_broad_privilege"

_RULE_APP_SERVICE_HTTPS_DISABLED = "azure_app_service_https_disabled"
_RULE_APP_SERVICE_FTP_ENABLED = "azure_app_service_ftp_enabled"
_RULE_APP_SERVICE_WEAK_TLS = "azure_app_service_weak_tls"
_RULE_APP_SERVICE_PUBLIC_NETWORK_ACCESS = "azure_app_service_public_network_access"

_RULE_SQL_PUBLIC_NETWORK_ACCESS = "azure_sql_public_network_access"
_RULE_SQL_WEAK_TLS = "azure_sql_weak_tls"

_RULE_AKS_LOCAL_ACCOUNTS_ENABLED = "azure_aks_local_accounts_enabled"
_RULE_AKS_PUBLIC_API_ACCESS = "azure_aks_public_api_access"
_RULE_AKS_NETWORK_POLICY_MISSING = "azure_aks_network_policy_missing"

AZURE_RULE_KEYS: frozenset[str] = frozenset({
    # M77B
    _RULE_NSG_PUBLIC_ADMIN_INGRESS,
    _RULE_NSG_PUBLIC_BROAD_INGRESS,
    _RULE_STORAGE_PUBLIC_BLOB_ACCESS,
    _RULE_STORAGE_PUBLIC_NETWORK_ACCESS,
    _RULE_STORAGE_WEAK_TLS,
    _RULE_STORAGE_SHARED_KEY_ENABLED,
    _RULE_KEY_VAULT_PUBLIC_NETWORK_ACCESS,
    _RULE_KEY_VAULT_PURGE_PROTECTION_DISABLED,
    _RULE_KEY_VAULT_SOFT_DELETE_DISABLED,
    _RULE_KEY_VAULT_RBAC_DISABLED,
    # M77C — Role Assignments
    _RULE_ROLE_ASSIGNMENT_BROAD_PRIVILEGE,
    # M77C — App Service
    _RULE_APP_SERVICE_HTTPS_DISABLED,
    _RULE_APP_SERVICE_FTP_ENABLED,
    _RULE_APP_SERVICE_WEAK_TLS,
    _RULE_APP_SERVICE_PUBLIC_NETWORK_ACCESS,
    # M77C — SQL Server
    _RULE_SQL_PUBLIC_NETWORK_ACCESS,
    _RULE_SQL_WEAK_TLS,
    # M77C — AKS
    _RULE_AKS_LOCAL_ACCOUNTS_ENABLED,
    _RULE_AKS_PUBLIC_API_ACCESS,
    _RULE_AKS_NETWORK_POLICY_MISSING,
})

# ── Shared constants ─────────────────────────────────────────────────────────

# Public-source prefixes as emitted by the M77A normalizer. The connector
# preserves Azure's canonical literals; we treat each as "public" because
# none of them constrain the source to a private network range.
_PUBLIC_SOURCE_PREFIXES: frozenset[str] = frozenset({
    "*",
    "0.0.0.0/0",
    "::/0",
    "Internet",
    "Any",
})

# Admin / database / cache / search ports. Each entry is a single port that
# we treat as administrative when allowed from a public source.
_ADMIN_PORTS_HIGH_SEVERITY: frozenset[int] = frozenset({
    3389,   # RDP
    5985,   # WinRM HTTP
    5986,   # WinRM HTTPS
    1433,   # SQL Server
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    9200,   # Elasticsearch
    27017,  # MongoDB
})
_ADMIN_PORTS_HIGH_LEVEL: frozenset[int] = frozenset({22})  # SSH (high, not critical)

# Broad/all-port indicators.
_ALL_PORT_LITERALS: frozenset[str] = frozenset({"*", "Any", "any", "ANY"})


def _common_disclaimer() -> str:
    return (
        "This is evidence for review and does not confirm compromise, "
        "unauthorized access, or data exposure."
    )


def _is_public_source(source_prefix: str) -> bool:
    """True when an NSG rule's source_address_prefix indicates a public source."""
    return source_prefix in _PUBLIC_SOURCE_PREFIXES


def _expand_destination_ports(dest_port_range: str) -> list[int]:
    """Best-effort parse of an Azure destination_port_range into integer ports.

    Returns an empty list when the value is broad ("*" / "Any") or unparseable.
    Only honors:
      * exact integer (e.g. "22")
      * single integer range (e.g. "8000-8010")
      * comma-separated (NSG `destinationPortRanges` may be flattened by some
        callers into "22,3389"; not the normal Azure shape for this field, but
        cheap to handle defensively).

    A genuinely broad value is returned as an empty list — broad-port rules are
    handled by the dedicated "broad public ingress" rule, not the admin-port
    rule.
    """
    s = (dest_port_range or "").strip()
    if not s or s in _ALL_PORT_LITERALS:
        return []
    out: list[int] = []
    for piece in s.split(","):
        piece = piece.strip()
        if not piece:
            continue
        if "-" in piece:
            lo_s, hi_s = piece.split("-", 1)
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                continue
            if 0 <= lo <= hi <= 65535 and (hi - lo) < 256:
                out.extend(range(lo, hi + 1))
        else:
            try:
                out.append(int(piece))
            except ValueError:
                continue
    return out


def _is_broad_destination_port(dest_port_range: str) -> bool:
    """True when destination_port_range covers "all ports" (Azure literals)."""
    s = (dest_port_range or "").strip()
    if s in _ALL_PORT_LITERALS:
        return True
    # Common "all ports" range shapes.
    if s in {"0-65535", "1-65535"}:
        return True
    return False


# ── M77C shared constants ─────────────────────────────────────────────────────

# Built-in Azure role names that constitute "broad privilege" for the
# role-assignment rule. These are the canonical Microsoft names.
_BROAD_PRIVILEGE_ROLES: frozenset[str] = frozenset({
    "Owner",
    "Contributor",
    "User Access Administrator",
})

# Scope types at which a broad role assignment is considered risky
_BROAD_SCOPE_TYPES: frozenset[str] = frozenset({"subscription", "resource_group"})

# App Service FTPS states that indicate unencrypted FTP is allowed
_FTP_WEAK_STATES: frozenset[str] = frozenset({"AllAllowed", "allallowed"})

# TLS version values considered weak
_WEAK_TLS_VERSIONS: frozenset[str] = frozenset({"1.0", "1.1"})

# AKS network policy values that mean "no policy"
_AKS_NO_POLICY: frozenset[str] = frozenset({"", "none", "None", "NONE"})


# ── Dispatcher ───────────────────────────────────────────────────────────────


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == AZURE_NETWORK_SECURITY_GROUP:
        return _eval_nsg(record)
    if rtype == AZURE_STORAGE_ACCOUNT:
        return _eval_storage_account(record)
    if rtype == AZURE_KEY_VAULT:
        return _eval_key_vault(record)
    # M77C
    if rtype == AZURE_ROLE_ASSIGNMENT:
        return _eval_role_assignment(record)
    if rtype == AZURE_APP_SERVICE:
        return _eval_app_service(record)
    if rtype == AZURE_SQL_SERVER:
        return _eval_sql_server(record)
    if rtype == AZURE_AKS_CLUSTER:
        return _eval_aks_cluster(record)
    return []


# ── Network Security Group ────────────────────────────────────────────────────


def _eval_nsg(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    nsg_name = get_str(record, "nsg_name")
    resource_group = get_str(record, "resource_group")
    location = get_str(record, "location")

    rules_summary = record.get("rules_summary")
    if not isinstance(rules_summary, list):
        return out

    # Emit at most one critical "broad" finding and at most one (per NSG)
    # "admin port" finding even if multiple rules match — we group by NSG to
    # avoid noisy fan-out. The highest-severity matching rule wins per group.
    broad_match: dict[str, Any] | None = None
    admin_match: dict[str, Any] | None = None
    admin_severity = "high"  # SSH-only default; bumps to critical on RDP/DB/etc.

    for rule in rules_summary:
        if not isinstance(rule, dict):
            continue
        direction = (rule.get("direction") or "").strip()
        access = (rule.get("access") or "").strip()
        if direction != "Inbound" or access != "Allow":
            continue
        src_prefix = (rule.get("source_address_prefix") or "").strip()
        if not _is_public_source(src_prefix):
            continue
        dest_port_range = (rule.get("destination_port_range") or "").strip()
        rule_name = get_str(rule, "rule_name")
        protocol = get_str(rule, "protocol")

        # B. Broad public inbound rule
        if _is_broad_destination_port(dest_port_range):
            if broad_match is None:
                broad_match = {
                    "rule_name": rule_name,
                    "source_address_prefix": src_prefix,
                    "destination_port_range": dest_port_range,
                    "protocol": protocol,
                }
            continue

        # A. Public admin/database/cache/search ingress
        ports = _expand_destination_ports(dest_port_range)
        if not ports:
            continue
        for p in ports:
            if p in _ADMIN_PORTS_HIGH_SEVERITY:
                # Critical wins outright.
                admin_match = {
                    "rule_name": rule_name,
                    "source_address_prefix": src_prefix,
                    "destination_port_range": dest_port_range,
                    "admin_port": p,
                    "protocol": protocol,
                }
                admin_severity = "critical"
                break
            if p in _ADMIN_PORTS_HIGH_LEVEL and admin_match is None:
                admin_match = {
                    "rule_name": rule_name,
                    "source_address_prefix": src_prefix,
                    "destination_port_range": dest_port_range,
                    "admin_port": p,
                    "protocol": protocol,
                }
                # Leave admin_severity = "high" (SSH).

    if broad_match is not None:
        out.append(
            FindingCandidate(
                provider="azure",
                rule_key=_RULE_NSG_PUBLIC_BROAD_INGRESS,
                finding_key=make_finding_key(_RULE_NSG_PUBLIC_BROAD_INGRESS, record_id),
                severity="critical",
                title="Azure NSG allows broad public inbound access",
                description=(
                    f"Network Security Group '{nsg_name}' in resource group "
                    f"'{resource_group}' has an inbound Allow rule "
                    f"('{broad_match['rule_name']}') that permits traffic from "
                    f"a public source ({broad_match['source_address_prefix']}) "
                    f"across all/many ports. This may expose resources using "
                    f"this NSG and may require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_NSG_PUBLIC_BROAD_INGRESS,
                    "nsg_name": nsg_name,
                    "resource_group": resource_group,
                    "location": location,
                    "rule_name": broad_match["rule_name"],
                    "source_address_prefix": broad_match["source_address_prefix"],
                    "destination_port_range": broad_match["destination_port_range"],
                    "protocol": broad_match["protocol"],
                    "public_source": True,
                },
                remediation={
                    "summary": (
                        "Tighten the NSG rule to a narrow source range and "
                        "specific ports, or remove the rule if it is no longer "
                        "needed."
                    ),
                    "steps": [
                        "Replace the public source prefix with a known IP range "
                        "(e.g. corporate VPN, jump host).",
                        "Limit the destination port range to only what the "
                        "service needs.",
                        "Confirm the resources behind this NSG actually require "
                        "this exposure.",
                    ],
                },
                record_id=record_id,
            )
        )

    if admin_match is not None:
        admin_port = admin_match["admin_port"]
        out.append(
            FindingCandidate(
                provider="azure",
                rule_key=_RULE_NSG_PUBLIC_ADMIN_INGRESS,
                finding_key=make_finding_key(_RULE_NSG_PUBLIC_ADMIN_INGRESS, record_id),
                severity=admin_severity,
                title="Azure NSG allows public inbound on an administrative port",
                description=(
                    f"Network Security Group '{nsg_name}' in resource group "
                    f"'{resource_group}' has an inbound Allow rule "
                    f"('{admin_match['rule_name']}') that permits traffic from "
                    f"a public source ({admin_match['source_address_prefix']}) "
                    f"to port {admin_port}. This may expose attached resources "
                    f"and may require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_NSG_PUBLIC_ADMIN_INGRESS,
                    "nsg_name": nsg_name,
                    "resource_group": resource_group,
                    "location": location,
                    "rule_name": admin_match["rule_name"],
                    "source_address_prefix": admin_match["source_address_prefix"],
                    "destination_port_range": admin_match["destination_port_range"],
                    "admin_port": admin_port,
                    "protocol": admin_match["protocol"],
                    "public_source": True,
                },
                remediation={
                    "summary": (
                        "Restrict source to a known IP range (e.g. VPN/jump "
                        "host) or remove the rule."
                    ),
                    "steps": [
                        "Replace the public source prefix with a known IP range.",
                        "Confirm the service actually needs to listen on this "
                        "port.",
                        "Consider a Bastion/Just-In-Time access approach for "
                        "administrative ports.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Storage Accounts ─────────────────────────────────────────────────────────


def _eval_storage_account(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    account_name = get_str(record, "account_name")
    resource_group = get_str(record, "resource_group")
    location = get_str(record, "location")

    allow_blob_public_access = record.get("allow_blob_public_access")
    public_network_access = get_str(record, "public_network_access")
    network_default_action = get_str(record, "network_default_action")
    minimum_tls_version = get_str(record, "minimum_tls_version")
    shared_access_key_enabled = record.get("shared_access_key_enabled")

    # C. Storage account public blob access enabled
    if allow_blob_public_access is True:
        out.append(
            FindingCandidate(
                provider="azure",
                rule_key=_RULE_STORAGE_PUBLIC_BLOB_ACCESS,
                finding_key=make_finding_key(_RULE_STORAGE_PUBLIC_BLOB_ACCESS, record_id),
                severity="high",
                title="Azure Storage account permits public blob access",
                description=(
                    f"Storage account '{account_name}' in resource group "
                    f"'{resource_group}' permits public blob access at the "
                    f"account level. Containers/blobs may be made public and "
                    f"this may require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_STORAGE_PUBLIC_BLOB_ACCESS,
                    "account_name": account_name,
                    "resource_group": resource_group,
                    "location": location,
                    "allow_blob_public_access": True,
                },
                remediation={
                    "summary": (
                        "Set allowBlobPublicAccess=false on the storage account, "
                        "or scope container ACLs explicitly."
                    ),
                    "steps": [
                        "Set 'Allow Blob public access' to disabled in the "
                        "Storage account configuration.",
                        "Audit each container's public access level.",
                    ],
                },
                record_id=record_id,
            )
        )

    # D. Storage account public network access enabled
    public_net = public_network_access.lower()
    is_public_network = public_net == "enabled" or public_net == "true"
    default_action_allow = network_default_action.lower() == "allow"
    if is_public_network:
        sev = "high" if default_action_allow else "medium"
        out.append(
            FindingCandidate(
                provider="azure",
                rule_key=_RULE_STORAGE_PUBLIC_NETWORK_ACCESS,
                finding_key=make_finding_key(_RULE_STORAGE_PUBLIC_NETWORK_ACCESS, record_id),
                severity=sev,
                title="Azure Storage account allows public network access",
                description=(
                    f"Storage account '{account_name}' in resource group "
                    f"'{resource_group}' has public network access enabled"
                    + (
                        " with default network action Allow"
                        if default_action_allow
                        else ""
                    )
                    + ". This may broaden access to the storage account and "
                    "may require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_STORAGE_PUBLIC_NETWORK_ACCESS,
                    "account_name": account_name,
                    "resource_group": resource_group,
                    "location": location,
                    "public_network_access": public_network_access,
                    "network_default_action": network_default_action,
                },
                remediation={
                    "summary": (
                        "Restrict to selected networks (VNet rules / Private "
                        "Endpoint) or disable public network access."
                    ),
                    "steps": [
                        "Set Public network access to 'Disabled' or 'Enabled "
                        "from selected virtual networks and IP addresses'.",
                        "Configure default network rule action to 'Deny' and "
                        "add explicit allow rules.",
                    ],
                },
                record_id=record_id,
            )
        )

    # E. Storage account weak TLS
    tls = minimum_tls_version.strip()
    weak_tls = False
    if not tls:
        weak_tls = False  # Missing field is not a confirmed downgrade.
    else:
        # Azure literal values: "TLS1_0", "TLS1_1", "TLS1_2", "TLS1_3"
        if tls in {"TLS1_0", "TLS1_1"}:
            weak_tls = True
    if weak_tls:
        out.append(
            FindingCandidate(
                provider="azure",
                rule_key=_RULE_STORAGE_WEAK_TLS,
                finding_key=make_finding_key(_RULE_STORAGE_WEAK_TLS, record_id),
                severity="medium",
                title="Azure Storage account allows TLS below 1.2",
                description=(
                    f"Storage account '{account_name}' in resource group "
                    f"'{resource_group}' has minimum_tls_version set to "
                    f"'{tls}', which is below TLS 1.2. This may allow weak "
                    f"transport on connections and may require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_STORAGE_WEAK_TLS,
                    "account_name": account_name,
                    "resource_group": resource_group,
                    "location": location,
                    "minimum_tls_version": tls,
                },
                remediation={
                    "summary": "Set minimum_tls_version to TLS1_2 (or TLS1_3).",
                    "steps": [
                        "Update the storage account's minimumTlsVersion to "
                        "'TLS1_2'.",
                        "Confirm dependent clients support TLS 1.2.",
                    ],
                },
                record_id=record_id,
            )
        )

    # F. Storage account shared key access enabled
    if shared_access_key_enabled is True:
        out.append(
            FindingCandidate(
                provider="azure",
                rule_key=_RULE_STORAGE_SHARED_KEY_ENABLED,
                finding_key=make_finding_key(_RULE_STORAGE_SHARED_KEY_ENABLED, record_id),
                severity="medium",
                title="Azure Storage account permits shared-key authorization",
                description=(
                    f"Storage account '{account_name}' in resource group "
                    f"'{resource_group}' permits shared-key authorization. "
                    f"Disabling shared-key access in favor of Azure AD "
                    f"(Entra ID) may reduce credential-management risk and may "
                    f"require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_STORAGE_SHARED_KEY_ENABLED,
                    "account_name": account_name,
                    "resource_group": resource_group,
                    "location": location,
                    "shared_access_key_enabled": True,
                },
                remediation={
                    "summary": (
                        "Disable shared-key access and use Azure AD / Entra ID "
                        "identities to authorize storage access."
                    ),
                    "steps": [
                        "Migrate clients to Azure AD-based authorization "
                        "(RBAC).",
                        "Set allowSharedKeyAccess=false on the storage "
                        "account.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Key Vaults ───────────────────────────────────────────────────────────────


def _eval_key_vault(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    vault_name = get_str(record, "vault_name")
    resource_group = get_str(record, "resource_group")
    location = get_str(record, "location")

    enable_rbac_authorization = record.get("enable_rbac_authorization")
    public_network_access = get_str(record, "public_network_access")
    network_default_action = get_str(record, "network_default_action")
    soft_delete_enabled = record.get("soft_delete_enabled")
    purge_protection_enabled = record.get("purge_protection_enabled")
    access_policy_count_raw = record.get("access_policy_count")
    access_policy_count = (
        access_policy_count_raw if isinstance(access_policy_count_raw, int) else 0
    )

    # G. Key Vault public network access enabled
    public_net = public_network_access.lower()
    is_public_network = public_net == "enabled" or public_net == "true"
    default_action_allow = network_default_action.lower() == "allow"
    if is_public_network:
        sev = "high" if default_action_allow else "medium"
        out.append(
            FindingCandidate(
                provider="azure",
                rule_key=_RULE_KEY_VAULT_PUBLIC_NETWORK_ACCESS,
                finding_key=make_finding_key(_RULE_KEY_VAULT_PUBLIC_NETWORK_ACCESS, record_id),
                severity=sev,
                title="Azure Key Vault allows public network access",
                description=(
                    f"Key Vault '{vault_name}' in resource group "
                    f"'{resource_group}' has public network access enabled"
                    + (
                        " with default network action Allow"
                        if default_action_allow
                        else ""
                    )
                    + ". This may broaden access to Key Vault endpoints and "
                    "may require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_KEY_VAULT_PUBLIC_NETWORK_ACCESS,
                    "vault_name": vault_name,
                    "resource_group": resource_group,
                    "location": location,
                    "public_network_access": public_network_access,
                    "network_default_action": network_default_action,
                },
                remediation={
                    "summary": (
                        "Restrict Key Vault to selected networks (Private "
                        "Endpoint / VNet) or disable public network access."
                    ),
                    "steps": [
                        "Set Public network access to 'Disabled' or 'Enabled "
                        "from specific virtual networks and IP addresses'.",
                        "Configure default network rule action to 'Deny'.",
                    ],
                },
                record_id=record_id,
            )
        )

    # H. Key Vault purge protection disabled
    if purge_protection_enabled is False:
        # Severity bumps to high when soft_delete is also off (no recovery
        # surface at all if a delete were to occur).
        sev = "high" if soft_delete_enabled is False else "medium"
        out.append(
            FindingCandidate(
                provider="azure",
                rule_key=_RULE_KEY_VAULT_PURGE_PROTECTION_DISABLED,
                finding_key=make_finding_key(
                    _RULE_KEY_VAULT_PURGE_PROTECTION_DISABLED, record_id
                ),
                severity=sev,
                title="Azure Key Vault has purge protection disabled",
                description=(
                    f"Key Vault '{vault_name}' in resource group "
                    f"'{resource_group}' does not have purge protection "
                    f"enabled. This may affect recoverability if vault "
                    f"contents are removed and may require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_KEY_VAULT_PURGE_PROTECTION_DISABLED,
                    "vault_name": vault_name,
                    "resource_group": resource_group,
                    "location": location,
                    "purge_protection_enabled": False,
                    "soft_delete_enabled": soft_delete_enabled,
                },
                remediation={
                    "summary": (
                        "Enable purge protection on the Key Vault."
                    ),
                    "steps": [
                        "Set enablePurgeProtection=true on the vault.",
                        "Confirm soft delete is also enabled.",
                    ],
                },
                record_id=record_id,
            )
        )

    # I. Key Vault soft delete disabled
    if soft_delete_enabled is False:
        out.append(
            FindingCandidate(
                provider="azure",
                rule_key=_RULE_KEY_VAULT_SOFT_DELETE_DISABLED,
                finding_key=make_finding_key(
                    _RULE_KEY_VAULT_SOFT_DELETE_DISABLED, record_id
                ),
                severity="medium",
                title="Azure Key Vault has soft delete disabled",
                description=(
                    f"Key Vault '{vault_name}' in resource group "
                    f"'{resource_group}' has soft delete disabled. This may "
                    f"affect recoverability of removed contents and may "
                    f"require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_KEY_VAULT_SOFT_DELETE_DISABLED,
                    "vault_name": vault_name,
                    "resource_group": resource_group,
                    "location": location,
                    "soft_delete_enabled": False,
                },
                remediation={
                    "summary": "Enable soft delete on the Key Vault.",
                    "steps": [
                        "Set enableSoftDelete=true on the vault.",
                    ],
                },
                record_id=record_id,
            )
        )

    # J. Key Vault RBAC disabled / legacy access policies
    # Only fires when access policies exist (count > 0) and RBAC is explicitly
    # disabled. Missing/unknown is skipped to avoid false positives.
    if enable_rbac_authorization is False and access_policy_count > 0:
        out.append(
            FindingCandidate(
                provider="azure",
                rule_key=_RULE_KEY_VAULT_RBAC_DISABLED,
                finding_key=make_finding_key(_RULE_KEY_VAULT_RBAC_DISABLED, record_id),
                severity="medium",
                title="Azure Key Vault uses legacy access policies instead of RBAC",
                description=(
                    f"Key Vault '{vault_name}' in resource group "
                    f"'{resource_group}' uses access policies "
                    f"({access_policy_count} configured) instead of Azure "
                    f"RBAC. This may complicate access governance and may "
                    f"require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_KEY_VAULT_RBAC_DISABLED,
                    "vault_name": vault_name,
                    "resource_group": resource_group,
                    "location": location,
                    "enable_rbac_authorization": False,
                    "access_policy_count": access_policy_count,
                },
                remediation={
                    "summary": (
                        "Migrate Key Vault permissions to Azure RBAC and "
                        "enable RBAC authorization."
                    ),
                    "steps": [
                        "Map each access policy assignment to an equivalent "
                        "Azure RBAC role assignment.",
                        "Set enableRbacAuthorization=true on the vault.",
                        "Remove legacy access policies after verifying RBAC "
                        "coverage.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── M77C: Role Assignments ────────────────────────────────────────────────────


def _eval_role_assignment(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    assignment_id = get_str(record, "assignment_id")
    scope_type = get_str(record, "scope_type")
    resource_group = get_str(record, "resource_group")
    role_definition_name = get_str(record, "role_definition_name")
    principal_type = get_str(record, "principal_type")
    condition_present = record.get("condition_present")

    if role_definition_name not in _BROAD_PRIVILEGE_ROLES:
        return out
    if scope_type not in _BROAD_SCOPE_TYPES:
        return out

    sev = "high" if scope_type == "subscription" else "medium"
    scope_desc = (
        "subscription scope"
        if scope_type == "subscription"
        else (
            f"resource-group scope (resource group: '{resource_group}')"
            if resource_group
            else "resource-group scope"
        )
    )

    evidence: dict[str, Any] = {
        "rule": _RULE_ROLE_ASSIGNMENT_BROAD_PRIVILEGE,
        "assignment_id": assignment_id,
        "scope_type": scope_type,
        "role_definition_name": role_definition_name,
        "principal_type": principal_type,
    }
    if resource_group:
        evidence["resource_group"] = resource_group
    if condition_present is not None:
        evidence["condition_present"] = condition_present

    out.append(
        FindingCandidate(
            provider="azure",
            rule_key=_RULE_ROLE_ASSIGNMENT_BROAD_PRIVILEGE,
            finding_key=make_finding_key(_RULE_ROLE_ASSIGNMENT_BROAD_PRIVILEGE, record_id),
            severity=sev,
            title=(
                f"Azure role assignment grants '{role_definition_name}' "
                f"at {scope_type.replace('_', ' ')} scope"
            ),
            description=(
                f"A role assignment grants the '{role_definition_name}' role "
                f"(principal_type: {principal_type or 'unknown'}) at "
                f"{scope_desc}. This may increase access-governance risk and "
                f"may require review. "
                f"{_common_disclaimer()}"
            ),
            evidence=evidence,
            remediation={
                "summary": (
                    "Review whether this broad role assignment is still "
                    "required. Consider narrower built-in roles (e.g. Reader, "
                    "resource-specific roles) or Azure RBAC conditions to limit "
                    "the effective access scope."
                ),
                "steps": [
                    "Confirm the assignment is intentional and business-justified.",
                    "Consider replacing with a narrower built-in or custom role.",
                    "Add an Azure ABAC condition to restrict the effective scope if needed.",
                    "Review subscription and resource-group scope assignments on a schedule.",
                ],
            },
            record_id=record_id,
        )
    )
    return out


# ── M77C: App Service ─────────────────────────────────────────────────────────


def _eval_app_service(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    app_name = get_str(record, "app_name")
    resource_group = get_str(record, "resource_group")
    location = get_str(record, "location")
    kind = get_str(record, "kind")

    https_only = record.get("https_only")
    public_network_access = get_str(record, "public_network_access")
    ftps_state = record.get("ftps_state") or ""
    min_tls_version = record.get("min_tls_version") or ""

    def _base_ev(**extra: Any) -> dict[str, Any]:
        ev: dict[str, Any] = {"app_name": app_name, "resource_group": resource_group, "location": location}
        if kind:
            ev["kind"] = kind
        ev.update(extra)
        return ev

    if https_only is False:
        out.append(FindingCandidate(
            provider="azure",
            rule_key=_RULE_APP_SERVICE_HTTPS_DISABLED,
            finding_key=make_finding_key(_RULE_APP_SERVICE_HTTPS_DISABLED, record_id),
            severity="high",
            title="Azure App Service does not enforce HTTPS",
            description=(
                f"App Service '{app_name}' in resource group '{resource_group}' "
                f"has httpsOnly=false, which permits unencrypted HTTP connections. "
                f"This may allow plaintext traffic and may require review. "
                f"{_common_disclaimer()}"
            ),
            evidence=_base_ev(rule=_RULE_APP_SERVICE_HTTPS_DISABLED, https_only=False),
            remediation={
                "summary": "Enable 'HTTPS Only' on the App Service.",
                "steps": [
                    "Open the App Service → TLS/SSL settings and set 'HTTPS Only' to On.",
                ],
            },
            record_id=record_id,
        ))

    if isinstance(ftps_state, str) and ftps_state in _FTP_WEAK_STATES:
        out.append(FindingCandidate(
            provider="azure",
            rule_key=_RULE_APP_SERVICE_FTP_ENABLED,
            finding_key=make_finding_key(_RULE_APP_SERVICE_FTP_ENABLED, record_id),
            severity="medium",
            title="Azure App Service allows unencrypted FTP access",
            description=(
                f"App Service '{app_name}' in resource group '{resource_group}' "
                f"has ftpsState='{ftps_state}', which permits unencrypted FTP "
                f"connections. This may allow credentials or data to transit in "
                f"cleartext and may require review. "
                f"{_common_disclaimer()}"
            ),
            evidence=_base_ev(rule=_RULE_APP_SERVICE_FTP_ENABLED, ftps_state=ftps_state),
            remediation={
                "summary": "Set FTP state to 'FTPS Only' or 'Disabled'.",
                "steps": [
                    "In App Service → Configuration → General Settings, "
                    "set FTP state to 'FTPS Only' or 'Disabled'.",
                ],
            },
            record_id=record_id,
        ))

    if isinstance(min_tls_version, str) and min_tls_version in _WEAK_TLS_VERSIONS:
        out.append(FindingCandidate(
            provider="azure",
            rule_key=_RULE_APP_SERVICE_WEAK_TLS,
            finding_key=make_finding_key(_RULE_APP_SERVICE_WEAK_TLS, record_id),
            severity="medium",
            title="Azure App Service allows TLS below 1.2",
            description=(
                f"App Service '{app_name}' in resource group '{resource_group}' "
                f"has minimum TLS version set to '{min_tls_version}'. This may "
                f"permit weak transport on connections and may require review. "
                f"{_common_disclaimer()}"
            ),
            evidence=_base_ev(rule=_RULE_APP_SERVICE_WEAK_TLS, min_tls_version=min_tls_version),
            remediation={
                "summary": "Raise the minimum TLS version to 1.2 or higher.",
                "steps": [
                    "In App Service → TLS/SSL settings, set Minimum TLS Version to 1.2.",
                ],
            },
            record_id=record_id,
        ))

    pna = public_network_access.lower()
    if pna in ("enabled", "true"):
        out.append(FindingCandidate(
            provider="azure",
            rule_key=_RULE_APP_SERVICE_PUBLIC_NETWORK_ACCESS,
            finding_key=make_finding_key(_RULE_APP_SERVICE_PUBLIC_NETWORK_ACCESS, record_id),
            severity="medium",
            title="Azure App Service allows public network access",
            description=(
                f"App Service '{app_name}' in resource group '{resource_group}' "
                f"has public network access enabled. This may broaden the network "
                f"attack surface and may require review. "
                f"{_common_disclaimer()}"
            ),
            evidence=_base_ev(
                rule=_RULE_APP_SERVICE_PUBLIC_NETWORK_ACCESS,
                public_network_access=public_network_access,
            ),
            remediation={
                "summary": "Use VNet integration or private endpoints where public access is not required.",
                "steps": [
                    "In App Service → Networking, configure access restrictions or use a private endpoint.",
                    "Disable public network access if the app is only accessed from within a VNet.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── M77C: SQL Servers ─────────────────────────────────────────────────────────


def _eval_sql_server(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    server_name = get_str(record, "server_name")
    resource_group = get_str(record, "resource_group")
    location = get_str(record, "location")

    public_network_access = get_str(record, "public_network_access")
    minimum_tls_version = get_str(record, "minimum_tls_version")
    has_allow_azure_services = record.get("has_allow_azure_services_rule")
    firewall_rule_count = record.get("firewall_rule_count")

    def _base_ev(**extra: Any) -> dict[str, Any]:
        ev: dict[str, Any] = {"server_name": server_name, "resource_group": resource_group, "location": location}
        ev.update(extra)
        return ev

    pna = public_network_access.lower()
    if pna in ("enabled", "true"):
        sev = "high" if has_allow_azure_services is True else "medium"
        ev: dict[str, Any] = _base_ev(rule=_RULE_SQL_PUBLIC_NETWORK_ACCESS, public_network_access=public_network_access)
        if isinstance(firewall_rule_count, int):
            ev["firewall_rule_count"] = firewall_rule_count
        if has_allow_azure_services is not None:
            ev["has_allow_azure_services_rule"] = has_allow_azure_services
        out.append(FindingCandidate(
            provider="azure",
            rule_key=_RULE_SQL_PUBLIC_NETWORK_ACCESS,
            finding_key=make_finding_key(_RULE_SQL_PUBLIC_NETWORK_ACCESS, record_id),
            severity=sev,
            title="Azure SQL Server allows public network access",
            description=(
                f"SQL Server '{server_name}' in resource group '{resource_group}' "
                f"has public network access enabled"
                + (" with the 'Allow Azure services' firewall rule present" if has_allow_azure_services is True else "")
                + ". This may broaden access to the SQL endpoint and may require review. "
                f"{_common_disclaimer()}"
            ),
            evidence=ev,
            remediation={
                "summary": "Disable public network access and use private endpoints.",
                "steps": [
                    "Set Public network access to 'Disable' on the SQL Server.",
                    "Configure a Private Endpoint for secure VNet access.",
                    "Remove the 'Allow Azure services' rule if Private Endpoint is used.",
                ],
            },
            record_id=record_id,
        ))

    if minimum_tls_version and minimum_tls_version in _WEAK_TLS_VERSIONS:
        out.append(FindingCandidate(
            provider="azure",
            rule_key=_RULE_SQL_WEAK_TLS,
            finding_key=make_finding_key(_RULE_SQL_WEAK_TLS, record_id),
            severity="medium",
            title="Azure SQL Server allows TLS below 1.2",
            description=(
                f"SQL Server '{server_name}' in resource group '{resource_group}' "
                f"has minimum TLS version set to '{minimum_tls_version}'. This may "
                f"permit weak transport on client connections and may require review. "
                f"{_common_disclaimer()}"
            ),
            evidence=_base_ev(rule=_RULE_SQL_WEAK_TLS, minimum_tls_version=minimum_tls_version),
            remediation={
                "summary": "Raise the minimum TLS version to 1.2 or higher.",
                "steps": [
                    "In the SQL Server Firewalls and virtual networks settings, "
                    "set Minimum TLS Version to 1.2.",
                ],
            },
            record_id=record_id,
        ))

    return out


# ── M77C: AKS Clusters ───────────────────────────────────────────────────────


def _eval_aks_cluster(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    cluster_name = get_str(record, "cluster_name")
    resource_group = get_str(record, "resource_group")
    location = get_str(record, "location")

    private_cluster_enabled = record.get("private_cluster_enabled")
    local_account_disabled = record.get("local_account_disabled")
    network_policy = get_str(record, "network_policy")
    ip_range_count_raw = record.get("api_server_authorized_ip_range_count")
    ip_range_count = ip_range_count_raw if isinstance(ip_range_count_raw, int) else None

    def _base_ev(**extra: Any) -> dict[str, Any]:
        ev: dict[str, Any] = {"cluster_name": cluster_name, "resource_group": resource_group, "location": location}
        ev.update(extra)
        return ev

    if local_account_disabled is False:
        out.append(FindingCandidate(
            provider="azure",
            rule_key=_RULE_AKS_LOCAL_ACCOUNTS_ENABLED,
            finding_key=make_finding_key(_RULE_AKS_LOCAL_ACCOUNTS_ENABLED, record_id),
            severity="medium",
            title="Azure AKS cluster has local accounts enabled",
            description=(
                f"AKS cluster '{cluster_name}' in resource group '{resource_group}' "
                f"has local Kubernetes accounts enabled (disableLocalAccounts=false). "
                f"Local accounts bypass Azure AD authentication and may increase "
                f"access-control risk. This may require review. "
                f"{_common_disclaimer()}"
            ),
            evidence=_base_ev(rule=_RULE_AKS_LOCAL_ACCOUNTS_ENABLED, local_account_disabled=False),
            remediation={
                "summary": "Disable local accounts to enforce Azure AD authentication.",
                "steps": [
                    "Set disableLocalAccounts=true on the AKS cluster.",
                    "Ensure Azure AD integration (AAD profile) is configured before disabling local accounts.",
                ],
            },
            record_id=record_id,
        ))

    if private_cluster_enabled is False and ip_range_count == 0:
        out.append(FindingCandidate(
            provider="azure",
            rule_key=_RULE_AKS_PUBLIC_API_ACCESS,
            finding_key=make_finding_key(_RULE_AKS_PUBLIC_API_ACCESS, record_id),
            severity="high",
            title="Azure AKS API server is publicly accessible with no IP restrictions",
            description=(
                f"AKS cluster '{cluster_name}' in resource group '{resource_group}' "
                f"has a public API server (privateCluster=false) with no authorized "
                f"IP ranges configured. This may expose the Kubernetes API server to "
                f"the internet and may require review. "
                f"{_common_disclaimer()}"
            ),
            evidence=_base_ev(
                rule=_RULE_AKS_PUBLIC_API_ACCESS,
                private_cluster_enabled=False,
                api_server_authorized_ip_range_count=0,
            ),
            remediation={
                "summary": "Restrict API server access via private cluster or authorized IP ranges.",
                "steps": [
                    "Enable private cluster (enablePrivateCluster=true) to remove the public endpoint.",
                    "If a public API server is required, configure authorizedIPRanges.",
                ],
            },
            record_id=record_id,
        ))

    np = network_policy.strip().lower() if network_policy else ""
    if np in _AKS_NO_POLICY:
        out.append(FindingCandidate(
            provider="azure",
            rule_key=_RULE_AKS_NETWORK_POLICY_MISSING,
            finding_key=make_finding_key(_RULE_AKS_NETWORK_POLICY_MISSING, record_id),
            severity="medium",
            title="Azure AKS cluster has no network policy configured",
            description=(
                f"AKS cluster '{cluster_name}' in resource group '{resource_group}' "
                f"does not have a Kubernetes network policy configured "
                f"(networkPolicy='{network_policy or 'none'}'). Without a network "
                f"policy, pod-to-pod traffic is unrestricted within the cluster. "
                f"This may require review. "
                f"{_common_disclaimer()}"
            ),
            evidence=_base_ev(rule=_RULE_AKS_NETWORK_POLICY_MISSING, network_policy=network_policy or ""),
            remediation={
                "summary": "Configure a Kubernetes network policy (Azure NPM, Calico, or Cilium).",
                "steps": [
                    "Set networkPolicy to 'azure', 'calico', or 'cilium' in the AKS network profile.",
                    "Define Kubernetes NetworkPolicy resources to control pod-to-pod traffic.",
                ],
            },
            record_id=record_id,
        ))

    return out
