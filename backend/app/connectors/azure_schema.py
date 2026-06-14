"""Azure connector record type constants — M77A / M77C.

M77A scope
----------
    azure_subscription          — top-level billing/RBAC boundary
    azure_resource_group        — logical container for resources within a subscription
    azure_network_security_group — NSG rules controlling inbound/outbound traffic
    azure_storage_account       — Blob/Queue/Table/File storage configuration posture
    azure_key_vault             — Key Vault metadata (keys/secrets/certs NEVER read)

M77C scope (added in this file)
--------------------------------
    azure_role_assignment       — RBAC role assignment scope and role metadata
                                  (principal IDs and emails are NEVER stored)
    azure_app_service           — App Service / Web App runtime and TLS config
                                  (app setting names/values NEVER stored)
    azure_sql_server            — Azure SQL Server firewall and TLS posture
                                  (login names and passwords NEVER stored)
    azure_aks_cluster           — AKS cluster network, RBAC, and access posture
                                  (kubeconfig, certs, node names NEVER stored)

Deferred until M77D+
---------------------
    azure_app_registration / azure_service_principal
        — Requires the Microsoft Graph API scope
          (https://graph.microsoft.com/.default), a different token endpoint
          and base URL from the ARM connector used here. Deferred to keep the
          connector to a single auth scope. App registration rules are therefore
          deferred as well.
"""
from __future__ import annotations

# ── M77A record types ─────────────────────────────────────────────────────────

AZURE_SUBSCRIPTION = "azure_subscription"
AZURE_RESOURCE_GROUP = "azure_resource_group"
AZURE_NETWORK_SECURITY_GROUP = "azure_network_security_group"
AZURE_STORAGE_ACCOUNT = "azure_storage_account"
AZURE_KEY_VAULT = "azure_key_vault"

# ── M77C record types ─────────────────────────────────────────────────────────

# One per role assignment visible from the subscription scope.
# SECURITY: principalId (object ID) is NEVER stored; only principalType
# (User / Group / ServicePrincipal — not PII) is kept.
AZURE_ROLE_ASSIGNMENT = "azure_role_assignment"

# One per App Service / Function App site.
# SECURITY: app setting names/values, connection string names/values,
# deployment slot credentials, and logs are NEVER stored — only counts.
AZURE_APP_SERVICE = "azure_app_service"

# One per Azure SQL logical server.
# SECURITY: administrator login name and password are NEVER stored;
# database contents, usernames, and firewall rule creator identity are excluded.
AZURE_SQL_SERVER = "azure_sql_server"

# One per AKS managed cluster.
# SECURITY: kubeconfig, cluster credentials, certificates, and node/pod data
# are NEVER stored.
AZURE_AKS_CLUSTER = "azure_aks_cluster"

# ── Deferred: requires Graph API ─────────────────────────────────────────────
# AZURE_APP_REGISTRATION = "azure_app_registration"
# AZURE_SERVICE_PRINCIPAL = "azure_service_principal"

# ── Aggregate set ─────────────────────────────────────────────────────────────

AZURE_RECORD_TYPES: frozenset[str] = frozenset({
    AZURE_SUBSCRIPTION,
    AZURE_RESOURCE_GROUP,
    AZURE_NETWORK_SECURITY_GROUP,
    AZURE_STORAGE_ACCOUNT,
    AZURE_KEY_VAULT,
    # M77C
    AZURE_ROLE_ASSIGNMENT,
    AZURE_APP_SERVICE,
    AZURE_SQL_SERVER,
    AZURE_AKS_CLUSTER,
})
