"""Azure connector record type constants — M77A.

M77A scope (this file)
----------------------
Defines the five core Azure resource surfaces ingested in the initial
Azure connector milestone:

    azure_subscription          — top-level billing/RBAC boundary
    azure_resource_group        — logical container for resources within a subscription
    azure_network_security_group — NSG rules controlling inbound/outbound traffic
    azure_storage_account       — Blob/Queue/Table/File storage configuration posture
    azure_key_vault             — Key Vault metadata (keys/secrets/certs NEVER read)

M77C deferred surfaces
-----------------------
The following record types are scoped to M77C and are intentionally omitted
from AZURE_RECORD_TYPES until that milestone lands:

    azure_app_service           — App Service / Web App runtime and TLS config
    azure_sql_server            — Azure SQL Server firewall and TDE posture
    azure_aks_cluster           — AKS cluster network, RBAC, and add-on posture
    azure_app_registration      — Entra ID (AAD) app registration credential metadata
"""
from __future__ import annotations

# ── M77A record types ─────────────────────────────────────────────────────────

# One per Azure subscription — billing/RBAC boundary metadata.
AZURE_SUBSCRIPTION = "azure_subscription"

# One per resource group per subscription — logical container for resources.
AZURE_RESOURCE_GROUP = "azure_resource_group"

# One per Network Security Group — inbound/outbound security rule posture.
# SECURITY: rule contents (source/destination CIDR, port ranges) are stored
# as structured metadata; no traffic payloads are ever accessed.
AZURE_NETWORK_SECURITY_GROUP = "azure_network_security_group"

# One per Storage Account — configuration/access posture metadata.
# SECURITY: blob contents, queue messages, and table data are NEVER read.
AZURE_STORAGE_ACCOUNT = "azure_storage_account"

# One per Key Vault — vault-level access policy and network posture metadata.
# SECURITY: key material, secret values, and certificate private keys are
# NEVER accessible from the management-plane API used here and are therefore
# impossible to leak.
AZURE_KEY_VAULT = "azure_key_vault"

# ── Deferred until M77C ───────────────────────────────────────────────────────
# AZURE_APP_SERVICE = "azure_app_service"
# AZURE_SQL_SERVER = "azure_sql_server"
# AZURE_AKS_CLUSTER = "azure_aks_cluster"
# AZURE_APP_REGISTRATION = "azure_app_registration"

# ── Aggregate set ─────────────────────────────────────────────────────────────

AZURE_RECORD_TYPES: frozenset[str] = frozenset({
    AZURE_SUBSCRIPTION,
    AZURE_RESOURCE_GROUP,
    AZURE_NETWORK_SECURITY_GROUP,
    AZURE_STORAGE_ACCOUNT,
    AZURE_KEY_VAULT,
})
