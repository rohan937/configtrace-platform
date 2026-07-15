"""Azure drift risk classification rules.

Entry point: ``classify_azure_change(change)``

Classifies drift changes for Azure configuration records. Built during
the Azure detection QA pass — this module previously did not exist, so
every Azure change silently fell through to the Cloudflare DNS classifier
fallback in ``risk_service.py``, despite the provider capability matrix
already advertising ``drift_risk_classification=True``.

Risk levels
-----------
critical — an NSG rule allows broad public inbound access on all
           ports/protocols, or public inbound access on an
           RDP/WinRM/SQL/MySQL/PostgreSQL/Redis/Elasticsearch/MongoDB
           port from a public source.

high     — a broad privileged role (Owner/Contributor/User Access
           Administrator) is granted; an NSG rule gains a public SSH
           ingress entry; a storage account's public blob access is
           enabled; a storage account's HTTPS-only traffic requirement is
           disabled; App Service HTTPS-only is disabled.

medium   — storage/Key Vault/SQL public network access is enabled;
           storage shared-key access is enabled; storage/App Service/SQL
           TLS is weakened; Key Vault purge protection or soft delete is
           disabled; Key Vault RBAC authorization is disabled; App
           Service FTP is enabled or public network access is enabled;
           AKS local accounts are enabled, the API server becomes
           public, or its network policy is removed.

low      — count-only changes with unclear impact; metadata-only drift;
           unknown/missing category fields; safe restoration/improvement
           transitions (e.g. a broad role removed, an NSG rule's public
           ingress narrowed, storage public blob access disabled).

Claim discipline
-----------------
All reason strings use safe review-framing:
  "Azure RBAC access was broadened"
  "Azure storage public-access posture changed"
  "Azure network ingress posture changed"
  "Azure SQL network posture changed"
  "Azure Key Vault protection posture changed"
  "This may require review"
  "Configuration evidence does not confirm compromise, unauthorized
  access, data exposure, secret exposure, or infrastructure exposure."
Forbidden phrases: breach, compromise, attacker, leaked, unauthorized
access, storage exposed, database exposed, key vault exposed, secret
exposed, infrastructure exposed, data exposed, customer data exposed.
"""

from __future__ import annotations

from typing import Any, Optional

from app.models.change import Change

# Thresholds/sets mirrored from security_rules/azure.py so Change
# severities stay aligned with the corresponding Security Findings.
_PUBLIC_SOURCE_PREFIXES: frozenset[str] = frozenset({
    "*", "0.0.0.0/0", "::/0", "Internet", "Any",
})
_ADMIN_PORTS_CRITICAL: frozenset[int] = frozenset({
    3389, 5985, 5986, 1433, 3306, 5432, 6379, 9200, 27017,
})
_ADMIN_PORTS_HIGH: frozenset[int] = frozenset({22})
_ALL_PORT_LITERALS: frozenset[str] = frozenset({"*", "Any", "any", "ANY"})

_BROAD_PRIVILEGE_ROLES: frozenset[str] = frozenset({
    "Owner", "Contributor", "User Access Administrator",
})
_FTP_WEAK_STATES: frozenset[str] = frozenset({"AllAllowed", "allallowed"})
_WEAK_TLS_VERSIONS: frozenset[str] = frozenset({"1.0", "1.1", "TLS1_0", "TLS1_1"})
_AKS_NO_POLICY: frozenset[str] = frozenset({"", "none", "None", "NONE"})


def _get(obj: object, field: str) -> object:
    """Safely retrieve a field from a Change object or dict."""
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _is_truthy(val: object) -> bool:
    if val is True or val == "true" or val == 1:
        return True
    return False


def _is_falsy_explicit(val: object) -> bool:
    if val is False or val == "false" or val == 0:
        return True
    return False


def _int_or_none(val: object) -> Optional[int]:
    """Coerce to int, but return None (not 0) for missing/unparseable values.

    A count that is genuinely unknown/missing must never be silently
    treated as an explicit ``0`` or as crossing a threshold — doing so
    would let an unknown transition falsely trigger a finding.
    """
    if isinstance(val, bool) or val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _as_dict_list_or_none(val: object) -> Optional[list[dict]]:
    """Return a list of dicts, or ``None`` when *val* is not actually a list.

    Preserves the missing/unknown distinction — a genuinely unknown
    previous ``rules_summary`` must never be conflated with an explicitly
    empty one (the exact list-diffing bug class found and fixed in
    Google Cloud's classification-QA pass, applied proactively here from
    the start).
    """
    if isinstance(val, list):
        return [v for v in val if isinstance(v, dict)]
    return None


def _expand_ports(dest_port_range: object) -> list[int]:
    """Best-effort parse of an NSG destination_port_range into ints.

    Mirrors security_rules/azure.py's ``_expand_destination_ports``.
    """
    s = (dest_port_range or "").strip() if isinstance(dest_port_range, str) else ""
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


def _is_broad_destination_port(dest_port_range: object) -> bool:
    """Mirrors security_rules/azure.py's ``_is_broad_destination_port``."""
    s = (dest_port_range or "").strip() if isinstance(dest_port_range, str) else ""
    if s in _ALL_PORT_LITERALS:
        return True
    if s in {"0-65535", "1-65535"}:
        return True
    return False


def _is_risky_public_rule(rule: dict) -> str:
    """Classify a single NSG rule entry's risk level, or "" if not risky.

    Only Inbound + Allow rules from a public source are considered.
    Returns "critical" for broad-port or admin-critical-port rules,
    "high" for SSH (22), or "" if the rule doesn't match any risky shape.
    """
    direction = (rule.get("direction") or "").strip()
    access = (rule.get("access") or "").strip()
    if direction != "Inbound" or access != "Allow":
        return ""
    src_prefix = (rule.get("source_address_prefix") or "").strip()
    if src_prefix not in _PUBLIC_SOURCE_PREFIXES:
        return ""
    dest_port_range = rule.get("destination_port_range") or ""
    if _is_broad_destination_port(dest_port_range):
        return "critical"
    ports = _expand_ports(dest_port_range)
    if any(p in _ADMIN_PORTS_CRITICAL for p in ports):
        return "critical"
    if any(p in _ADMIN_PORTS_HIGH for p in ports):
        return "high"
    return ""


def _rule_key(rule: dict) -> tuple:
    return (
        (rule.get("direction") or "").strip(),
        (rule.get("access") or "").strip(),
        (rule.get("source_address_prefix") or "").strip(),
        (rule.get("destination_port_range") or "").strip(),
        (rule.get("protocol") or "").strip(),
    )


def _added_rules(prev_list: list[dict], new_list: list[dict]) -> list[dict]:
    prev_keys = {_rule_key(r) for r in prev_list}
    return [r for r in new_list if _rule_key(r) not in prev_keys]


# ── azure_subscription ───────────────────────────────────────────────────────


def _classify_subscription_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()

    if ct in ("added", "removed"):
        return ("low", "Azure subscription configuration record was added or removed during sync.")

    # No dedicated Security Finding exists for azure_subscription — subscription
    # metadata is informational (see security_rules/azure.py's own docstring:
    # "no actionable posture surface available at these record types").
    if fp in ("display_name", "state", "tenant_id", "authorization_source"):
        return ("low", f"Azure subscription {fp.replace('_', ' ')} changed.")

    return ("low", f"Azure subscription configuration field '{fp}' changed.")


# ── azure_resource_group ─────────────────────────────────────────────────────


def _classify_resource_group_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()

    if ct in ("added", "removed"):
        return ("low", "Azure resource group configuration record was added or removed during sync.")

    # No dedicated Security Finding exists for azure_resource_group either.
    if fp in ("location", "provisioning_state", "tag_keys"):
        return ("low", f"Azure resource group {fp.replace('_', ' ')} changed.")

    return ("low", f"Azure resource group configuration field '{fp}' changed.")


# ── azure_network_security_group ─────────────────────────────────────────────


def _classify_nsg_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Azure NSG configuration record was added or removed during sync.")

    if fp == "rules_summary":
        new_list = _as_dict_list_or_none(new_v)
        if new_list is None:
            return ("low", "Azure NSG rules are now unknown or missing.")
        prev_list = _as_dict_list_or_none(prev_v)
        if prev_list is None:
            # Previous rules are genuinely unknown — cannot claim a rule was
            # newly "added". Evaluate current state only, mirroring the
            # Finding's own current-state-only check.
            worst = ""
            for rule in new_list:
                sev = _is_risky_public_rule(rule)
                if sev == "critical":
                    worst = "critical"
                    break
                if sev == "high":
                    worst = "high"
            if worst:
                return (
                    worst,
                    "Azure network ingress posture changed — the NSG currently "
                    "has a public inbound rule on a broad or administrative "
                    "port, though prior rules are unknown or missing. This may "
                    "require review.",
                )
            return ("low", "Azure NSG rules changed.")

        added = _added_rules(prev_list, new_list)
        if not added:
            removed = _added_rules(new_list, prev_list)
            if removed:
                return ("low", "Azure NSG rule was removed.")
            return ("low", "Azure NSG rules changed.")
        worst = ""
        for rule in added:
            sev = _is_risky_public_rule(rule)
            if sev == "critical":
                worst = "critical"
                break
            if sev == "high":
                worst = "high"
        if worst:
            return (
                worst,
                "Azure network ingress posture changed — a new public inbound "
                "rule was added. This may require review.",
            )
        return ("low", "Azure NSG gained an inbound rule.")

    if fp in (
        "nsg_name", "resource_group", "location", "rule_count",
        "inbound_allow_rule_count", "public_inbound_rule_count",
    ):
        return ("low", f"Azure NSG {fp.replace('_', ' ')} changed.")

    return ("low", f"Azure NSG configuration field '{fp}' changed.")


# ── azure_storage_account ────────────────────────────────────────────────────


def _classify_storage_account_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Azure storage account configuration record was added or removed during sync.")

    if fp == "allow_blob_public_access":
        if _is_truthy(new_v):
            return (
                "high",
                "Azure storage public-access posture changed — public blob "
                "access was enabled. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Azure storage account public blob access was disabled.")
        return ("low", "Azure storage account public blob access state is now unknown or missing.")

    if fp == "public_network_access":
        new_v_s = new_v.lower() if isinstance(new_v, str) else ""
        prev_v_s = prev_v.lower() if isinstance(prev_v, str) else ""
        new_enabled = new_v_s in ("enabled", "true")
        prev_enabled = prev_v_s in ("enabled", "true")
        if new_enabled and not prev_enabled:
            return (
                "medium",
                "Azure storage public-access posture changed — public "
                "network access was enabled. This may require review.",
            )
        if not new_enabled and prev_enabled:
            return ("low", "Azure storage account public network access was disabled.")
        return ("low", "Azure storage account public network access changed.")

    if fp == "minimum_tls_version":
        new_weak = isinstance(new_v, str) and new_v in _WEAK_TLS_VERSIONS
        prev_weak = isinstance(prev_v, str) and prev_v in _WEAK_TLS_VERSIONS
        if new_weak and not prev_weak:
            return (
                "medium",
                "Azure storage account minimum TLS version was weakened. "
                "This may require review.",
            )
        if not new_weak and prev_weak:
            return ("low", "Azure storage account minimum TLS version was strengthened.")
        return ("low", "Azure storage account minimum TLS version changed.")

    if fp == "shared_access_key_enabled":
        if _is_truthy(new_v):
            return (
                "medium",
                "Azure storage account shared-key access was enabled. "
                "This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Azure storage account shared-key access was disabled.")
        return ("low", "Azure storage account shared-key access state is now unknown or missing.")

    if fp == "supports_https_traffic_only":
        # Backed by the azure_storage_https_only_disabled Security Finding
        # (added in the Azure classification-QA pass) — high severity matches
        # the Finding directly, and mirrors the analogous
        # azure_app_service_https_disabled rule (high) on a sibling record type.
        if _is_falsy_explicit(new_v):
            return (
                "high",
                "Azure storage account no longer requires HTTPS-only traffic. "
                "This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Azure storage account HTTPS-only traffic was enabled.")
        return ("low", "Azure storage account HTTPS-only state is now unknown or missing.")

    if fp in (
        "account_name", "resource_group", "location", "kind", "sku_name",
        "network_default_action",
    ):
        return ("low", f"Azure storage account {fp.replace('_', ' ')} changed.")

    return ("low", f"Azure storage account configuration field '{fp}' changed.")


# ── azure_key_vault ──────────────────────────────────────────────────────────


def _classify_key_vault_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Azure Key Vault configuration record was added or removed during sync.")

    if fp == "public_network_access":
        new_v_s = new_v.lower() if isinstance(new_v, str) else ""
        prev_v_s = prev_v.lower() if isinstance(prev_v, str) else ""
        new_enabled = new_v_s in ("enabled", "true")
        prev_enabled = prev_v_s in ("enabled", "true")
        if new_enabled and not prev_enabled:
            return (
                "medium",
                "Azure Key Vault protection posture changed — public network "
                "access was enabled. This may require review.",
            )
        if not new_enabled and prev_enabled:
            return ("low", "Azure Key Vault public network access was disabled.")
        return ("low", "Azure Key Vault public network access changed.")

    if fp == "purge_protection_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Azure Key Vault protection posture changed — purge "
                "protection was disabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Azure Key Vault purge protection was enabled.")
        return ("low", "Azure Key Vault purge protection state is now unknown or missing.")

    if fp == "soft_delete_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Azure Key Vault protection posture changed — soft delete "
                "was disabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Azure Key Vault soft delete was enabled.")
        return ("low", "Azure Key Vault soft delete state is now unknown or missing.")

    if fp == "enable_rbac_authorization":
        # Change-only approximation: the backing Finding
        # (azure_key_vault_rbac_disabled) also requires access_policy_count > 0,
        # which a single-field Change can't confirm — kept at the Finding's
        # severity (medium) as a conservative default.
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Azure Key Vault protection posture changed — RBAC "
                "authorization was disabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Azure Key Vault RBAC authorization was enabled.")
        return ("low", "Azure Key Vault RBAC authorization state is now unknown or missing.")

    if fp in (
        "vault_name", "resource_group", "location", "access_policy_count",
        "network_default_action",
    ):
        return ("low", f"Azure Key Vault {fp.replace('_', ' ')} changed.")

    return ("low", f"Azure Key Vault configuration field '{fp}' changed.")


# ── azure_role_assignment ────────────────────────────────────────────────────


def _classify_role_assignment_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Azure role assignment configuration record was added or removed during sync.")

    if fp == "role_definition_name":
        # Change-only signal: role assignments are effectively immutable in
        # Azure (a role change is normally a delete+create, which compute_diff
        # would surface as removed/added on a different assignment_id, not a
        # "modified" event) — this branch exists defensively for the rare
        # case a modified event is observed. Kept at the Finding's worst-case
        # severity (high) since a single-field Change can't confirm scope_type.
        new_broad = isinstance(new_v, str) and new_v in _BROAD_PRIVILEGE_ROLES
        prev_broad = isinstance(prev_v, str) and prev_v in _BROAD_PRIVILEGE_ROLES
        if new_broad and not prev_broad:
            return (
                "high",
                "Azure RBAC access was broadened — a broad privileged role "
                "was granted. This may require review.",
            )
        if not new_broad and prev_broad:
            return ("low", "Azure role assignment broad privileged role was removed.")
        return ("low", "Azure role assignment role name changed.")

    if fp in (
        "scope_type", "resource_group", "role_definition_id", "principal_type",
        "condition_present", "created_on", "updated_on",
    ):
        return ("low", f"Azure role assignment {fp.replace('_', ' ')} changed.")

    return ("low", f"Azure role assignment configuration field '{fp}' changed.")


# ── azure_app_service ────────────────────────────────────────────────────────


def _classify_app_service_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Azure App Service configuration record was added or removed during sync.")

    if fp == "https_only":
        if _is_falsy_explicit(new_v):
            return (
                "high",
                "Azure App Service no longer enforces HTTPS-only. "
                "This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Azure App Service HTTPS-only was enabled.")
        return ("low", "Azure App Service HTTPS-only state is now unknown or missing.")

    if fp == "ftps_state":
        new_weak = isinstance(new_v, str) and new_v in _FTP_WEAK_STATES
        prev_weak = isinstance(prev_v, str) and prev_v in _FTP_WEAK_STATES
        if new_weak and not prev_weak:
            return (
                "medium",
                "Azure App Service now allows unencrypted FTP access. "
                "This may require review.",
            )
        if not new_weak and prev_weak:
            return ("low", "Azure App Service FTP access was restricted.")
        return ("low", "Azure App Service FTP state changed.")

    if fp == "min_tls_version":
        new_weak = isinstance(new_v, str) and new_v in _WEAK_TLS_VERSIONS
        prev_weak = isinstance(prev_v, str) and prev_v in _WEAK_TLS_VERSIONS
        if new_weak and not prev_weak:
            return (
                "medium",
                "Azure App Service minimum TLS version was weakened. "
                "This may require review.",
            )
        if not new_weak and prev_weak:
            return ("low", "Azure App Service minimum TLS version was strengthened.")
        return ("low", "Azure App Service minimum TLS version changed.")

    if fp == "public_network_access":
        new_v_s = new_v.lower() if isinstance(new_v, str) else ""
        prev_v_s = prev_v.lower() if isinstance(prev_v, str) else ""
        new_enabled = new_v_s in ("enabled", "true")
        prev_enabled = prev_v_s in ("enabled", "true")
        if new_enabled and not prev_enabled:
            return (
                "medium",
                "Azure App Service public network access was enabled. "
                "This may require review.",
            )
        if not new_enabled and prev_enabled:
            return ("low", "Azure App Service public network access was disabled.")
        return ("low", "Azure App Service public network access changed.")

    if fp == "client_cert_enabled":
        # Change-only signal, kept intentionally (reviewed in the Azure
        # classification-QA pass): client certificate / mTLS auth is an
        # opt-in App Service hardening feature, not a usually-on default like
        # HTTPS — most correctly configured App Services never enable it, so
        # a Finding would fire on the overwhelming majority of records with
        # near-zero signal (unlike supports_https_traffic_only, which has a
        # clear "usually on, this is a regression" story and did get a
        # Finding). Classified per this task's App-Service posture convention.
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Azure App Service client certificate requirement was disabled. "
                "This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Azure App Service client certificate requirement was enabled.")
        return ("low", "Azure App Service client certificate state is now unknown or missing.")

    if fp in (
        "app_name", "resource_group", "location", "kind", "auth_enabled",
        "app_settings_count", "connection_string_count",
    ):
        return ("low", f"Azure App Service {fp.replace('_', ' ')} changed.")

    return ("low", f"Azure App Service configuration field '{fp}' changed.")


# ── azure_sql_server ─────────────────────────────────────────────────────────


def _classify_sql_server_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Azure SQL Server configuration record was added or removed during sync.")

    if fp == "public_network_access":
        new_v_s = new_v.lower() if isinstance(new_v, str) else ""
        prev_v_s = prev_v.lower() if isinstance(prev_v, str) else ""
        new_enabled = new_v_s in ("enabled", "true")
        prev_enabled = prev_v_s in ("enabled", "true")
        if new_enabled and not prev_enabled:
            return (
                "medium",
                "Azure SQL network posture changed — public network access "
                "was enabled. This may require review.",
            )
        if not new_enabled and prev_enabled:
            return ("low", "Azure SQL Server public network access was disabled.")
        return ("low", "Azure SQL Server public network access changed.")

    if fp == "minimum_tls_version":
        new_weak = isinstance(new_v, str) and new_v in _WEAK_TLS_VERSIONS
        prev_weak = isinstance(prev_v, str) and prev_v in _WEAK_TLS_VERSIONS
        if new_weak and not prev_weak:
            return (
                "medium",
                "Azure SQL Server minimum TLS version was weakened. "
                "This may require review.",
            )
        if not new_weak and prev_weak:
            return ("low", "Azure SQL Server minimum TLS version was strengthened.")
        return ("low", "Azure SQL Server minimum TLS version changed.")

    if fp in (
        "server_name", "resource_group", "location",
        "azure_ad_only_authentication", "firewall_rule_count",
        "has_allow_azure_services_rule",
    ):
        return ("low", f"Azure SQL Server {fp.replace('_', ' ')} changed.")

    return ("low", f"Azure SQL Server configuration field '{fp}' changed.")


# ── azure_aks_cluster ────────────────────────────────────────────────────────


def _classify_aks_cluster_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Azure AKS cluster configuration record was added or removed during sync.")

    if fp == "private_cluster_enabled":
        # Change-only approximation: azure_aks_public_api_access also
        # requires api_server_authorized_ip_range_count==0, which a single-
        # field Change can't confirm — a public API server combined with
        # configured authorized IP ranges is a common, safe configuration,
        # so this stays at "medium" rather than the Finding's "high" ceiling
        # to avoid over-alerting on that common case.
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Azure AKS cluster control plane became publicly accessible. "
                "This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Azure AKS cluster control plane was made private.")
        return ("low", "Azure AKS cluster private-cluster state is now unknown or missing.")

    if fp == "local_account_disabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Azure AKS cluster local accounts were enabled. "
                "This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Azure AKS cluster local accounts were disabled.")
        return ("low", "Azure AKS cluster local-account state is now unknown or missing.")

    if fp == "network_policy":
        new_weak = (not isinstance(new_v, str)) or new_v.strip().lower() in _AKS_NO_POLICY
        if new_weak:
            return (
                "medium",
                "Azure AKS cluster network policy was removed. "
                "This may require review.",
            )
        return ("low", "Azure AKS cluster network policy changed.")

    if fp in (
        "cluster_name", "resource_group", "location", "azure_rbac_enabled",
        "network_plugin", "public_network_access",
        "api_server_authorized_ip_range_count", "authorized_ip_ranges_configured",
    ):
        return ("low", f"Azure AKS cluster {fp.replace('_', ' ')} changed.")

    return ("low", f"Azure AKS cluster configuration field '{fp}' changed.")


# ── Main dispatcher ───────────────────────────────────────────────────────────


def classify_azure_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for an Azure configuration change.

    Dispatches on ``provider_metadata["record_type"]``:
      * ``azure_subscription``            → subscription metadata (no Finding)
      * ``azure_resource_group``          → resource group metadata (no Finding)
      * ``azure_network_security_group``  → NSG ingress/rule-list posture
      * ``azure_storage_account``         → storage public-access/TLS posture
      * ``azure_key_vault``               → Key Vault protection posture
      * ``azure_role_assignment``         → RBAC broad-privilege posture
      * ``azure_app_service``             → App Service HTTPS/TLS/network posture
      * ``azure_sql_server``              → SQL network/TLS posture
      * ``azure_aks_cluster``             → AKS endpoint/RBAC/network posture

    Configuration evidence does not confirm compromise, unauthorized
    access, data exposure, secret exposure, or infrastructure exposure.
    Azure configuration evidence may require review.
    """
    pm = _get(change, "provider_metadata") or {}
    if isinstance(pm, dict):
        record_type = (pm.get("record_type") or "").lower()
    else:
        record_type = ""

    if record_type == "azure_subscription":
        return _classify_subscription_change(change)
    if record_type == "azure_resource_group":
        return _classify_resource_group_change(change)
    if record_type == "azure_network_security_group":
        return _classify_nsg_change(change)
    if record_type == "azure_storage_account":
        return _classify_storage_account_change(change)
    if record_type == "azure_key_vault":
        return _classify_key_vault_change(change)
    if record_type == "azure_role_assignment":
        return _classify_role_assignment_change(change)
    if record_type == "azure_app_service":
        return _classify_app_service_change(change)
    if record_type == "azure_sql_server":
        return _classify_sql_server_change(change)
    if record_type == "azure_aks_cluster":
        return _classify_aks_cluster_change(change)

    # Fallback for unknown azure_ subtypes
    return (
        "low",
        f"Azure configuration changed (record type: {record_type or 'unknown'}). "
        "This may require review.",
    )
