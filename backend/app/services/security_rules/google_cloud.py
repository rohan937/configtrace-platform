"""Google Cloud security / configuration-risk rules — M78B.

Every rule fires only on explicit, reliable normalized fields produced by the
Google Cloud connector (app/connectors/google_cloud.py +
app/connectors/google_cloud_schema.py). Evidence is metadata-only: project id +
posture booleans + counts + well-known canonical role names + firewall rule
name + bucket name. Customer data, IAM principal identities (member emails,
service-account emails, group names, user names, principal object IDs),
database contents, Cloud Storage object names/contents, signed URLs,
HMAC/SAS/access tokens, service-account private keys, KMS key material, raw
API responses, bearer tokens, authorization headers, request/response bodies,
and PII are NEVER read, stored, or surfaced by the connector — none of those
bytes are even present on the normalized records here.

CLAIM DISCIPLINE
----------------
These are configuration risks, not confirmed incidents. Copy says "may
expose", "may broaden access", "may increase configuration risk", "evidence
for review", and "does not confirm compromise, unauthorized access, or data
exposure". It never asserts that secrets were leaked, customer data was
disclosed, an attacker is present, data was exposed, or a breach / attack
occurred. Firewall rule + public source range does NOT prove a VM / Cloud
Run / GKE workload is actually reachable.

M78A record types consumed
--------------------------
- ``google_cloud_iam_policy_summary`` → public-member exposure / broad
                                         privileged-role binding
- ``google_cloud_firewall_rule``      → public admin / broad-port ingress;
                                         public ingress with no targets
- ``google_cloud_storage_bucket``     → public-access-prevention disabled,
                                         uniform bucket-level access disabled,
                                         versioning disabled, retention policy
                                         not locked

Explicitly deferred to M78C
---------------------------
* Cloud SQL public-network / weak-TLS / no-deletion-protection rules — record
  type ``google_cloud_sql_instance`` not in M78A.
* Cloud Run public-invoker / weak-ingress rules — record type
  ``google_cloud_run_service`` not in M78A.
* GKE local-accounts / public-API-server / network-policy rules — record
  type ``google_cloud_gke_cluster`` not in M78A.
* Secret Manager rotation / replication rules — record type
  ``google_cloud_secret_manager_secret`` not in M78A.
* Service-account key age / KMS-key-protection rules — record type
  ``google_cloud_service_account_key`` not in M78A.
* Organization Policy posture rules — require Organization Policy API access
  not in the M78A connector.
* google_cloud_project / google_cloud_vpc_network rules — no actionable
  posture surface at M78B (project metadata is informational; VPC network
  posture is captured via the firewall-rule surface).
"""

from __future__ import annotations

from typing import Any

from app.connectors.google_cloud_schema import (
    GOOGLE_CLOUD_FIREWALL_RULE,
    GOOGLE_CLOUD_GKE_CLUSTER,
    GOOGLE_CLOUD_IAM_POLICY_SUMMARY,
    GOOGLE_CLOUD_RUN_SERVICE,
    GOOGLE_CLOUD_SECRET_MANAGER_SUMMARY,
    GOOGLE_CLOUD_SERVICE_ACCOUNT_KEY_SUMMARY,
    GOOGLE_CLOUD_SQL_INSTANCE,
    GOOGLE_CLOUD_STORAGE_BUCKET,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule keys ────────────────────────────────────────────────────────────────

_RULE_IAM_PUBLIC_MEMBER = "google_cloud_iam_public_member"
_RULE_IAM_BROAD_PRIVILEGED_ROLE = "google_cloud_iam_broad_privileged_role"

_RULE_FIREWALL_PUBLIC_ADMIN_INGRESS = "google_cloud_firewall_public_admin_ingress"
_RULE_FIREWALL_PUBLIC_BROAD_INGRESS = "google_cloud_firewall_public_broad_ingress"
_RULE_FIREWALL_RULE_NO_TARGETS = "google_cloud_firewall_rule_no_targets"

_RULE_STORAGE_PUBLIC_ACCESS_PREVENTION_DISABLED = (
    "google_cloud_storage_public_access_prevention_disabled"
)
_RULE_STORAGE_UNIFORM_ACCESS_DISABLED = "google_cloud_storage_uniform_access_disabled"
_RULE_STORAGE_VERSIONING_DISABLED = "google_cloud_storage_versioning_disabled"
_RULE_STORAGE_RETENTION_NOT_LOCKED = "google_cloud_storage_retention_not_locked"

# M78C — Cloud SQL
_RULE_SQL_PUBLIC_NETWORK_ACCESS = "google_cloud_sql_public_network_access"
_RULE_SQL_WEAK_TLS = "google_cloud_sql_weak_tls"
_RULE_SQL_BACKUPS_DISABLED = "google_cloud_sql_backups_disabled"
_RULE_SQL_DELETION_PROTECTION_DISABLED = "google_cloud_sql_deletion_protection_disabled"

# M78C — Cloud Run
_RULE_RUN_PUBLIC_INVOKER = "google_cloud_run_public_invoker"
_RULE_RUN_ALL_INGRESS = "google_cloud_run_all_ingress"

# M78C — GKE
_RULE_GKE_PUBLIC_CONTROL_PLANE = "google_cloud_gke_public_control_plane"
_RULE_GKE_LEGACY_ABAC_ENABLED = "google_cloud_gke_legacy_abac_enabled"
_RULE_GKE_NETWORK_POLICY_DISABLED = "google_cloud_gke_network_policy_disabled"
_RULE_GKE_WORKLOAD_IDENTITY_DISABLED = "google_cloud_gke_workload_identity_disabled"

# M78C — Service account keys
_RULE_SA_USER_MANAGED_KEYS = "google_cloud_service_account_user_managed_keys"
_RULE_SA_OLD_KEYS = "google_cloud_service_account_old_keys"

# M78C — Secret Manager
_RULE_SECRET_MANAGER_AUTO_REPLICATION_WITHOUT_CMEK = (
    "google_cloud_secret_manager_auto_replication_without_cmek"
)

GOOGLE_CLOUD_RULE_KEYS: frozenset[str] = frozenset({
    # IAM
    _RULE_IAM_PUBLIC_MEMBER,
    _RULE_IAM_BROAD_PRIVILEGED_ROLE,
    # Firewall
    _RULE_FIREWALL_PUBLIC_ADMIN_INGRESS,
    _RULE_FIREWALL_PUBLIC_BROAD_INGRESS,
    _RULE_FIREWALL_RULE_NO_TARGETS,
    # Storage
    _RULE_STORAGE_PUBLIC_ACCESS_PREVENTION_DISABLED,
    _RULE_STORAGE_UNIFORM_ACCESS_DISABLED,
    _RULE_STORAGE_VERSIONING_DISABLED,
    _RULE_STORAGE_RETENTION_NOT_LOCKED,
    # M78C — Cloud SQL
    _RULE_SQL_PUBLIC_NETWORK_ACCESS,
    _RULE_SQL_WEAK_TLS,
    _RULE_SQL_BACKUPS_DISABLED,
    _RULE_SQL_DELETION_PROTECTION_DISABLED,
    # M78C — Cloud Run
    _RULE_RUN_PUBLIC_INVOKER,
    _RULE_RUN_ALL_INGRESS,
    # M78C — GKE
    _RULE_GKE_PUBLIC_CONTROL_PLANE,
    _RULE_GKE_LEGACY_ABAC_ENABLED,
    _RULE_GKE_NETWORK_POLICY_DISABLED,
    _RULE_GKE_WORKLOAD_IDENTITY_DISABLED,
    # M78C — Service account keys
    _RULE_SA_USER_MANAGED_KEYS,
    _RULE_SA_OLD_KEYS,
    # M78C — Secret Manager
    _RULE_SECRET_MANAGER_AUTO_REPLICATION_WITHOUT_CMEK,
})

# ── Shared constants ─────────────────────────────────────────────────────────

# Public source-range prefixes Google Cloud firewall rules accept that
# unambiguously indicate the source is the entire IPv4 or IPv6 internet.
_PUBLIC_SOURCE_RANGES: frozenset[str] = frozenset({
    "0.0.0.0/0",
    "::/0",
})

# Admin / database / cache / search ports. Each entry is a single port that
# we treat as administrative when allowed from a public source range.
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

# Protocol identifiers Google Cloud accepts that indicate "all protocols" in
# the allowed list.
_ALL_PROTOCOL_LITERALS: frozenset[str] = frozenset({"all", "*", "any"})

# Roles considered "broad privileged" project-level roles. These are the
# well-known canonical Google role names — storing the role NAME is no
# different from storing well-known IAM role identifiers.
#
# Severity bucketing:
#   "high"   — the rule's headline severity (Owner / Editor / Security Admin /
#              IAM admin); fires the finding at "high".
#   "medium" — the service-account admin roles which are still risky but
#              not as broad. Their presence fires the finding at "medium".
_HIGH_SEVERITY_BROAD_ROLES: frozenset[str] = frozenset({
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.projectIamAdmin",
})
_MEDIUM_SEVERITY_BROAD_ROLES: frozenset[str] = frozenset({
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin",
})
_ALL_BROAD_PRIVILEGED_ROLES: frozenset[str] = (
    _HIGH_SEVERITY_BROAD_ROLES | _MEDIUM_SEVERITY_BROAD_ROLES
)


def _common_disclaimer() -> str:
    return (
        "This is evidence for review and does not confirm compromise, "
        "unauthorized access, or data exposure."
    )


def _is_public_source(source_range: str) -> bool:
    """True when a firewall source_range value indicates a public source."""
    return source_range in _PUBLIC_SOURCE_RANGES


def _has_public_source(source_ranges_summary: Any) -> bool:
    """True when any entry in the M78A source_ranges_summary list is public."""
    if not isinstance(source_ranges_summary, list):
        return False
    for r in source_ranges_summary:
        if isinstance(r, str) and _is_public_source(r.strip()):
            return True
    return False


def _expand_ports(ports_value: Any) -> list[int]:
    """Best-effort parse of an M78A allowed_summary[i]["ports"] entry into ints.

    Returns an empty list for entries that indicate broad / all-port coverage
    (handled by the broad-ingress rule), and for missing / unparseable values.

    Honors:
      * exact integer (e.g. "22")
      * single integer range (e.g. "8000-8010") — bounded to <=256 ports to
        avoid pathological inputs blowing up evaluation cost.
    """
    out: list[int] = []
    if not isinstance(ports_value, list):
        return out
    for p in ports_value:
        if not isinstance(p, str):
            continue
        piece = p.strip()
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


def _is_broad_port_entry(entry: dict) -> bool:
    """True when an allowed_summary entry covers "all ports" / wildcard / huge range.

    A firewall rule entry like {"protocol": "all"} or one with an empty ports
    list (Google Cloud convention for "any port") is broad. We also treat a
    very wide single range (e.g. "0-65535" or "1-65535") as broad.
    """
    proto = (entry.get("protocol") or "").strip().lower()
    ports = entry.get("ports")
    # "all" / "*" / "any" protocol always means broad.
    if proto in _ALL_PROTOCOL_LITERALS:
        return True
    # An empty ports list in Google Cloud means "all ports for this protocol".
    if isinstance(ports, list) and len(ports) == 0:
        return True
    # Explicit wide range.
    if isinstance(ports, list):
        for p in ports:
            if not isinstance(p, str):
                continue
            piece = p.strip()
            if piece in {"*", "any", "ANY", "0-65535", "1-65535"}:
                return True
    return False


# ── Dispatcher ───────────────────────────────────────────────────────────────


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == GOOGLE_CLOUD_IAM_POLICY_SUMMARY:
        return _eval_iam_policy_summary(record)
    if rtype == GOOGLE_CLOUD_FIREWALL_RULE:
        return _eval_firewall_rule(record)
    if rtype == GOOGLE_CLOUD_STORAGE_BUCKET:
        return _eval_storage_bucket(record)
    # M78C
    if rtype == GOOGLE_CLOUD_SQL_INSTANCE:
        return _eval_sql_instance(record)
    if rtype == GOOGLE_CLOUD_RUN_SERVICE:
        return _eval_run_service(record)
    if rtype == GOOGLE_CLOUD_GKE_CLUSTER:
        return _eval_gke_cluster(record)
    if rtype == GOOGLE_CLOUD_SERVICE_ACCOUNT_KEY_SUMMARY:
        return _eval_service_account_key_summary(record)
    if rtype == GOOGLE_CLOUD_SECRET_MANAGER_SUMMARY:
        return _eval_secret_manager_summary(record)
    return []


# ── IAM policy summary ───────────────────────────────────────────────────────


def _eval_iam_policy_summary(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    project_id = get_str(record, "project_id")
    binding_count = record.get("binding_count")
    role_names_raw = record.get("role_names")
    role_names: list[str] = (
        [r for r in role_names_raw if isinstance(r, str)]
        if isinstance(role_names_raw, list) else []
    )
    broad_role_count = record.get("broad_role_count")
    has_all_users = record.get("allusers_binding_present")
    has_all_authenticated = record.get("allauthenticatedusers_binding_present")
    user_count = record.get("user_member_count")
    group_count = record.get("group_member_count")
    sa_count = record.get("service_account_member_count")
    domain_count = record.get("domain_member_count")

    # A. Public IAM member on project
    if has_all_users is True or has_all_authenticated is True:
        sentinels = []
        if has_all_users is True:
            sentinels.append("allUsers")
        if has_all_authenticated is True:
            sentinels.append("allAuthenticatedUsers")
        sentinel_str = " and ".join(sentinels)
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_IAM_PUBLIC_MEMBER,
                finding_key=make_finding_key(_RULE_IAM_PUBLIC_MEMBER, record_id),
                severity="high",
                title="Google Cloud IAM policy includes a public member",
                description=(
                    f"Google Cloud IAM policy for project '{project_id}' includes "
                    f"a public sentinel member ({sentinel_str}) on one or more "
                    f"role bindings. This may broaden access to project "
                    f"resources and may require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_IAM_PUBLIC_MEMBER,
                    "project_id": project_id,
                    "allusers_binding_present": bool(has_all_users),
                    "allauthenticatedusers_binding_present": bool(has_all_authenticated),
                    "binding_count": binding_count,
                },
                remediation={
                    "summary": (
                        "Remove the allUsers / allAuthenticatedUsers binding "
                        "from the project IAM policy."
                    ),
                    "steps": [
                        "Audit each binding that includes allUsers or "
                        "allAuthenticatedUsers in the principal list.",
                        "Replace public sentinels with explicit Google "
                        "identities (user/group/serviceAccount) scoped to the "
                        "needed roles.",
                        "Re-run the project-level IAM policy snapshot to "
                        "confirm the public sentinels are removed.",
                    ],
                },
                record_id=record_id,
            )
        )

    # B. Broad project-level privileged role
    found_high = sorted(set(role_names) & _HIGH_SEVERITY_BROAD_ROLES)
    found_medium = sorted(set(role_names) & _MEDIUM_SEVERITY_BROAD_ROLES)
    if found_high or found_medium:
        severity = "high" if found_high else "medium"
        matched = found_high + found_medium
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_IAM_BROAD_PRIVILEGED_ROLE,
                finding_key=make_finding_key(_RULE_IAM_BROAD_PRIVILEGED_ROLE, record_id),
                severity=severity,
                title="Google Cloud IAM policy includes broad privileged roles",
                description=(
                    f"Google Cloud IAM policy for project '{project_id}' grants "
                    f"one or more broad privileged roles "
                    f"({', '.join(matched)}). This may increase access-"
                    f"governance risk and may require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_IAM_BROAD_PRIVILEGED_ROLE,
                    "project_id": project_id,
                    "broad_roles": matched,
                    "broad_role_count": broad_role_count,
                    "binding_count": binding_count,
                    "user_member_count": user_count,
                    "group_member_count": group_count,
                    "service_account_member_count": sa_count,
                    "domain_member_count": domain_count,
                },
                remediation={
                    "summary": (
                        "Replace broad project-level roles with narrower "
                        "predefined or custom roles scoped to least-privilege "
                        "use cases."
                    ),
                    "steps": [
                        "Audit the bindings for the broad privileged roles "
                        "listed in the evidence.",
                        "Replace each binding with the narrower role(s) the "
                        "principal actually needs (e.g. roles/storage.objectViewer "
                        "instead of roles/owner).",
                        "Consider IAM Conditions to scope the binding to a "
                        "specific resource or time window.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Firewall rule ────────────────────────────────────────────────────────────


def _eval_firewall_rule(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    firewall_name = get_str(record, "firewall_name")
    network_name = get_str(record, "network_name")
    project_id = get_str(record, "project_id")
    direction = get_str(record, "direction")
    priority = record.get("priority")
    disabled = record.get("disabled")
    source_ranges_summary = record.get("source_ranges_summary")
    allowed_summary = record.get("allowed_summary")
    target_tag_count = record.get("target_tag_count")
    target_sa_count = record.get("target_service_account_count")

    # Only INGRESS rules apply to these three findings.
    if (direction or "").upper() != "INGRESS":
        return out
    # Disabled firewall rules cannot expose resources.
    if disabled is True:
        return out
    # No public source range → none of these rules fire.
    if not _has_public_source(source_ranges_summary):
        return out

    if not isinstance(allowed_summary, list):
        allowed_summary = []

    # Scan the allowed entries for broad vs admin patterns. The rule below
    # mirrors the Azure NSG pattern: at most one broad finding + one admin
    # finding per firewall record (with the worst-case admin port winning).
    broad_match: dict[str, Any] | None = None
    admin_match: dict[str, Any] | None = None
    admin_severity = "high"  # SSH-only default; bumps to critical on RDP/DB/etc.

    for entry in allowed_summary:
        if not isinstance(entry, dict):
            continue
        proto = (entry.get("protocol") or "").strip()

        # D. Broad public inbound rule
        if _is_broad_port_entry(entry):
            if broad_match is None:
                broad_match = {
                    "protocol": proto,
                    "ports": entry.get("ports") or [],
                }
            continue

        # C. Public admin/database/cache/search ingress
        # We only consider tcp/udp protocols for known admin ports; "icmp" /
        # "esp" / "ah" never fire the admin rule.
        ports = _expand_ports(entry.get("ports"))
        if not ports:
            continue
        for p in ports:
            if p in _ADMIN_PORTS_HIGH_SEVERITY:
                # Critical wins outright.
                admin_match = {
                    "protocol": proto,
                    "admin_port": p,
                    "ports": entry.get("ports") or [],
                }
                admin_severity = "critical"
                break
            if p in _ADMIN_PORTS_HIGH_LEVEL and admin_match is None:
                admin_match = {
                    "protocol": proto,
                    "admin_port": p,
                    "ports": entry.get("ports") or [],
                }
                # Leave admin_severity = "high" (SSH).

    if broad_match is not None:
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_FIREWALL_PUBLIC_BROAD_INGRESS,
                finding_key=make_finding_key(
                    _RULE_FIREWALL_PUBLIC_BROAD_INGRESS, record_id
                ),
                severity="critical",
                title="Google Cloud firewall rule allows broad public inbound access",
                description=(
                    f"Firewall rule '{firewall_name}' on network "
                    f"'{network_name}' in project '{project_id}' allows broad "
                    f"public inbound traffic ({broad_match['protocol'] or 'all'}/"
                    f"{broad_match['ports'] or 'all ports'}) from a public "
                    f"source range. This may broaden network exposure for "
                    f"targeted resources and may require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_FIREWALL_PUBLIC_BROAD_INGRESS,
                    "firewall_rule_name": firewall_name,
                    "network_name": network_name,
                    "project_id": project_id,
                    "direction": direction,
                    "priority": priority,
                    "disabled": False,
                    "source_ranges_summary": source_ranges_summary,
                    "matched_protocol": broad_match["protocol"],
                    "matched_ports": broad_match["ports"],
                    "target_tag_count": target_tag_count,
                    "target_service_account_count": target_sa_count,
                    "public_source": True,
                },
                remediation={
                    "summary": (
                        "Tighten the firewall rule to a narrow source range "
                        "and specific ports, or disable the rule if it is no "
                        "longer needed."
                    ),
                    "steps": [
                        "Replace 0.0.0.0/0 / ::/0 with a known IP range "
                        "(e.g. corporate VPN or jump host).",
                        "Limit the allowed protocols and ports to what the "
                        "service requires.",
                        "Confirm the resources behind this rule actually need "
                        "broad ingress; otherwise scope via target tags or "
                        "target service accounts.",
                    ],
                },
                record_id=record_id,
            )
        )

    if admin_match is not None:
        admin_port = admin_match["admin_port"]
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_FIREWALL_PUBLIC_ADMIN_INGRESS,
                finding_key=make_finding_key(
                    _RULE_FIREWALL_PUBLIC_ADMIN_INGRESS, record_id
                ),
                severity=admin_severity,
                title="Google Cloud firewall rule allows public inbound on an administrative port",
                description=(
                    f"Firewall rule '{firewall_name}' on network "
                    f"'{network_name}' in project '{project_id}' allows public "
                    f"inbound traffic on port {admin_port}. This may expose "
                    f"targeted resources and may require review. ConfigTrace "
                    f"does not confirm reachability — a firewall rule plus a "
                    f"public source range does not prove a VM is publicly "
                    f"reachable. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_FIREWALL_PUBLIC_ADMIN_INGRESS,
                    "firewall_rule_name": firewall_name,
                    "network_name": network_name,
                    "project_id": project_id,
                    "direction": direction,
                    "priority": priority,
                    "disabled": False,
                    "source_ranges_summary": source_ranges_summary,
                    "matched_protocol": admin_match["protocol"],
                    "matched_ports": admin_match["ports"],
                    "admin_port": admin_port,
                    "target_tag_count": target_tag_count,
                    "target_service_account_count": target_sa_count,
                    "public_source": True,
                },
                remediation={
                    "summary": (
                        "Restrict the source range to known IPs (e.g. VPN / "
                        "jump host) or remove the rule."
                    ),
                    "steps": [
                        "Replace the public source range with a known IP range.",
                        "Confirm the service actually needs to listen on the "
                        "exposed port.",
                        "Consider IAP / Bastion / Cloud Identity-Aware Proxy "
                        "for administrative-port access.",
                    ],
                },
                record_id=record_id,
            )
        )

    # E. Firewall rule with disabled=false and no targets (ingress + public).
    if (
        isinstance(target_tag_count, int)
        and isinstance(target_sa_count, int)
        and target_tag_count == 0
        and target_sa_count == 0
    ):
        # Severity bumps to high when the rule is ALSO a broad/admin public
        # ingress (the rule applies broadly across the network AND it permits
        # risky ingress). Otherwise stays at medium.
        severity = "high" if (broad_match is not None or admin_match is not None) else "medium"
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_FIREWALL_RULE_NO_TARGETS,
                finding_key=make_finding_key(
                    _RULE_FIREWALL_RULE_NO_TARGETS, record_id
                ),
                severity=severity,
                title="Google Cloud firewall rule has no explicit target tags or service accounts",
                description=(
                    f"Firewall rule '{firewall_name}' on network "
                    f"'{network_name}' in project '{project_id}' allows public "
                    f"inbound traffic but has no target tags and no target "
                    f"service accounts. In Google Cloud this may cause the "
                    f"rule to apply broadly across the network and may require "
                    f"review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_FIREWALL_RULE_NO_TARGETS,
                    "firewall_rule_name": firewall_name,
                    "network_name": network_name,
                    "project_id": project_id,
                    "direction": direction,
                    "priority": priority,
                    "disabled": False,
                    "source_ranges_summary": source_ranges_summary,
                    "target_tag_count": 0,
                    "target_service_account_count": 0,
                    "public_source": True,
                },
                remediation={
                    "summary": (
                        "Scope the firewall rule to specific target tags or "
                        "target service accounts so it only applies to the "
                        "intended VMs."
                    ),
                    "steps": [
                        "Identify the VMs (or VM templates) that need this "
                        "ingress.",
                        "Add target_tags or target_service_accounts to the "
                        "firewall rule so it only applies to those VMs.",
                        "Confirm the rule no longer applies to unrelated VMs "
                        "in the VPC.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Storage bucket ───────────────────────────────────────────────────────────



# Public-access-prevention values that mean "prevention is enforced" — anything
# else (missing / empty / "inherited" / "unspecified") means the bucket does
# NOT enforce public-access prevention.
_PAP_ENFORCED_VALUES: frozenset[str] = frozenset({"enforced"})


def _eval_storage_bucket(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    bucket_name = get_str(record, "bucket_name")
    location = get_str(record, "location")
    storage_class = get_str(record, "storage_class")
    public_access_prevention = get_str(record, "public_access_prevention")
    uniform_enabled = record.get("uniform_bucket_level_access_enabled")
    versioning_enabled = record.get("versioning_enabled")
    retention_locked = record.get("retention_policy_locked")
    retention_seconds = record.get("retention_policy_seconds")
    lifecycle_rule_count = record.get("lifecycle_rule_count")

    pap_lower = public_access_prevention.strip().lower() if isinstance(public_access_prevention, str) else ""
    pap_enforced = pap_lower in _PAP_ENFORCED_VALUES

    # F. Public-access prevention disabled.
    # Fires whenever PAP is missing / inherited / unspecified / explicitly
    # disabled. Severity bumps to high when uniform bucket-level access is
    # ALSO disabled (object ACLs can independently make objects public).
    if not pap_enforced:
        severity = "high" if uniform_enabled is False else "medium"
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_STORAGE_PUBLIC_ACCESS_PREVENTION_DISABLED,
                finding_key=make_finding_key(
                    _RULE_STORAGE_PUBLIC_ACCESS_PREVENTION_DISABLED, record_id
                ),
                severity=severity,
                title="Google Cloud Storage bucket does not enforce public access prevention",
                description=(
                    f"Storage bucket '{bucket_name}' in location '{location}' "
                    f"has public-access prevention set to "
                    f"'{public_access_prevention or 'inherited/unspecified'}'. "
                    f"This may allow broader bucket access depending on IAM "
                    f"or object ACLs and may require review. ConfigTrace does "
                    f"not inspect individual object ACLs and does not claim "
                    f"objects are public. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_STORAGE_PUBLIC_ACCESS_PREVENTION_DISABLED,
                    "bucket_name": bucket_name,
                    "location": location,
                    "storage_class": storage_class,
                    "public_access_prevention": public_access_prevention,
                    "uniform_bucket_level_access_enabled": uniform_enabled,
                },
                remediation={
                    "summary": (
                        "Set the bucket-level publicAccessPrevention policy "
                        "to 'enforced'."
                    ),
                    "steps": [
                        "In the bucket's IAM configuration, set "
                        "publicAccessPrevention to 'enforced'.",
                        "Audit existing object ACLs to confirm no objects are "
                        "already shared publicly.",
                        "Consider enabling uniform bucket-level access to "
                        "remove object ACL surface entirely.",
                    ],
                },
                record_id=record_id,
            )
        )

    # G. Uniform bucket-level access disabled.
    if uniform_enabled is False:
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_STORAGE_UNIFORM_ACCESS_DISABLED,
                finding_key=make_finding_key(
                    _RULE_STORAGE_UNIFORM_ACCESS_DISABLED, record_id
                ),
                severity="medium",
                title="Google Cloud Storage bucket does not enforce uniform bucket-level access",
                description=(
                    f"Storage bucket '{bucket_name}' in location '{location}' "
                    f"has uniform bucket-level access disabled, meaning "
                    f"per-object ACLs can independently grant access. This may "
                    f"complicate access governance and may require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_STORAGE_UNIFORM_ACCESS_DISABLED,
                    "bucket_name": bucket_name,
                    "location": location,
                    "storage_class": storage_class,
                    "uniform_bucket_level_access_enabled": False,
                    "public_access_prevention": public_access_prevention,
                },
                remediation={
                    "summary": (
                        "Enable uniform bucket-level access on the bucket so "
                        "access is governed by IAM only."
                    ),
                    "steps": [
                        "Audit any existing object ACLs and migrate the same "
                        "intent to IAM bindings.",
                        "Enable uniform bucket-level access on the bucket.",
                    ],
                },
                record_id=record_id,
            )
        )

    # H. Versioning disabled.
    if versioning_enabled is False:
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_STORAGE_VERSIONING_DISABLED,
                finding_key=make_finding_key(
                    _RULE_STORAGE_VERSIONING_DISABLED, record_id
                ),
                severity="low",
                title="Google Cloud Storage bucket does not have object versioning enabled",
                description=(
                    f"Storage bucket '{bucket_name}' in location '{location}' "
                    f"has object versioning disabled. This may affect "
                    f"recoverability of removed or overwritten objects and "
                    f"may require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_STORAGE_VERSIONING_DISABLED,
                    "bucket_name": bucket_name,
                    "location": location,
                    "storage_class": storage_class,
                    "versioning_enabled": False,
                    "lifecycle_rule_count": lifecycle_rule_count,
                },
                remediation={
                    "summary": "Enable object versioning on the bucket.",
                    "steps": [
                        "Enable versioning on the bucket configuration.",
                        "Configure lifecycle rules to prune older noncurrent "
                        "versions to bound storage cost.",
                    ],
                },
                record_id=record_id,
            )
        )

    # I. Retention policy not locked or absent.
    # Fires when the retention policy is either absent (no retentionPeriod)
    # OR present but unlocked (retention_policy_locked=false).
    has_retention = isinstance(retention_seconds, str) and retention_seconds.strip()
    has_retention = has_retention or isinstance(retention_seconds, int)
    if (not has_retention) or retention_locked is False:
        # Slightly higher severity when there IS a retention policy but it's
        # unlocked (configured-but-bypassable is a clearer governance gap)
        # than when none exists at all.
        severity = "medium" if has_retention and retention_locked is False else "low"
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_STORAGE_RETENTION_NOT_LOCKED,
                finding_key=make_finding_key(
                    _RULE_STORAGE_RETENTION_NOT_LOCKED, record_id
                ),
                severity=severity,
                title="Google Cloud Storage bucket retention policy is not locked",
                description=(
                    f"Storage bucket '{bucket_name}' in location '{location}' "
                    f"does not have a locked retention policy. This may affect "
                    f"long-term recoverability and immutability posture and "
                    f"may require review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_STORAGE_RETENTION_NOT_LOCKED,
                    "bucket_name": bucket_name,
                    "location": location,
                    "storage_class": storage_class,
                    "retention_policy_seconds": retention_seconds,
                    "retention_policy_locked": retention_locked,
                },
                remediation={
                    "summary": (
                        "Configure a retention policy and lock it to enforce "
                        "immutability."
                    ),
                    "steps": [
                        "Set a retentionPeriod that matches your compliance "
                        "or governance needs.",
                        "Lock the retention policy (note: locking is "
                        "irreversible — confirm the period first).",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Cloud SQL instance (M78C) ─────────────────────────────────────────────────


# SSL mode values that indicate non-strict encryption posture.
_WEAK_SSL_MODES: frozenset[str] = frozenset({
    "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
    "ENCRYPTED_ONLY",  # Encrypts but does not verify client certs — medium risk.
})


def _eval_sql_instance(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    instance_name = get_str(record, "instance_name")
    project_id = get_str(record, "project_id")
    region = get_str(record, "region")
    database_version = get_str(record, "database_version")
    state = get_str(record, "state")
    public_ip_enabled = record.get("public_ip_enabled")
    authorized_network_count = record.get("authorized_network_count")
    require_ssl = record.get("require_ssl")
    ssl_mode = get_str(record, "ssl_mode")
    backup_enabled = record.get("backup_enabled")
    deletion_protection_enabled = record.get("deletion_protection_enabled")

    # A. Public network access
    if public_ip_enabled is True:
        if isinstance(authorized_network_count, int) and authorized_network_count > 0:
            severity = "high"
        else:
            severity = "medium"
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_SQL_PUBLIC_NETWORK_ACCESS,
                finding_key=make_finding_key(_RULE_SQL_PUBLIC_NETWORK_ACCESS, record_id),
                severity=severity,
                title="Google Cloud SQL instance allows public network access",
                description=(
                    f"Cloud SQL instance '{instance_name}' in project '{project_id}' "
                    f"has a public IP address enabled. This may broaden database "
                    f"exposure and requires review. ConfigTrace does not confirm "
                    f"reachability, compromise, unauthorized access, or data exposure."
                ),
                evidence={
                    "rule": _RULE_SQL_PUBLIC_NETWORK_ACCESS,
                    "instance_name": instance_name,
                    "project_id": project_id,
                    "region": region,
                    "database_version": database_version,
                    "state": state,
                    "public_ip_enabled": True,
                    "authorized_network_count": authorized_network_count,
                },
                remediation={
                    "summary": (
                        "Disable the public IP address on the Cloud SQL instance "
                        "and use private IP with authorized networks instead."
                    ),
                    "steps": [
                        "Switch the instance to private IP connectivity using VPC "
                        "peering or Cloud SQL Auth Proxy.",
                        "If a public IP is required, restrict authorized networks "
                        "to the minimum necessary IP ranges.",
                        "Consider enabling the Cloud SQL Auth Proxy to avoid "
                        "exposing the database port directly.",
                    ],
                },
                record_id=record_id,
            )
        )

    # B. Weak SSL/TLS posture
    ssl_weak = (
        require_ssl is False
        or (isinstance(ssl_mode, str) and ssl_mode.upper() in _WEAK_SSL_MODES)
    )
    if ssl_weak:
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_SQL_WEAK_TLS,
                finding_key=make_finding_key(_RULE_SQL_WEAK_TLS, record_id),
                severity="medium",
                title="Google Cloud SQL instance does not require SSL/TLS",
                description=(
                    f"Cloud SQL instance '{instance_name}' in project '{project_id}' "
                    f"does not require SSL/TLS for all connections "
                    f"(require_ssl={require_ssl}, ssl_mode='{ssl_mode}'). "
                    f"This may allow unencrypted database connections and requires "
                    f"review. {_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_SQL_WEAK_TLS,
                    "instance_name": instance_name,
                    "project_id": project_id,
                    "region": region,
                    "require_ssl": require_ssl,
                    "ssl_mode": ssl_mode,
                },
                remediation={
                    "summary": (
                        "Enable require_ssl on the instance and set ssl_mode "
                        "to TRUSTED_CLIENT_CERTIFICATE_REQUIRED."
                    ),
                    "steps": [
                        "Set requireSsl=true on the IP configuration, or set "
                        "sslMode to TRUSTED_CLIENT_CERTIFICATE_REQUIRED.",
                        "Ensure clients use SSL certificates when connecting.",
                    ],
                },
                record_id=record_id,
            )
        )

    # C. Backups disabled
    if backup_enabled is False:
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_SQL_BACKUPS_DISABLED,
                finding_key=make_finding_key(_RULE_SQL_BACKUPS_DISABLED, record_id),
                severity="medium",
                title="Google Cloud SQL instance does not have automated backups enabled",
                description=(
                    f"Cloud SQL instance '{instance_name}' in project '{project_id}' "
                    f"has automated backups disabled. This may affect recoverability "
                    f"and requires review. {_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_SQL_BACKUPS_DISABLED,
                    "instance_name": instance_name,
                    "project_id": project_id,
                    "region": region,
                    "database_version": database_version,
                    "backup_enabled": False,
                },
                remediation={
                    "summary": "Enable automated backups on the Cloud SQL instance.",
                    "steps": [
                        "Enable automated backups in the instance settings.",
                        "Consider enabling point-in-time recovery (PITR) as well "
                        "for finer-grained restore capabilities.",
                    ],
                },
                record_id=record_id,
            )
        )

    # D. Deletion protection disabled
    if deletion_protection_enabled is False:
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_SQL_DELETION_PROTECTION_DISABLED,
                finding_key=make_finding_key(
                    _RULE_SQL_DELETION_PROTECTION_DISABLED, record_id
                ),
                severity="medium",
                title="Google Cloud SQL instance does not have deletion protection enabled",
                description=(
                    f"Cloud SQL instance '{instance_name}' in project '{project_id}' "
                    f"does not have deletion protection enabled. This may allow the "
                    f"instance to be accidentally deleted and requires review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_SQL_DELETION_PROTECTION_DISABLED,
                    "instance_name": instance_name,
                    "project_id": project_id,
                    "region": region,
                    "database_version": database_version,
                    "deletion_protection_enabled": False,
                },
                remediation={
                    "summary": "Enable deletion protection on the Cloud SQL instance.",
                    "steps": [
                        "Set deletionProtectionEnabled=true on the instance settings.",
                        "Review which principals have permission to update instance "
                        "settings if needed.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Cloud Run service (M78C) ──────────────────────────────────────────────────


# Cloud Run ingress values that mean "all traffic including public internet".
_RUN_ALL_INGRESS_VALUES: frozenset[str] = frozenset({
    "INGRESS_TRAFFIC_ALL",
    "ALL",
})


def _eval_run_service(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    service_name = get_str(record, "service_name")
    project_id = get_str(record, "project_id")
    region = get_str(record, "region")
    ingress = get_str(record, "ingress")
    public_invoker_allowed = record.get("public_invoker_allowed")

    # E. Public invoker
    if public_invoker_allowed is True:
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_RUN_PUBLIC_INVOKER,
                finding_key=make_finding_key(_RULE_RUN_PUBLIC_INVOKER, record_id),
                severity="high",
                title="Google Cloud Run service allows public invocation",
                description=(
                    f"Cloud Run service '{service_name}' in region '{region}' "
                    f"in project '{project_id}' allows public invocation (allUsers "
                    f"or allAuthenticatedUsers has roles/run.invoker). This may "
                    f"broaden service access and requires review. "
                    f"ConfigTrace does not confirm invocation events or unauthorized "
                    f"access. {_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_RUN_PUBLIC_INVOKER,
                    "service_name": service_name,
                    "project_id": project_id,
                    "region": region,
                    "ingress": ingress,
                    "public_invoker_allowed": True,
                    "invoker_policy_summary": record.get("invoker_policy_summary"),
                },
                remediation={
                    "summary": (
                        "Remove the allUsers / allAuthenticatedUsers binding from "
                        "the Cloud Run service's IAM policy."
                    ),
                    "steps": [
                        "Audit the Cloud Run service IAM policy for public "
                        "sentinels on roles/run.invoker.",
                        "Replace with explicit identity bindings scoped to the "
                        "intended callers.",
                        "Use VPC-internal ingress combined with authenticated "
                        "service-to-service calls if public access is not needed.",
                    ],
                },
                record_id=record_id,
            )
        )

    # F. All-ingress traffic
    ingress_is_all = (ingress.upper() in _RUN_ALL_INGRESS_VALUES) if ingress else False
    if ingress_is_all:
        severity = "high" if public_invoker_allowed is True else "medium"
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_RUN_ALL_INGRESS,
                finding_key=make_finding_key(_RULE_RUN_ALL_INGRESS, record_id),
                severity=severity,
                title="Google Cloud Run service allows all ingress traffic",
                description=(
                    f"Cloud Run service '{service_name}' in region '{region}' "
                    f"in project '{project_id}' has ingress set to "
                    f"'{ingress}', which allows all traffic including from the public "
                    f"internet. This may broaden service exposure and requires "
                    f"review. {_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_RUN_ALL_INGRESS,
                    "service_name": service_name,
                    "project_id": project_id,
                    "region": region,
                    "ingress": ingress,
                    "public_invoker_allowed": public_invoker_allowed,
                },
                remediation={
                    "summary": (
                        "Restrict ingress to internal or internal + load balancer "
                        "if public internet access is not required."
                    ),
                    "steps": [
                        "Set ingress to INGRESS_TRAFFIC_INTERNAL_ONLY or "
                        "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER.",
                        "If public access is needed, ensure IAM restricts "
                        "invocation to authenticated identities.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── GKE cluster (M78C) ────────────────────────────────────────────────────────


def _eval_gke_cluster(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    cluster_name = get_str(record, "cluster_name")
    project_id = get_str(record, "project_id")
    location = get_str(record, "location")
    public_endpoint_enabled = record.get("public_endpoint_enabled")
    master_authorized_networks_count = record.get("master_authorized_networks_count")
    legacy_abac_enabled = record.get("legacy_abac_enabled")
    network_policy_enabled = record.get("network_policy_enabled")
    workload_identity_enabled = record.get("workload_identity_enabled")

    # G. Public control plane without authorized networks
    public_without_restrictions = (
        public_endpoint_enabled is True
        and (
            master_authorized_networks_count == 0
            or master_authorized_networks_count is None
        )
    )
    if public_without_restrictions:
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_GKE_PUBLIC_CONTROL_PLANE,
                finding_key=make_finding_key(_RULE_GKE_PUBLIC_CONTROL_PLANE, record_id),
                severity="high",
                title="GKE cluster control plane appears publicly reachable without authorized network restrictions",
                description=(
                    f"GKE cluster '{cluster_name}' in location '{location}' "
                    f"in project '{project_id}' has a public control plane endpoint "
                    f"with no master authorized network restrictions. This may "
                    f"require review. ConfigTrace does not confirm actual "
                    f"reachability, compromise, or unauthorized access. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_GKE_PUBLIC_CONTROL_PLANE,
                    "cluster_name": cluster_name,
                    "project_id": project_id,
                    "location": location,
                    "public_endpoint_enabled": True,
                    "master_authorized_networks_count": master_authorized_networks_count,
                },
                remediation={
                    "summary": (
                        "Enable master authorized networks and restrict control "
                        "plane access to known IP ranges, or enable a private "
                        "control plane endpoint."
                    ),
                    "steps": [
                        "Enable masterAuthorizedNetworksConfig and add the "
                        "minimum necessary CIDR ranges.",
                        "Consider enabling the private endpoint "
                        "(enablePrivateEndpoint=true) if public API access is "
                        "not required.",
                    ],
                },
                record_id=record_id,
            )
        )

    # H. Legacy ABAC enabled
    if legacy_abac_enabled is True:
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_GKE_LEGACY_ABAC_ENABLED,
                finding_key=make_finding_key(_RULE_GKE_LEGACY_ABAC_ENABLED, record_id),
                severity="high",
                title="GKE cluster has legacy attribute-based access control (ABAC) enabled",
                description=(
                    f"GKE cluster '{cluster_name}' in location '{location}' "
                    f"in project '{project_id}' has legacy ABAC enabled. Legacy "
                    f"ABAC is a deprecated authorization mode that may broaden "
                    f"access beyond what is intended by RBAC policies and requires "
                    f"review. {_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_GKE_LEGACY_ABAC_ENABLED,
                    "cluster_name": cluster_name,
                    "project_id": project_id,
                    "location": location,
                    "legacy_abac_enabled": True,
                },
                remediation={
                    "summary": "Disable legacy ABAC and rely exclusively on Kubernetes RBAC.",
                    "steps": [
                        "Disable legacy ABAC (legacyAbac.enabled=false) on the cluster.",
                        "Ensure all access-control requirements are expressed in "
                        "RBAC policies before disabling.",
                    ],
                },
                record_id=record_id,
            )
        )

    # I. Network policy disabled
    if network_policy_enabled is False:
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_GKE_NETWORK_POLICY_DISABLED,
                finding_key=make_finding_key(
                    _RULE_GKE_NETWORK_POLICY_DISABLED, record_id
                ),
                severity="medium",
                title="GKE cluster does not have network policy enforcement enabled",
                description=(
                    f"GKE cluster '{cluster_name}' in location '{location}' "
                    f"in project '{project_id}' does not have network policy "
                    f"enforcement enabled. Without a network policy, all pods can "
                    f"communicate with each other by default, which may broaden "
                    f"lateral-movement risk and requires review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_GKE_NETWORK_POLICY_DISABLED,
                    "cluster_name": cluster_name,
                    "project_id": project_id,
                    "location": location,
                    "network_policy_enabled": False,
                },
                remediation={
                    "summary": "Enable a network policy provider on the GKE cluster.",
                    "steps": [
                        "Enable networkPolicy.enabled=true and choose a provider "
                        "(e.g. CALICO).",
                        "Define NetworkPolicy objects in each namespace to restrict "
                        "pod-to-pod traffic to the minimum necessary.",
                    ],
                },
                record_id=record_id,
            )
        )

    # J. Workload identity disabled
    if workload_identity_enabled is False:
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_GKE_WORKLOAD_IDENTITY_DISABLED,
                finding_key=make_finding_key(
                    _RULE_GKE_WORKLOAD_IDENTITY_DISABLED, record_id
                ),
                severity="medium",
                title="GKE cluster does not have Workload Identity enabled",
                description=(
                    f"GKE cluster '{cluster_name}' in location '{location}' "
                    f"in project '{project_id}' does not have Workload Identity "
                    f"enabled. Without Workload Identity, workloads must use "
                    f"node-scoped service account credentials, which may broaden "
                    f"credential access and requires review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_GKE_WORKLOAD_IDENTITY_DISABLED,
                    "cluster_name": cluster_name,
                    "project_id": project_id,
                    "location": location,
                    "workload_identity_enabled": False,
                },
                remediation={
                    "summary": "Enable Workload Identity on the GKE cluster.",
                    "steps": [
                        "Enable Workload Identity by setting "
                        "workloadIdentityConfig.workloadPool=<PROJECT_ID>.svc.id.goog.",
                        "Migrate workloads to use Kubernetes service accounts "
                        "annotated with IAM service accounts.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Service account key summary (M78C) ───────────────────────────────────────

# Key age threshold that elevates a USER_MANAGED key to "old".
_OLD_KEY_AGE_DAYS = 90


def _eval_service_account_key_summary(
    record: dict[str, Any],
) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    project_id = get_str(record, "project_id")
    service_account_count = record.get("service_account_count")
    user_managed_key_count = record.get("user_managed_key_count")
    old_user_managed_key_count = record.get("old_user_managed_key_count")
    oldest_key_age_days = record.get("oldest_key_age_days")

    # K. User-managed keys present
    if isinstance(user_managed_key_count, int) and user_managed_key_count > 0:
        severity = "high" if user_managed_key_count >= 5 else "medium"
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_SA_USER_MANAGED_KEYS,
                finding_key=make_finding_key(_RULE_SA_USER_MANAGED_KEYS, record_id),
                severity=severity,
                title="Google Cloud service accounts have user-managed keys",
                description=(
                    f"Project '{project_id}' has {user_managed_key_count} "
                    f"user-managed service account key(s). This may increase "
                    f"credential-management risk and requires review. "
                    f"ConfigTrace does not confirm that keys are in use, were "
                    f"leaked, or represent unauthorized access. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_SA_USER_MANAGED_KEYS,
                    "project_id": project_id,
                    "service_account_count": service_account_count,
                    "user_managed_key_count": user_managed_key_count,
                },
                remediation={
                    "summary": (
                        "Replace user-managed service account keys with Workload "
                        "Identity or short-lived credentials."
                    ),
                    "steps": [
                        "Audit which services use user-managed keys and migrate "
                        "to Workload Identity where possible.",
                        "For workloads outside GCP, use service account key "
                        "rotation policies and minimize the number of keys.",
                        "Delete any user-managed keys that are no longer in use.",
                    ],
                },
                record_id=record_id,
            )
        )

    # L. Old user-managed keys
    has_old = (
        (isinstance(old_user_managed_key_count, int) and old_user_managed_key_count > 0)
        or (isinstance(oldest_key_age_days, int) and oldest_key_age_days >= _OLD_KEY_AGE_DAYS)
    )
    if has_old:
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_SA_OLD_KEYS,
                finding_key=make_finding_key(_RULE_SA_OLD_KEYS, record_id),
                severity="medium",
                title="Google Cloud service accounts have aged user-managed keys",
                description=(
                    f"Project '{project_id}' has {old_user_managed_key_count or 0} "
                    f"user-managed service account key(s) older than "
                    f"{_OLD_KEY_AGE_DAYS} days "
                    f"(oldest: {oldest_key_age_days} days). Long-lived keys may "
                    f"increase credential-rotation risk and requires review. "
                    f"{_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_SA_OLD_KEYS,
                    "project_id": project_id,
                    "user_managed_key_count": user_managed_key_count,
                    "old_user_managed_key_count": old_user_managed_key_count,
                    "oldest_key_age_days": oldest_key_age_days,
                },
                remediation={
                    "summary": "Rotate or delete service account keys older than 90 days.",
                    "steps": [
                        "Identify user-managed keys older than 90 days in IAM.",
                        "Rotate the keys (create new, update application, delete old).",
                        "Consider migrating to Workload Identity to eliminate "
                        "long-lived key management entirely.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Secret Manager summary (M78C) ─────────────────────────────────────────────


def _eval_secret_manager_summary(
    record: dict[str, Any],
) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    record_id = get_str(record, "record_id") or None
    project_id = get_str(record, "project_id")
    secret_count = record.get("secret_count")
    automatic_replication_count = record.get("automatic_replication_count")
    customer_managed_encryption_count = record.get("customer_managed_encryption_count")

    # M. Automatic replication without CMEK
    if (
        isinstance(automatic_replication_count, int)
        and automatic_replication_count > 0
        and (
            not isinstance(customer_managed_encryption_count, int)
            or customer_managed_encryption_count == 0
        )
    ):
        out.append(
            FindingCandidate(
                provider="google_cloud",
                rule_key=_RULE_SECRET_MANAGER_AUTO_REPLICATION_WITHOUT_CMEK,
                finding_key=make_finding_key(
                    _RULE_SECRET_MANAGER_AUTO_REPLICATION_WITHOUT_CMEK, record_id
                ),
                severity="low",
                title=(
                    "Google Cloud Secret Manager uses automatic replication "
                    "without customer-managed encryption keys"
                ),
                description=(
                    f"Project '{project_id}' has {automatic_replication_count} "
                    f"Secret Manager secret(s) using automatic replication without "
                    f"customer-managed encryption keys (CMEK). Secrets are encrypted "
                    f"at rest using Google-managed keys. This is a governance "
                    f"posture finding and requires review if CMEK is required "
                    f"by policy. {_common_disclaimer()}"
                ),
                evidence={
                    "rule": _RULE_SECRET_MANAGER_AUTO_REPLICATION_WITHOUT_CMEK,
                    "project_id": project_id,
                    "secret_count": secret_count,
                    "automatic_replication_count": automatic_replication_count,
                    "customer_managed_encryption_count": customer_managed_encryption_count,
                },
                remediation={
                    "summary": (
                        "Configure customer-managed encryption keys (CMEK) on "
                        "Secret Manager secrets where required by policy."
                    ),
                    "steps": [
                        "Identify secrets that must comply with CMEK requirements.",
                        "Create a Cloud KMS key and grant Secret Manager the "
                        "needed roles/cloudkms.cryptoKeyEncrypterDecrypter role.",
                        "Recreate the affected secrets with the CMEK configuration.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out
