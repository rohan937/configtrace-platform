"""Google Cloud drift risk classification rules.

Entry point: ``classify_google_cloud_change(change)``

Classifies drift changes for Google Cloud configuration records. Built
during the Google Cloud detection QA pass — this module previously did
not exist, so every Google Cloud change silently fell through to the
Cloudflare DNS classifier fallback in ``risk_service.py``, despite the
provider capability matrix already advertising
``drift_risk_classification=True``.

Risk levels
-----------
critical — a firewall rule allows broad public inbound access on all
           ports/protocols, or public inbound access on an
           RDP/WinRM/SQL/MySQL/PostgreSQL/Redis/Elasticsearch/MongoDB
           port from a public source range.

high     — IAM policy gains a public member (allUsers /
           allAuthenticatedUsers); IAM policy gains a high-severity broad
           privileged role (owner/editor/securityAdmin/projectIamAdmin);
           a firewall rule gains a public SSH ingress entry; a bucket's
           public-access-prevention is disabled; Cloud SQL public IP is
           enabled; Cloud Run allows public invocation; a GKE cluster
           gains legacy ABAC; a project's user-managed service account
           key count reaches 5 or more.

medium   — IAM policy gains a medium-severity broad privileged role
           (service-account admin roles); a firewall rule newly targets
           no tags/service accounts while carrying public ingress; a
           bucket's uniform bucket-level access is disabled; a bucket's
           retention policy becomes unlocked; Cloud SQL SSL/backups/
           deletion-protection is disabled; Cloud Run ingress opens to
           all traffic; a GKE cluster's network policy or Workload
           Identity is disabled; a project's user-managed key count
           increases (below 5); old (>=90 day) user-managed keys appear.

low      — count-only changes with unclear impact; metadata-only drift;
           unknown/missing category fields; safe restoration/improvement
           transitions (e.g. a public IAM member removed, a firewall
           rule's public ingress narrowed, a bucket's uniform access
           re-enabled).

Claim discipline
-----------------
All reason strings use safe review-framing:
  "Google Cloud IAM access was broadened"
  "Google Cloud bucket public-access posture changed"
  "Firewall ingress posture changed"
  "Cloud SQL network posture changed"
  "This may require review"
  "Configuration evidence does not confirm compromise, unauthorized
  access, data exposure, secret exposure, or infrastructure exposure."
Forbidden phrases: breach, compromise, attacker, leaked, unauthorized
access, bucket exposed, state exposed, secret exposed, infrastructure
exposed, data exposed, customer data exposed.
"""

from __future__ import annotations

from typing import Any, Optional

from app.models.change import Change

# Thresholds/sets mirrored from security_rules/google_cloud.py so Change
# severities stay aligned with the corresponding Security Findings.
_PUBLIC_SOURCE_RANGES: frozenset[str] = frozenset({"0.0.0.0/0", "::/0"})
_ADMIN_PORTS_CRITICAL: frozenset[int] = frozenset({
    3389, 5985, 5986, 1433, 3306, 5432, 6379, 9200, 27017,
})
_ADMIN_PORTS_HIGH: frozenset[int] = frozenset({22})
_ALL_PROTOCOL_LITERALS: frozenset[str] = frozenset({"all", "*", "any"})

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

_WEAK_SSL_MODES: frozenset[str] = frozenset({
    "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
    "ENCRYPTED_ONLY",
})
_RUN_ALL_INGRESS_VALUES: frozenset[str] = frozenset({"INGRESS_TRAFFIC_ALL", "ALL"})

_MANY_KEY_COUNT_THRESHOLD = 4  # >=5 is "high" per security_rules/google_cloud.py
_OLD_KEY_AGE_DAYS = 90


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


def _as_str_list(val: object) -> list[str]:
    if isinstance(val, list):
        return [v for v in val if isinstance(v, str)]
    return []


def _as_str_list_or_none(val: object) -> Optional[list[str]]:
    """Like ``_as_str_list``, but preserves the missing/unknown distinction.

    Returns ``None`` (not ``[]``) when *val* is not actually a list, so a
    genuinely unknown/missing list is never conflated with an explicitly
    empty one — the list-valued analog of ``_int_or_none()``.
    """
    if isinstance(val, list):
        return [v for v in val if isinstance(v, str)]
    return None


def _as_dict_list(val: object) -> list[dict]:
    if isinstance(val, list):
        return [v for v in val if isinstance(v, dict)]
    return []


def _as_dict_list_or_none(val: object) -> Optional[list[dict]]:
    """List-of-dict analog of ``_as_str_list_or_none``."""
    if isinstance(val, list):
        return [v for v in val if isinstance(v, dict)]
    return None


def _expand_ports(ports_value: object) -> list[int]:
    """Best-effort parse of an allowed_summary[i]["ports"] entry into ints.

    Mirrors security_rules/google_cloud.py's ``_expand_ports``.
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
    """Mirrors security_rules/google_cloud.py's ``_is_broad_port_entry``."""
    proto = (entry.get("protocol") or "").strip().lower()
    ports = entry.get("ports")
    if proto in _ALL_PROTOCOL_LITERALS:
        return True
    if isinstance(ports, list) and len(ports) == 0:
        return True
    if isinstance(ports, list):
        for p in ports:
            if isinstance(p, str) and p.strip() in {"*", "any", "ANY", "0-65535", "1-65535"}:
                return True
    return False


def _entry_key(entry: dict) -> tuple:
    proto = (entry.get("protocol") or "").strip().lower()
    ports = tuple(sorted(_as_str_list(entry.get("ports"))))
    return (proto, ports)


def _added_entries(prev_v: object, new_v: object) -> list[dict]:
    """Return allowed_summary entries present in *new_v* but not *prev_v*."""
    prev_entries = _as_dict_list(prev_v)
    new_entries = _as_dict_list(new_v)
    prev_keys = {_entry_key(e) for e in prev_entries}
    return [e for e in new_entries if _entry_key(e) not in prev_keys]


# ── google_cloud_project ─────────────────────────────────────────────────────


def _classify_project_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()

    if ct in ("added", "removed"):
        return ("low", "Google Cloud project configuration record was added or removed during sync.")

    # No dedicated Security Finding exists for google_cloud_project — project
    # metadata is informational (see security_rules/google_cloud.py's own
    # docstring: "no actionable posture surface").
    if fp in (
        "project_number", "display_name", "lifecycle_state", "parent_type",
        "create_time", "label_keys",
    ):
        return ("low", f"Google Cloud project {fp.replace('_', ' ')} changed.")

    return ("low", f"Google Cloud project configuration field '{fp}' changed.")


# ── google_cloud_iam_policy_summary ──────────────────────────────────────────


def _classify_iam_policy_summary_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Google Cloud IAM policy summary record was added or removed during sync.")

    if fp in ("allusers_binding_present", "allauthenticatedusers_binding_present"):
        if _is_truthy(new_v):
            return (
                "high",
                "Google Cloud IAM access was broadened — the project IAM policy "
                "now includes a public member. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Google Cloud IAM public member binding was removed.")
        return ("low", "Google Cloud IAM public member presence is now unknown or missing.")

    if fp == "role_names":
        new_role_list = _as_str_list_or_none(new_v)
        if new_role_list is None:
            return ("low", "Google Cloud IAM policy role names are now unknown or missing.")
        new_roles = set(new_role_list)
        prev_role_list = _as_str_list_or_none(prev_v)
        if prev_role_list is None:
            # Previous role list is genuinely unknown — cannot claim a role
            # was newly "added". Evaluate the current role set only, mirroring
            # the Finding's own current-state-only check, without overstating
            # a transition we have no evidence for.
            if new_roles & _HIGH_SEVERITY_BROAD_ROLES:
                return (
                    "high",
                    "Google Cloud IAM policy currently includes a broad "
                    "privileged role, though prior role names are unknown or "
                    "missing. This may require review.",
                )
            if new_roles & _MEDIUM_SEVERITY_BROAD_ROLES:
                return (
                    "medium",
                    "Google Cloud IAM policy currently includes a "
                    "service-account admin role, though prior role names are "
                    "unknown or missing. This may require review.",
                )
            return ("low", "Google Cloud IAM policy role names changed.")

        prev_roles = set(prev_role_list)
        added_roles = new_roles - prev_roles
        if added_roles & _HIGH_SEVERITY_BROAD_ROLES:
            return (
                "high",
                "Google Cloud IAM access was broadened — a broad privileged "
                "role was added to the project IAM policy. This may require review.",
            )
        if added_roles & _MEDIUM_SEVERITY_BROAD_ROLES:
            return (
                "medium",
                "Google Cloud IAM access was broadened — a service-account "
                "admin role was added to the project IAM policy. This may require review.",
            )
        removed_roles = prev_roles - new_roles
        if removed_roles & (_HIGH_SEVERITY_BROAD_ROLES | _MEDIUM_SEVERITY_BROAD_ROLES):
            return ("low", "Google Cloud IAM broad privileged role was removed.")
        return ("low", "Google Cloud IAM policy role names changed.")

    if fp in (
        "binding_count", "role_count", "broad_role_count", "user_member_count",
        "group_member_count", "service_account_member_count",
        "domain_member_count", "other_member_count", "conditional_binding_count",
    ):
        return ("low", f"Google Cloud IAM policy {fp.replace('_', ' ')} changed.")

    return ("low", f"Google Cloud IAM policy summary field '{fp}' changed.")


# ── google_cloud_vpc_network ─────────────────────────────────────────────────


def _classify_vpc_network_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()

    if ct in ("added", "removed"):
        return ("low", "Google Cloud VPC network configuration record was added or removed during sync.")

    # No dedicated Security Finding exists for google_cloud_vpc_network —
    # network posture is captured via the firewall-rule surface instead
    # (see security_rules/google_cloud.py's own docstring).
    if fp in (
        "network_name", "auto_create_subnetworks", "routing_mode", "mtu",
        "subnet_count", "peering_count",
    ):
        return ("low", f"Google Cloud VPC network {fp.replace('_', ' ')} changed.")

    return ("low", f"Google Cloud VPC network configuration field '{fp}' changed.")


# ── google_cloud_firewall_rule ───────────────────────────────────────────────


def _classify_firewall_rule_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Google Cloud firewall rule configuration record was added or removed during sync.")

    if fp == "disabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Firewall ingress posture changed — a firewall rule was "
                "enabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Firewall rule was disabled.")
        return ("low", "Firewall rule disabled state is now unknown or missing.")

    if fp == "source_ranges_summary":
        new_range_list = _as_str_list_or_none(new_v)
        if new_range_list is None:
            return ("low", "Firewall rule source ranges are now unknown or missing.")
        new_ranges = set(new_range_list)
        prev_range_list = _as_str_list_or_none(prev_v)
        if prev_range_list is None:
            # Previous source ranges are genuinely unknown — cannot claim a
            # public range was newly "added". Evaluate the current source
            # ranges only, without overstating a transition we have no
            # evidence for.
            if new_ranges & _PUBLIC_SOURCE_RANGES:
                return (
                    "low",
                    "Firewall rule currently has a public source range, though "
                    "prior source ranges are unknown or missing. This may require review.",
                )
            return ("low", "Firewall rule source ranges changed.")

        prev_ranges = set(prev_range_list)
        gained_public = bool((new_ranges - prev_ranges) & _PUBLIC_SOURCE_RANGES)
        lost_public = bool((prev_ranges - new_ranges) & _PUBLIC_SOURCE_RANGES)
        if gained_public:
            return (
                "high",
                "Firewall ingress posture changed — a public source range "
                "(0.0.0.0/0 or ::/0) was added. This may require review.",
            )
        if lost_public:
            return ("low", "Firewall rule's public source range was removed.")
        return ("low", "Firewall rule source ranges changed.")

    if fp == "allowed_summary":
        new_entry_list = _as_dict_list_or_none(new_v)
        if new_entry_list is None:
            return ("low", "Firewall rule allowed entries are now unknown or missing.")
        prev_entry_list = _as_dict_list_or_none(prev_v)
        if prev_entry_list is None:
            # Previous allowed entries are genuinely unknown — cannot claim
            # an entry was newly "added". Evaluate the current entries only,
            # mirroring the Finding's own current-state-only check.
            worst = "low"
            for entry in new_entry_list:
                if _is_broad_port_entry(entry):
                    worst = "critical"
                    break
                ports = _expand_ports(entry.get("ports"))
                if any(p in _ADMIN_PORTS_CRITICAL for p in ports):
                    worst = "critical"
                    break
                if any(p in _ADMIN_PORTS_HIGH for p in ports) and worst != "critical":
                    worst = "high"
            if worst in ("critical", "high"):
                return (
                    worst,
                    "Firewall rule currently has a broad or administrative-port "
                    "allowed entry, though prior allowed entries are unknown or "
                    "missing. This may require review.",
                )
            return ("low", "Firewall rule allowed entries changed.")

        added = _added_entries(prev_entry_list, new_entry_list)
        if not added:
            removed = _added_entries(new_entry_list, prev_entry_list)
            if removed:
                return ("low", "Firewall rule's allowed protocol/port entry was removed.")
            return ("low", "Firewall rule allowed entries changed.")
        worst = "low"
        for entry in added:
            if _is_broad_port_entry(entry):
                worst = "critical"
                break
            ports = _expand_ports(entry.get("ports"))
            if any(p in _ADMIN_PORTS_CRITICAL for p in ports):
                worst = "critical"
                break
            if any(p in _ADMIN_PORTS_HIGH for p in ports) and worst != "critical":
                worst = "high"
        if worst in ("critical", "high"):
            return (
                worst,
                "Firewall ingress posture changed — a new allowed protocol/port "
                "entry was added. This may require review.",
            )
        return ("low", "Firewall rule gained an allowed protocol/port entry.")

    if fp in ("target_tag_count", "target_service_account_count"):
        n_new = _int_or_none(new_v)
        n_old = _int_or_none(prev_v)
        if n_new is None:
            return ("low", f"Firewall rule {fp.replace('_', ' ')} is now unknown or missing.")
        if n_new == 0 and (n_old or 0) > 0:
            return (
                "medium",
                "Firewall ingress posture changed — the rule no longer has "
                "explicit target tags or service accounts. This may require review.",
            )
        if n_old == 0 and n_new > 0:
            return ("low", f"Firewall rule {fp.replace('_', ' ')} increased from 0.")
        return ("low", f"Firewall rule {fp.replace('_', ' ')} changed to {n_new}.")

    if fp in (
        "firewall_name", "network_name", "direction", "priority",
        "destination_ranges_summary", "denied_summary", "has_log_config",
    ):
        return ("low", f"Firewall rule {fp.replace('_', ' ')} changed.")

    return ("low", f"Firewall rule configuration field '{fp}' changed.")


# ── google_cloud_storage_bucket ──────────────────────────────────────────────


def _classify_storage_bucket_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Google Cloud Storage bucket configuration record was added or removed during sync.")

    if fp == "public_access_prevention":
        new_enforced = isinstance(new_v, str) and new_v.strip().lower() == "enforced"
        prev_enforced = isinstance(prev_v, str) and prev_v.strip().lower() == "enforced"
        if not new_enforced and prev_enforced:
            return (
                "medium",
                "Google Cloud bucket public-access posture changed — public "
                "access prevention is no longer enforced. This may require review.",
            )
        if new_enforced and not prev_enforced:
            return ("low", "Google Cloud bucket public access prevention was enforced.")
        return ("low", "Google Cloud bucket public access prevention category changed.")

    if fp == "uniform_bucket_level_access_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Google Cloud bucket public-access posture changed — uniform "
                "bucket-level access was disabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Google Cloud bucket uniform bucket-level access was enabled.")
        return ("low", "Google Cloud bucket uniform bucket-level access state is now unknown or missing.")

    if fp == "versioning_enabled":
        if _is_falsy_explicit(new_v):
            return ("low", "Google Cloud bucket object versioning was disabled. This may require review.")
        if _is_truthy(new_v):
            return ("low", "Google Cloud bucket object versioning was enabled.")
        return ("low", "Google Cloud bucket versioning state is now unknown or missing.")

    if fp == "retention_policy_locked":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Google Cloud bucket retention policy is no longer locked. "
                "This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Google Cloud bucket retention policy was locked.")
        return ("low", "Google Cloud bucket retention lock state is now unknown or missing.")

    if fp in (
        "bucket_name", "location", "location_type", "storage_class",
        "retention_policy_seconds", "lifecycle_rule_count",
        "encryption_default_kms_key_present",
    ):
        return ("low", f"Google Cloud bucket {fp.replace('_', ' ')} changed.")

    return ("low", f"Google Cloud Storage bucket configuration field '{fp}' changed.")


# ── google_cloud_sql_instance ────────────────────────────────────────────────


def _classify_sql_instance_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Google Cloud SQL instance configuration record was added or removed during sync.")

    if fp == "public_ip_enabled":
        if _is_truthy(new_v):
            return (
                "high",
                "Cloud SQL network posture changed — public IP was enabled. "
                "This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Cloud SQL public IP was disabled.")
        return ("low", "Cloud SQL public IP state is now unknown or missing.")

    if fp == "require_ssl":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Cloud SQL network posture changed — SSL is no longer "
                "required. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Cloud SQL SSL requirement was enabled.")
        return ("low", "Cloud SQL SSL requirement state is now unknown or missing.")

    if fp == "ssl_mode":
        new_weak = isinstance(new_v, str) and new_v.upper() in _WEAK_SSL_MODES
        prev_weak = isinstance(prev_v, str) and prev_v.upper() in _WEAK_SSL_MODES
        if new_weak and not prev_weak:
            return (
                "medium",
                "Cloud SQL network posture changed — SSL mode weakened. "
                "This may require review.",
            )
        if not new_weak and prev_weak:
            return ("low", "Cloud SQL SSL mode was strengthened.")
        return ("low", "Cloud SQL SSL mode changed.")

    if fp == "backup_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Cloud SQL automated backups were disabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Cloud SQL automated backups were enabled.")
        return ("low", "Cloud SQL backup state is now unknown or missing.")

    if fp == "deletion_protection_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "Cloud SQL deletion protection was disabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "Cloud SQL deletion protection was enabled.")
        return ("low", "Cloud SQL deletion protection state is now unknown or missing.")

    if fp in (
        "instance_name", "database_version", "region", "state",
        "authorized_network_count", "point_in_time_recovery_enabled",
        "availability_type",
    ):
        return ("low", f"Cloud SQL instance {fp.replace('_', ' ')} changed.")

    return ("low", f"Cloud SQL instance configuration field '{fp}' changed.")


# ── google_cloud_run_service ─────────────────────────────────────────────────


def _classify_run_service_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Google Cloud Run service configuration record was added or removed during sync.")

    if fp == "public_invoker_allowed":
        if _is_truthy(new_v):
            return (
                "high",
                "Google Cloud Run service posture changed — public invocation "
                "was enabled. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "Google Cloud Run public invocation was disabled.")
        return ("low", "Google Cloud Run public invocation state is now unknown or missing.")

    if fp == "ingress":
        # Change-only signal, deliberately kept at "medium" rather than the
        # Finding's "high" ceiling: google_cloud_run_all_ingress only reaches
        # "high" when combined with public_invoker_allowed=True, which is
        # not the common case for a service opening ingress — most all-
        # ingress Cloud Run services still require IAM-authenticated
        # invocation. Defaulting to "high" would over-alert on that common,
        # safe configuration.
        if isinstance(new_v, str) and new_v.upper() in _RUN_ALL_INGRESS_VALUES:
            return (
                "medium",
                "Google Cloud Run service posture changed — ingress was "
                "opened to all traffic. This may require review.",
            )
        return ("low", "Google Cloud Run service ingress changed.")

    if fp in (
        "service_name", "region", "launch_stage", "invoker_policy_summary",
        "environment_variable_count", "secret_environment_variable_count",
    ):
        return ("low", f"Google Cloud Run service {fp.replace('_', ' ')} changed.")

    return ("low", f"Google Cloud Run service configuration field '{fp}' changed.")


# ── google_cloud_gke_cluster ─────────────────────────────────────────────────


def _classify_gke_cluster_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Google Cloud GKE cluster configuration record was added or removed during sync.")

    if fp == "public_endpoint_enabled":
        # Change-only signal, deliberately kept at "medium" rather than the
        # Finding's "high" ceiling: google_cloud_gke_public_control_plane
        # only reaches "high" when master_authorized_networks_count is also
        # 0/None, which a single-field Change can't confirm — a public
        # endpoint combined with authorized networks is a common, safe GKE
        # configuration. Defaulting to "high" would over-alert on that case.
        if _is_truthy(new_v):
            return (
                "medium",
                "GKE cluster public endpoint posture changed — the control "
                "plane endpoint became public. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "GKE cluster control plane endpoint was made private.")
        return ("low", "GKE cluster public endpoint state is now unknown or missing.")

    if fp == "legacy_abac_enabled":
        if _is_truthy(new_v):
            return (
                "high",
                "GKE cluster authorization posture changed — legacy ABAC was "
                "enabled. This may require review.",
            )
        if _is_falsy_explicit(new_v):
            return ("low", "GKE cluster legacy ABAC was disabled.")
        return ("low", "GKE cluster legacy ABAC state is now unknown or missing.")

    if fp == "network_policy_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "GKE cluster network policy enforcement was disabled. "
                "This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "GKE cluster network policy enforcement was enabled.")
        return ("low", "GKE cluster network policy state is now unknown or missing.")

    if fp == "workload_identity_enabled":
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "GKE cluster Workload Identity was disabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "GKE cluster Workload Identity was enabled.")
        return ("low", "GKE cluster Workload Identity state is now unknown or missing.")

    if fp == "shielded_nodes_enabled":
        # Matches google_cloud_gke_shielded_nodes_disabled (medium), added
        # during this classification-QA pass — a direct single-field analog
        # of the sibling network_policy_enabled/workload_identity_enabled
        # rules already present on this same record type.
        if _is_falsy_explicit(new_v):
            return (
                "medium",
                "GKE cluster Shielded Nodes was disabled. This may require review.",
            )
        if _is_truthy(new_v):
            return ("low", "GKE cluster Shielded Nodes was enabled.")
        return ("low", "GKE cluster Shielded Nodes state is now unknown or missing.")

    if fp in (
        "cluster_name", "location", "private_cluster_enabled",
        "master_authorized_networks_count", "release_channel",
    ):
        return ("low", f"GKE cluster {fp.replace('_', ' ')} changed.")

    return ("low", f"GKE cluster configuration field '{fp}' changed.")


# ── google_cloud_service_account_key_summary ─────────────────────────────────


def _classify_service_account_key_summary_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    prev_v = _get(change, "prev_value")
    new_v = _get(change, "new_value")

    if ct in ("added", "removed"):
        return ("low", "Google Cloud service account key summary record was added or removed during sync.")

    if fp == "user_managed_key_count":
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Google Cloud service account key count is now unknown or missing.")
        n_old = _int_or_none(prev_v)
        if n_new > _MANY_KEY_COUNT_THRESHOLD:
            return (
                "high",
                f"Google Cloud service account user-managed key count reached "
                f"{n_new}. This may require review.",
            )
        # n_old is only compared when it is a known value — an unknown
        # baseline (n_old is None) must never be coerced to 0, which would
        # falsely claim "increased" for a count we have no prior evidence
        # about (the exact bug class found in PagerDuty's classification-QA
        # pass, applied here proactively even though the connector always
        # populates this field with a real int today).
        if n_old is not None and n_new > n_old:
            return (
                "medium",
                f"Google Cloud service account user-managed key count "
                f"increased to {n_new}. This may require review.",
            )
        return ("low", f"Google Cloud service account user-managed key count changed to {n_new}.")

    if fp == "old_user_managed_key_count":
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Google Cloud old user-managed key count is now unknown or missing.")
        n_old = _int_or_none(prev_v)
        if n_old is not None and n_new > n_old:
            return (
                "medium",
                f"Google Cloud aged (90+ day) service account key count "
                f"increased to {n_new}. This may require review.",
            )
        return ("low", f"Google Cloud old user-managed key count changed to {n_new}.")

    if fp == "oldest_key_age_days":
        n_new = _int_or_none(new_v)
        if n_new is None:
            return ("low", "Google Cloud oldest service account key age is now unknown or missing.")
        n_old = _int_or_none(prev_v)
        if n_new >= _OLD_KEY_AGE_DAYS and (n_old is None or n_old < _OLD_KEY_AGE_DAYS):
            return (
                "medium",
                f"Google Cloud oldest service account key age reached "
                f"{n_new} days. This may require review.",
            )
        return ("low", f"Google Cloud oldest service account key age changed to {n_new} days.")

    if fp in ("service_account_count", "disabled_service_account_count"):
        return ("low", f"Google Cloud {fp.replace('_', ' ')} changed.")

    return ("low", f"Google Cloud service account key summary field '{fp}' changed.")


# ── google_cloud_secret_manager_summary ──────────────────────────────────────


def _classify_secret_manager_summary_change(change: Change) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()

    if ct in ("added", "removed"):
        return ("low", "Google Cloud Secret Manager summary record was added or removed during sync.")

    # The only backing Finding (auto-replication without CMEK) has a "low"
    # severity ceiling, so every field here is safely classified generic low.
    if fp in (
        "secret_count", "automatic_replication_count",
        "user_managed_replication_count", "customer_managed_encryption_count",
    ):
        return ("low", f"Google Cloud Secret Manager {fp.replace('_', ' ')} changed.")

    return ("low", f"Google Cloud Secret Manager summary field '{fp}' changed.")


# ── Main dispatcher ───────────────────────────────────────────────────────────


def classify_google_cloud_change(change: Change) -> tuple[str, str]:
    """Return ``(risk_level, risk_reason)`` for a Google Cloud configuration change.

    Dispatches on ``provider_metadata["record_type"]``:
      * ``google_cloud_project``                  → project metadata (no Finding)
      * ``google_cloud_iam_policy_summary``       → IAM public-member/broad-role posture
      * ``google_cloud_vpc_network``              → network metadata (no Finding)
      * ``google_cloud_firewall_rule``            → ingress/source-range/port posture
      * ``google_cloud_storage_bucket``           → bucket public-access/versioning posture
      * ``google_cloud_sql_instance``             → SQL network/SSL/backup posture
      * ``google_cloud_run_service``               → Cloud Run invoker/ingress posture
      * ``google_cloud_gke_cluster``               → GKE endpoint/RBAC/network posture
      * ``google_cloud_service_account_key_summary`` → SA key count/age posture
      * ``google_cloud_secret_manager_summary``    → Secret Manager replication posture

    Configuration evidence does not confirm compromise, unauthorized
    access, data exposure, secret exposure, or infrastructure exposure.
    Google Cloud configuration evidence may require review.
    """
    pm = _get(change, "provider_metadata") or {}
    if isinstance(pm, dict):
        record_type = (pm.get("record_type") or "").lower()
    else:
        record_type = ""

    if record_type == "google_cloud_project":
        return _classify_project_change(change)
    if record_type == "google_cloud_iam_policy_summary":
        return _classify_iam_policy_summary_change(change)
    if record_type == "google_cloud_vpc_network":
        return _classify_vpc_network_change(change)
    if record_type == "google_cloud_firewall_rule":
        return _classify_firewall_rule_change(change)
    if record_type == "google_cloud_storage_bucket":
        return _classify_storage_bucket_change(change)
    if record_type == "google_cloud_sql_instance":
        return _classify_sql_instance_change(change)
    if record_type == "google_cloud_run_service":
        return _classify_run_service_change(change)
    if record_type == "google_cloud_gke_cluster":
        return _classify_gke_cluster_change(change)
    if record_type == "google_cloud_service_account_key_summary":
        return _classify_service_account_key_summary_change(change)
    if record_type == "google_cloud_secret_manager_summary":
        return _classify_secret_manager_summary_change(change)

    # Fallback for unknown google_cloud_ subtypes
    return (
        "low",
        f"Google Cloud configuration changed (record type: {record_type or 'unknown'}). "
        "This may require review.",
    )
