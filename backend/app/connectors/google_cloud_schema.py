"""Google Cloud connector record type constants — M78A.

M78A scope (drift foundation only)
----------------------------------
Five safe drift surfaces ingested in the initial Google Cloud connector
milestone:

    google_cloud_project              — project metadata (id, number, label keys,
                                        lifecycle state, parent type only)
    google_cloud_iam_policy_summary   — project-level IAM policy aggregated by
                                        role / member-type COUNTS only; principal
                                        emails are NEVER stored
    google_cloud_vpc_network          — VPC network configuration (auto-create,
                                        routing mode, subnet/peering counts)
    google_cloud_firewall_rule        — VPC firewall rule (direction, action,
                                        priority, summarized source/destination
                                        ranges and protocol/port allowances)
    google_cloud_storage_bucket       — Cloud Storage bucket configuration
                                        posture (location, storage class,
                                        uniform IAM, public access prevention,
                                        versioning, retention, lifecycle count)

Deferred to M78C
----------------
The following Google Cloud record types are scoped to M78C (the IAM /
network / storage / runtime risk expansion milestone) and are intentionally
omitted from GOOGLE_CLOUD_RECORD_TYPES until then:

    google_cloud_sql_instance         — Cloud SQL instance posture (public IP,
                                        authorized networks, SSL mode, backup
                                        / deletion protection). Requires the
                                        Cloud SQL Admin API.
    google_cloud_run_service          — Cloud Run service posture (ingress,
                                        launch stage, invoker policy summary,
                                        public_invoker_allowed). Requires the
                                        Cloud Run Admin API.
    google_cloud_gke_cluster          — GKE cluster posture (private cluster,
                                        master-authorized-networks count, RBAC,
                                        workload identity, shielded nodes,
                                        network policy). Requires the
                                        Kubernetes Engine API.
    google_cloud_service_account_key  — Service account key age / KMS-protected
                                        status. Requires IAM Admin API.
    google_cloud_secret_manager_secret — Secret Manager secret metadata (NEVER
                                        the secret value or version payload).
                                        Requires the Secret Manager API.

Privacy contract
----------------
SECURITY: in M78A no service-account private key, OAuth token, refresh token,
authorization header, raw API response, secret value, KMS key material,
database row, log line, IAM principal email/name, user/customer data, IP
address, or PII is ever stored on a normalized record.

For IAM policy summary records specifically, we surface ONLY:
  - binding_count (int)
  - role_count (int — distinct role names observed)
  - role_names (list capped at 20; role names like 'roles/storage.admin' are
    well-known canonical strings, not principal identities)
  - broad_role_count (int — Owner / Editor / Viewer + Security Admin / IAM
    Admin etc.)
  - user_member_count (int — count of `user:...` bindings)
  - group_member_count (int — count of `group:...` bindings)
  - service_account_member_count (int — count of `serviceAccount:...` bindings)
  - domain_member_count (int — count of `domain:...` bindings)
  - allusers_binding_present (bool — `allUsers` in any binding)
  - allauthenticatedusers_binding_present (bool — `allAuthenticatedUsers`)
  - conditional_binding_count (int — bindings carrying a `condition`)

Never stored:
  - actual member identifiers (user emails, group names, service-account
    emails, principal object IDs)
  - the `etag` field (treat as opaque token)
  - condition expressions (CEL strings may carry resource IDs)
  - the raw `bindings` array
"""
from __future__ import annotations

# ── M78A record types ─────────────────────────────────────────────────────────

# One per Google Cloud project — top-level container for resources, billing,
# and IAM in GCP (the equivalent of an Azure subscription).
# SECURITY: label VALUES are user-controlled and may contain PII or secrets;
# only label KEY names are stored. Project owners / ancestry principals are
# never stored.
GOOGLE_CLOUD_PROJECT = "google_cloud_project"

# One per project — aggregated counts of project-level IAM policy bindings.
# SECURITY: principal emails / object IDs / service-account addresses are
# NEVER stored. Only role NAMES (well-known canonical strings) and bucketed
# member-type counts are kept. The raw `bindings` array, the `etag`, and CEL
# condition expressions are never surfaced.
GOOGLE_CLOUD_IAM_POLICY_SUMMARY = "google_cloud_iam_policy_summary"

# One per VPC network — top-level network configuration posture.
# SECURITY: packet flow data, log-config payloads, and route table contents
# are never accessed. Only configuration metadata (auto_create_subnetworks,
# routing_mode, subnet/peering counts) is stored.
GOOGLE_CLOUD_VPC_NETWORK = "google_cloud_vpc_network"

# One per VPC firewall rule — ingress/egress rule posture.
# SECURITY: target service-account emails are NEVER stored — only the
# count. Source/destination ranges and allowed protocol/port lists are
# summarized to capped lists; packet capture / log-config data is never
# accessed.
GOOGLE_CLOUD_FIREWALL_RULE = "google_cloud_firewall_rule"

# One per Cloud Storage bucket — bucket configuration posture.
# SECURITY: object names, object contents, signed URLs, HMAC keys, customer-
# supplied encryption keys, and ACL grantee identities are NEVER accessed.
# Only bucket-level configuration metadata is stored.
GOOGLE_CLOUD_STORAGE_BUCKET = "google_cloud_storage_bucket"

# ── Deferred until M78C ───────────────────────────────────────────────────────
# GOOGLE_CLOUD_SQL_INSTANCE = "google_cloud_sql_instance"
# GOOGLE_CLOUD_RUN_SERVICE = "google_cloud_run_service"
# GOOGLE_CLOUD_GKE_CLUSTER = "google_cloud_gke_cluster"
# GOOGLE_CLOUD_SERVICE_ACCOUNT_KEY = "google_cloud_service_account_key"
# GOOGLE_CLOUD_SECRET_MANAGER_SECRET = "google_cloud_secret_manager_secret"

# ── Aggregate set ─────────────────────────────────────────────────────────────

GOOGLE_CLOUD_RECORD_TYPES: frozenset[str] = frozenset({
    GOOGLE_CLOUD_PROJECT,
    GOOGLE_CLOUD_IAM_POLICY_SUMMARY,
    GOOGLE_CLOUD_VPC_NETWORK,
    GOOGLE_CLOUD_FIREWALL_RULE,
    GOOGLE_CLOUD_STORAGE_BUCKET,
})
