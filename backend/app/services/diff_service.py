"""Diff service — Milestone 9.

Responsibilities
----------------
* ``build_record_index``     — stable key → full record dict from snapshot.state
* ``format_record_identifier`` — human-readable label, e.g. "A api.example.com"
* ``compute_diff``           — pure function: two Snapshots → list[change_dict]
* ``store_changes``          — persist change_dicts as Change rows in the DB

Design decisions
----------------
* ``compute_diff`` is **pure** — it reads Snapshot.state but never touches the
  database.  This makes every diff scenario testable without DB fixtures.

* ``store_changes`` is the DB writer.  Keeping it separate from ``compute_diff``
  means the diff logic can be validated independently of persistence concerns.

* Only the seven fields in ``_TRACKED_FIELDS`` are compared for modified
  records.  Volatile provider timestamps (``modified_on``, ``created_on``,
  etc.) are explicitly excluded to prevent false positives on every sync.

* One Change row is written per changed *field* for "modified" records.  A
  record with three changed fields produces three rows.  This granularity lets
  Milestone 10 apply different risk levels to TTL changes vs content changes on
  the same record.

* ``risk_level`` is set to ``"unknown"`` on all rows written here.  Milestone 10
  (risk service) will update these to low/medium/high/critical.

* ``provider_metadata`` is populated with enough record context (type, name,
  content, stable ID) for Milestone 10 risk rules and the Milestone 11/15 UI
  to classify and display changes without reloading snapshot state.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.change import Change
from app.models.snapshot import Snapshot

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Fields compared field-by-field for Cloudflare DNS records.
# Ordered deterministically so multi-field modifications are always in the same
# sequence, which matters for the UI and for risk rule matching.
_TRACKED_FIELDS: tuple[str, ...] = (
    "record_type",   # maps from Cloudflare's "type" via connector normalisation
    "name",
    "content",
    "ttl",
    "proxied",
    "priority",
    "comment",
)

# Fields that must NEVER trigger a change even if they differ between snapshots.
# These are provider-managed timestamps that change on every API response
# regardless of whether the configuration actually changed.
_IGNORED_FIELDS: frozenset[str] = frozenset({
    "modified_on",
    "created_on",
    "created_at",
    "updated_at",
})

# ── GitHub-specific tracked fields ──────────────────────────────────────────

#: Set of GitHub record type strings — used for O(1) membership checks.
_GITHUB_RECORD_TYPES: frozenset[str] = frozenset({
    "github_repo_settings",
    "github_branch_protection",
    "github_actions_secret",
    "github_actions_variable",
    "github_webhook",
    "github_actions_permissions",
    "github_deploy_key",
})

# ── Vercel-specific tracked fields ───────────────────────────────────────────

#: Per-record-type tracked field tuples for Vercel records.
#: Only the fields listed here are compared field-by-field in compute_diff.
#: Provider-managed timestamps (``created_at``) are intentionally excluded
#: except for ``updated_at`` on env vars (a change signals secret rotation).
_VERCEL_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "vercel_project": (
        # Identity
        "name",               # project rename
        # Build pipeline (supply-chain / deployment critical)
        "build_command",      # custom build command
        "install_command",    # custom install command
        "root_directory",     # monorepo source root (build-breaking if wrong)
        "output_directory",   # where the build writes output
        # Runtime
        "framework",          # framework preset (changes routing + build strategy)
        "node_version",       # Node.js runtime version
        # Git connection
        "git_repository",     # connected repository (owner/repo)
        "git_branch",         # production branch (e.g. "main")
        # Deployment protection
        "sso_protection",     # None = disabled; "all" = SSO-gated
        "password_protection", # None = disabled; "all" = password-gated
    ),
    "vercel_env_var": (
        # key/name change is unusual but meaningful (env var renamed)
        "key",
        # type change (encrypted → plain is a security downgrade)
        "env_type",
        # target change (promoted to / demoted from production)
        "target",
        # git_branch scope change
        "git_branch",
        # updated_at change signals a value rotation — tracked intentionally
        # SECURITY: only the timestamp is stored, never the new value
        "updated_at",
        # NOTE: "value" is intentionally NOT listed here (M33 security constraint)
    ),
    "vercel_domain": (
        "verified",    # domain verification status
        "redirect",    # redirect target (None = no redirect)
        "git_branch",  # branch-specific domain scope
    ),
}

#: Per-record-type tracked field tuples for GitHub records.
#: Only the fields listed here are compared field-by-field in compute_diff.
#: Provider-managed timestamps (e.g. ``created_at``) are intentionally excluded.
_GITHUB_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "github_repo_settings": (
        "visibility",
        "default_branch",
        "has_issues",
        "has_projects",
        "has_wiki",
        "allow_merge_commit",
        "allow_squash_merge",
        "allow_rebase_merge",
        "delete_branch_on_merge",
        "archived",
    ),
    "github_branch_protection": (
        "protection_enabled",
        "required_status_checks_enabled",
        "required_pull_request_reviews_enabled",
        "required_approving_review_count",
        "dismiss_stale_reviews",
        "enforce_admins",
        "required_linear_history",
        "allow_force_pushes",
        "allow_deletions",
    ),
    "github_actions_secret": (
        # Only metadata — secret values are never fetched.
        # last_updated_at changing signals a credential rotation.
        "last_updated_at",
    ),
    "github_actions_variable": (
        "value",
    ),
    "github_webhook": (
        "url",
        "active",
        "events",
        "content_type",
    ),
    "github_actions_permissions": (
        "enabled",
        "allowed_actions",
    ),
    "github_deploy_key": (
        "title",
        "read_only",
        "verified",
    ),
}



# ── Stripe-specific tracked fields ────────────────────────────────────────────

#: Per-record-type tracked field tuples for Stripe records.
#: Only the fields listed here are compared field-by-field in compute_diff.
#: Volatile metadata (file IDs that change on branding uploads, etc.) is
#: included only where changes are meaningful.
_STRIPE_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "stripe_account_settings": (
        # Operational flags — highest priority
        "charges_enabled",
        "payouts_enabled",
        # Payout schedule
        "payout_schedule_interval",
        "payout_schedule_delay_days",
        # Capabilities / payment methods
        "enabled_payment_methods",
        # Currency
        "default_currency",
        # Business profile
        "business_name",
        "support_email",
        "support_url",
        "business_url",
        # Branding
        "branding_icon",
        "branding_logo",
        "branding_primary_color",
        # Dashboard
        "display_name",
        # Platform
        "controller_type",
    ),
    "stripe_webhook_endpoint": (
        "url",
        "status",
        "enabled_events",
        "api_version",
        "description",
        # SECURITY: signing secret is intentionally NOT listed here
    ),
    "stripe_payment_method_configuration": (
        "config_name",
        "is_default",
        "enabled_payment_methods",
    ),
    "stripe_payment_method_domain": (
        "enabled",
        "apple_pay_enabled",
        "google_pay_enabled",
        "link_enabled",
        "domain_name",
    ),
}


# ── AWS-specific tracked fields ───────────────────────────────────────────────

_AWS_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "aws_account_identity": (
        "account_id",
        "principal_arn",
        "principal_type",
        "partition",
        "default_region",
        "selected_regions",
    ),
    "aws_region": (
        "opt_in_status",
        "enabled",
        "source",
    ),
    "aws_service_inventory": (
        "selected_regions",
        "enabled_surfaces",
        "s3_bucket_count",
        # NOTE: future_surfaces is intentionally NOT tracked — adding future
        # surfaces to the placeholder list should not generate change events.
    ),
    # ── M37: S3 bucket configuration ─────────────────────────────────────────
    # One record per S3 bucket. All security-relevant fields are tracked so
    # that exposure changes generate change events at the correct risk level.
    # creation_date is intentionally excluded (immutable).
    # Raw policy text is never stored; policy_hash tracks policy text changes.
    "aws_s3_bucket": (
        # Location
        "bucket_region",
        # Block Public Access
        "block_public_acls",
        "ignore_public_acls",
        "block_public_policy",
        "restrict_public_buckets",
        "public_access_block_configured",
        # Policy
        "policy_present",
        "policy_status_is_public",
        "policy_hash",            # hash of raw policy — tracks text changes
        "public_principals_detected",
        # ACL
        "acl_all_users_read",
        "acl_all_users_write",
        "acl_authenticated_users_read",
        "acl_authenticated_users_write",
        # Encryption
        "encryption_enabled",
        "encryption_algorithm",
        "bucket_key_enabled",
        # Versioning
        "versioning_status",
        "mfa_delete_status",
        # Logging
        "logging_enabled",
        "logging_target_bucket",
        # Lifecycle
        "lifecycle_rule_count",
        # Tags
        "tag_keys",
        # Fetch-time warnings (missing optional permissions)
        "config_fetch_warnings",
    ),
}


def _tracked_fields_for(record: dict) -> tuple[str, ...]:
    """Return the tuple of field names to compare for *record*.

    Dispatches on ``record["record_type"]``:
    * Record types starting with ``"github_"`` look up in
      ``_GITHUB_TRACKED_FIELDS_BY_TYPE`` — unknown sub-types return ``()``
      (empty) so they never generate spurious modifications.
    * Record types starting with ``"vercel_"`` look up in
      ``_VERCEL_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"stripe_"`` look up in
      ``_STRIPE_TRACKED_FIELDS_BY_TYPE``.
    * All other records (Cloudflare DNS) use ``_TRACKED_FIELDS``.

    Args:
        record: A single record dict from a snapshot state list.

    Returns:
        Tuple of field name strings to compare field-by-field.
    """
    rt = record.get("record_type", "")
    if isinstance(rt, str) and rt.startswith("github_"):
        return _GITHUB_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("vercel_"):
        return _VERCEL_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("stripe_"):
        return _STRIPE_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("aws_"):
        return _AWS_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    return _TRACKED_FIELDS


# ─────────────────────────────────────────────────────────────────────────────
# Index builder
# ─────────────────────────────────────────────────────────────────────────────

def build_record_index(state: list[dict]) -> dict[str, dict]:
    """Return a mapping from stable record identifier → full record dict.

    Identifier priority (first non-empty value wins):
    1. ``external_id``  — used by future providers that expose their own ID
    2. ``id``           — generic fallback
    3. ``record_id``    — used by the Cloudflare connector (canonical field)

    Args:
        state: Normalised record list stored in ``Snapshot.state``.

    Returns:
        Dict keyed by the stable identifier string.

    Raises:
        ValueError: if any record has none of the recognised identifier fields.
    """
    index: dict[str, dict] = {}
    for record in state:
        key = (
            record.get("external_id")
            or record.get("id")
            or record.get("record_id")
        )
        if not key:
            raise ValueError(
                "Record has no stable identifier "
                "(expected 'external_id', 'id', or 'record_id'): "
                f"{record!r}"
            )
        index[str(key)] = record
    return index


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def format_record_identifier(record: dict) -> str:
    """Return a short human-readable label for *record*.

    Examples::

        "A api.example.com"
        "MX example.com"
        "CNAME checkout.example.com"
        "TXT _dmarc.example.com"

    Uses ``record_type`` (Cloudflare normalised field) or ``type`` (raw API
    field) as the type prefix.  Falls back gracefully if neither is present.
    """
    record_type = record.get("record_type") or record.get("type") or "UNKNOWN"
    name = record.get("name") or ""
    label = f"{record_type} {name}".strip()
    return label or "unknown record"


def _stable_id(record: dict) -> Optional[str]:
    """Extract the stable identifier from *record*, or ``None``."""
    key = (
        record.get("external_id")
        or record.get("id")
        or record.get("record_id")
    )
    return str(key) if key else None


def _build_provider_metadata(
    record: dict,
    alt_record: Optional[dict] = None,
) -> dict[str, Any]:
    """Build the ``provider_metadata`` payload stored on each Change row.

    Contains enough context for Milestone 10 risk rules and Milestone 11/15
    UI to classify and display changes without re-loading snapshot state.

    Args:
        record:     Primary record (prev for removed/modified; new for added).
        alt_record: Counterpart record, used for modified changes to include
                    the new record's content alongside the old one.
    """
    metadata: dict[str, Any] = {
        "record_id": _stable_id(record),
        "record_type": record.get("record_type") or record.get("type"),
        "record_name": record.get("name"),
        "record_content": record.get("content"),
    }
    if alt_record is not None:
        metadata["new_record_content"] = alt_record.get("content")
    return metadata


# ─────────────────────────────────────────────────────────────────────────────
# Diff computation — pure, no DB
# ─────────────────────────────────────────────────────────────────────────────

def compute_diff(
    prev_snapshot: Snapshot,
    new_snapshot: Snapshot,
) -> list[dict]:
    """Compare two snapshots and return a list of change dicts.

    This is a **pure function**: it reads ``Snapshot.state`` but never touches
    the database.  Pass the output to :func:`store_changes` to persist.

    Algorithm
    ---------
    1. Build keyed indexes for both snapshot states via :func:`build_record_index`.
    2. Added records  — keys present in ``new_index`` but not ``prev_index``.
    3. Removed records — keys present in ``prev_index`` but not ``new_index``.
    4. Modified records — keys in both indexes where any tracked field differs.
       One change dict is emitted **per changed field** (not per record).

    Volatile provider timestamps (``modified_on``, ``created_on``, etc.) are
    always excluded from comparison.  Only the fields in ``_TRACKED_FIELDS``
    are compared.

    Change dict keys
    ----------------
    ``change_type``       : ``"added"``, ``"removed"``, or ``"modified"``
    ``record_identifier`` : human-readable label, e.g. ``"A api.example.com"``
    ``field_path``        : field name for ``"modified"``; ``None`` otherwise
    ``prev_value``        : old value; ``None`` for ``"added"``
    ``new_value``         : new value; ``None`` for ``"removed"``
    ``provider_metadata`` : dict with record context for risk rules and UI

    Args:
        prev_snapshot: The earlier ``Snapshot`` (previous state).
        new_snapshot:  The later ``Snapshot`` (current state).

    Returns:
        List of change dicts.  Empty list when snapshots are identical.
    """
    prev_index = build_record_index(prev_snapshot.state or [])
    new_index = build_record_index(new_snapshot.state or [])

    changes: list[dict] = []

    # ── Added records ────────────────────────────────────────────────────────
    for key, new_record in new_index.items():
        if key not in prev_index:
            changes.append({
                "change_type": "added",
                "record_identifier": format_record_identifier(new_record),
                "field_path": None,
                "prev_value": None,
                "new_value": new_record,
                "provider_metadata": _build_provider_metadata(new_record),
            })
            logger.debug(
                "diff: added  id=%s  label=%r",
                key,
                format_record_identifier(new_record),
            )

    # ── Removed records ──────────────────────────────────────────────────────
    for key, prev_record in prev_index.items():
        if key not in new_index:
            changes.append({
                "change_type": "removed",
                "record_identifier": format_record_identifier(prev_record),
                "field_path": None,
                "prev_value": prev_record,
                "new_value": None,
                "provider_metadata": _build_provider_metadata(prev_record),
            })
            logger.debug(
                "diff: removed  id=%s  label=%r",
                key,
                format_record_identifier(prev_record),
            )

    # ── Modified records (field-level) ───────────────────────────────────────
    for key in sorted(prev_index.keys() & new_index.keys()):
        prev_record = prev_index[key]
        new_record = new_index[key]
        identifier = format_record_identifier(prev_record)

        for field in _tracked_fields_for(prev_record):
            prev_val = prev_record.get(field)
            new_val = new_record.get(field)
            if prev_val != new_val:
                changes.append({
                    "change_type": "modified",
                    "record_identifier": identifier,
                    "field_path": field,
                    "prev_value": prev_val,
                    "new_value": new_val,
                    "provider_metadata": _build_provider_metadata(
                        prev_record, new_record
                    ),
                })
                logger.debug(
                    "diff: modified  id=%s  field=%s  prev=%r  new=%r",
                    key,
                    field,
                    prev_val,
                    new_val,
                )

    logger.info(
        "compute_diff: %d change(s)  prev_snapshot=%s  new_snapshot=%s",
        len(changes),
        getattr(prev_snapshot, "id", "?"),
        getattr(new_snapshot, "id", "?"),
    )
    return changes


# ─────────────────────────────────────────────────────────────────────────────
# Persist changes — writes to DB
# ─────────────────────────────────────────────────────────────────────────────

def store_changes(
    *,
    resource_id: uuid.UUID,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    prev_snapshot_id: uuid.UUID,
    new_snapshot_id: uuid.UUID,
    change_dicts: list[dict],
    db: Session,
) -> list[Change]:
    """Persist a list of change dicts as ``Change`` rows in the database.

    Each dict in *change_dicts* must contain the keys produced by
    :func:`compute_diff`.

    Transactional pattern:
        Calls ``db.flush()`` after adding all rows — consistent with
        ``store_snapshot``.  The caller (``sync_integration`` task) is
        responsible for ``db.commit()`` once all per-resource work is done.

    Risk classification:
        All rows are written with ``risk_level = "unknown"`` and
        ``risk_reason = None``.  Milestone 10's risk service will update
        these values.

    Args:
        resource_id:      UUID of the monitored resource.
        integration_id:   UUID of the parent integration (denormalised FK).
        user_id:          UUID of the owning user (denormalised FK).
        prev_snapshot_id: UUID of the earlier Snapshot.
        new_snapshot_id:  UUID of the newer Snapshot.
        change_dicts:     Output of :func:`compute_diff`.
        db:               Active SQLAlchemy session.

    Returns:
        List of persisted ``Change`` objects with populated ``id`` fields.
        Empty list when *change_dicts* is empty.
    """
    if not change_dicts:
        return []

    created: list[Change] = []
    for cd in change_dicts:
        change = Change(
            resource_id=resource_id,
            integration_id=integration_id,
            user_id=user_id,
            prev_snapshot_id=prev_snapshot_id,
            new_snapshot_id=new_snapshot_id,
            change_type=cd["change_type"],
            record_identifier=cd["record_identifier"],
            field_path=cd.get("field_path"),
            prev_value=cd.get("prev_value"),
            new_value=cd.get("new_value"),
            provider_metadata=cd.get("provider_metadata"),
            risk_level="unknown",      # Milestone 10 updates to real levels
            risk_reason=None,
        )
        db.add(change)
        created.append(change)

    db.flush()
    for change in created:
        db.refresh(change)

    logger.info(
        "store_changes: %d row(s) written  resource_id=%s",
        len(created),
        resource_id,
    )
    return created
