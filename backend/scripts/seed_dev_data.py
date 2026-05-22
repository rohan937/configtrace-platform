#!/usr/bin/env python3
"""Dev seed script — populates realistic ConfigTrace sample data.

Usage (inside Docker):
    docker compose exec api python scripts/seed_dev_data.py

Usage (local venv from /backend):
    python scripts/seed_dev_data.py

The script is IDEMPOTENT: running it multiple times deletes and recreates the
seed data, so the database never accumulates duplicate seed rows.

What it creates
---------------
- One Cloudflare integration for the dev user (dev@configtrace.local)
- One Cloudflare DNS zone resource (example.com)
- Three snapshots showing a realistic change history
- Five Change rows across those snapshots, covering all four risk levels

It does NOT:
- Use real credentials; the encrypted_credentials field is a safe placeholder.
- Touch production behavior, sync logic, or connector code.
- Run automatically on app startup.

NEVER run this script against a production database.
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

# ── Production safety guard ───────────────────────────────────────────────────
# Check as early as possible — before any database imports — so that the guard
# fires even if the database connection would fail.
_ENVIRONMENT = os.environ.get("ENVIRONMENT", "development").lower()
if _ENVIRONMENT == "production":
    print("=" * 60)
    print("ERROR: seed_dev_data.py refused to run.")
    print()
    print("  ENVIRONMENT=production was detected.")
    print()
    print("  This script is for LOCAL DEVELOPMENT ONLY.")
    print("  It deletes and recreates data for the dev user.")
    print("  Running it against a production database would")
    print("  destroy real user data.")
    print()
    print("  If you genuinely need to run this locally while")
    print("  ENVIRONMENT is set, unset it first:")
    print("    unset ENVIRONMENT && python scripts/seed_dev_data.py")
    print("=" * 60)
    sys.exit(1)

# ── Path setup ───────────────────────────────────────────────────────────────
# Allow running from the /backend directory or from the project root.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_SCRIPT_DIR)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from sqlalchemy.orm import Session  # noqa: E402 — after sys.path fix

from app.database import SessionLocal  # noqa: E402
from app.models.change import Change  # noqa: E402
from app.models.integration import Integration  # noqa: E402
from app.models.resource import Resource  # noqa: E402
from app.models.snapshot import Snapshot  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services.snapshot_service import compute_content_hash  # noqa: E402


# ── Constants ─────────────────────────────────────────────────────────────────

# Matches auth.py's _DEV_DEFAULT_EMAIL and the clerk_id derivation logic.
_DEV_EMAIL: str = "dev@configtrace.local"
_DEV_CLERK_ID: str = "dev_dev_at_configtrace_dot_local"

# Sentinel value on the resource — used to find and wipe old seed data.
SEED_PROVIDER_RESOURCE_ID: str = "dev-zone-example-com"
SEED_INTEGRATION_DISPLAY_NAME: str = "Production Cloudflare Zone [seed]"

# Fake encrypted bytes — the model requires non-null LargeBinary.
# These are NOT valid AES-GCM ciphertext and cannot be decrypted.
# The sync task would fail if it tried to use this integration, which is
# intentional: seed data is for the read API only.
_FAKE_CREDS: bytes = b"SEED_DEV_PLACEHOLDER_NOT_REAL_AES_CIPHERTEXT_DO_NOT_USE"
_FAKE_IV: bytes = b"SEED_IV_12BYTES!"

# ── Sample DNS state ──────────────────────────────────────────────────────────
# Each list represents the full DNS zone state at a point in time.
# Records use stable record_ids so the diff service can identify changes.

SNAPSHOT_1_STATE: list[dict] = [
    {
        "record_id": "cf-rec-001",
        "record_type": "A",
        "name": "example.com",
        "content": "203.0.113.10",
        "ttl": 3600,
        "proxied": True,
        "priority": None,
        "comment": None,
        "modified_on": "2026-05-18T10:00:00Z",
    },
    {
        "record_id": "cf-rec-002",
        "record_type": "CNAME",
        "name": "checkout.example.com",
        "content": "checkout-prod.vercel.app",
        "ttl": 300,
        "proxied": True,
        "priority": None,
        "comment": None,
        "modified_on": "2026-05-18T10:00:00Z",
    },
    {
        "record_id": "cf-rec-003",
        "record_type": "MX",
        "name": "example.com",
        "content": "mail.example.com",
        "ttl": 3600,
        "proxied": False,
        "priority": 10,
        "comment": None,
        "modified_on": "2026-05-18T10:00:00Z",
    },
    {
        "record_id": "cf-rec-004",
        "record_type": "TXT",
        "name": "_dmarc.example.com",
        "content": "v=DMARC1; p=none",
        "ttl": 3600,
        "proxied": False,
        "priority": None,
        "comment": None,
        "modified_on": "2026-05-18T10:00:00Z",
    },
]

SNAPSHOT_2_STATE: list[dict] = [
    {
        "record_id": "cf-rec-001",
        "record_type": "A",
        "name": "example.com",
        "content": "203.0.113.10",
        "ttl": 60,          # changed: 3600 → 60 (high risk)
        "proxied": True,
        "priority": None,
        "comment": None,
        "modified_on": "2026-05-19T14:00:00Z",
    },
    {
        "record_id": "cf-rec-002",
        "record_type": "CNAME",
        "name": "checkout.example.com",
        "content": "checkout-staging.vercel.app",   # changed (high risk)
        "ttl": 300,
        "proxied": True,
        "priority": None,
        "comment": None,
        "modified_on": "2026-05-19T14:00:00Z",
    },
    {
        "record_id": "cf-rec-003",
        "record_type": "MX",
        "name": "example.com",
        "content": "mail.example.com",
        "ttl": 3600,
        "proxied": False,
        "priority": 10,
        "comment": None,
        "modified_on": "2026-05-18T10:00:00Z",
    },
    {
        "record_id": "cf-rec-004",
        "record_type": "TXT",
        "name": "_dmarc.example.com",
        "content": "v=DMARC1; p=none",
        "ttl": 3600,
        "proxied": False,
        "priority": None,
        "comment": "Updated DMARC policy comment",  # changed (low risk)
        "modified_on": "2026-05-19T14:00:00Z",
    },
]

SNAPSHOT_3_STATE: list[dict] = [
    # cf-rec-001 (A example.com) is ABSENT — critical removal
    {
        "record_id": "cf-rec-002",
        "record_type": "CNAME",
        "name": "checkout.example.com",
        "content": "checkout-staging.vercel.app",
        "ttl": 300,
        "proxied": True,
        "priority": None,
        "comment": None,
        "modified_on": "2026-05-19T14:00:00Z",
    },
    {
        "record_id": "cf-rec-003",
        "record_type": "MX",
        "name": "example.com",
        "content": "mail.example.com",
        "ttl": 3600,
        "proxied": False,
        "priority": 10,
        "comment": None,
        "modified_on": "2026-05-18T10:00:00Z",
    },
    {
        "record_id": "cf-rec-004",
        "record_type": "TXT",
        "name": "_dmarc.example.com",
        "content": "v=DMARC1; p=none",
        "ttl": 3600,
        "proxied": False,
        "priority": None,
        "comment": "Updated DMARC policy comment",
        "modified_on": "2026-05-19T14:00:00Z",
    },
    {
        "record_id": "cf-rec-005",   # new — medium risk (subdomain A)
        "record_type": "A",
        "name": "api.example.com",
        "content": "203.0.113.20",
        "ttl": 300,
        "proxied": True,
        "priority": None,
        "comment": None,
        "modified_on": "2026-05-20T09:00:00Z",
    },
]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _get_or_create_dev_user(db: Session) -> User:
    """Return the dev user, creating it if it does not exist.

    Uses the same clerk_id derivation as app/core/auth.py so that requests to
    the running API (which automatically resolve the dev user) see the same
    user row as the seed data.
    """
    user = db.query(User).filter(User.clerk_id == _DEV_CLERK_ID).first()
    if user is None:
        user = User(
            clerk_id=_DEV_CLERK_ID,
            email=_DEV_EMAIL,
            display_name="Dev User",
        )
        db.add(user)
        db.flush()
        db.refresh(user)
    return user


def _delete_existing_seed(user_id: uuid.UUID, db: Session) -> int:
    """Wipe all seed data for *user_id* (idempotency).

    Deletion order respects RESTRICT foreign keys:
      Change → Snapshot → Resource → Integration
    """
    total_deleted = 0

    # Find all seed resources (identified by the sentinel provider_resource_id)
    seed_resources = (
        db.query(Resource)
        .filter(
            Resource.user_id == user_id,
            Resource.provider_resource_id == SEED_PROVIDER_RESOURCE_ID,
        )
        .all()
    )

    for resource in seed_resources:
        # 1. Delete Changes first (RESTRICT → snapshots)
        n = (
            db.query(Change)
            .filter(Change.resource_id == resource.id)
            .delete(synchronize_session=False)
        )
        total_deleted += n

        # 2. Delete Snapshots (RESTRICT → resources)
        n = (
            db.query(Snapshot)
            .filter(Snapshot.resource_id == resource.id)
            .delete(synchronize_session=False)
        )
        total_deleted += n

        # 3. Delete Resource
        db.delete(resource)
        total_deleted += 1

    db.flush()

    # 4. Delete orphaned seed integrations (sentinel display_name)
    n = (
        db.query(Integration)
        .filter(
            Integration.user_id == user_id,
            Integration.display_name == SEED_INTEGRATION_DISPLAY_NAME,
        )
        .delete(synchronize_session=False)
    )
    total_deleted += n
    db.flush()

    return total_deleted


def _create_snapshot(
    resource: Resource,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    state: list[dict],
    created_at: datetime,
    db: Session,
) -> Snapshot:
    """Persist a single Snapshot row with a pre-computed content hash."""
    content_hash = compute_content_hash(state)
    snapshot = Snapshot(
        resource_id=resource.id,
        integration_id=integration_id,
        user_id=user_id,
        state=state,
        content_hash=content_hash,
        triggered_by="manual",
        sync_run_id=None,
        created_at=created_at,
    )
    db.add(snapshot)
    db.flush()
    db.refresh(snapshot)
    return snapshot


def _make_provider_metadata(record: dict, alt_record: dict | None = None) -> dict:
    """Build provider_metadata in the same shape as the diff service uses."""
    meta: dict = {
        "record_id": record.get("record_id"),
        "record_type": record.get("record_type"),
        "record_name": record.get("name"),
        "record_content": record.get("content"),
        "zone_name": "example.com",
    }
    if alt_record is not None:
        meta["new_record_content"] = alt_record.get("content")
    return meta


def _create_change(
    *,
    resource: Resource,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    prev_snapshot: Snapshot,
    new_snapshot: Snapshot,
    change_type: str,
    record_identifier: str,
    field_path: str | None,
    prev_value: object,
    new_value: object,
    risk_level: str,
    risk_reason: str,
    provider_metadata: dict,
    created_at: datetime,
    db: Session,
) -> Change:
    change = Change(
        resource_id=resource.id,
        integration_id=integration_id,
        user_id=user_id,
        prev_snapshot_id=prev_snapshot.id,
        new_snapshot_id=new_snapshot.id,
        change_type=change_type,
        record_identifier=record_identifier,
        field_path=field_path,
        prev_value=prev_value,
        new_value=new_value,
        risk_level=risk_level,
        risk_reason=risk_reason,
        provider_metadata=provider_metadata,
        created_at=created_at,
    )
    db.add(change)
    return change


# ── Public API ────────────────────────────────────────────────────────────────

def seed_for_user(user_id: uuid.UUID, db: Session) -> dict:
    """Seed realistic dev data for *user_id*.

    This is the core seeding function used both by the CLI entry point and by
    the test suite.  It is idempotent: calling it multiple times for the same
    user_id always leaves exactly the data described in this module.

    Args:
        user_id: UUID of the user who should own all created rows.
        db:      Active SQLAlchemy session.  The caller is responsible for
                 committing (or rolling back) after this returns.

    Returns:
        Summary dict with keys: user_id, integration_id, resource_id,
        snapshot_count, change_count.
    """
    now = _now()

    # Timestamps spread across the last 3 days for a realistic-looking timeline
    t1 = now - timedelta(days=3)   # Snapshot 1 — baseline
    t2 = now - timedelta(days=2)   # Snapshot 2 — TTL + CNAME change
    t3 = now - timedelta(days=1)   # Snapshot 3 — apex A removed, api.* added

    # ── 1. Clear old seed data (idempotency) ─────────────────────────────────
    _delete_existing_seed(user_id, db)

    # ── 2. Integration ───────────────────────────────────────────────────────
    integration = Integration(
        user_id=user_id,
        provider="cloudflare",
        display_name=SEED_INTEGRATION_DISPLAY_NAME,
        encrypted_credentials=_FAKE_CREDS,
        credential_iv=_FAKE_IV,
        status="active",
        last_synced_at=t3,
    )
    db.add(integration)
    db.flush()
    db.refresh(integration)

    # ── 3. Resource ──────────────────────────────────────────────────────────
    resource = Resource(
        integration_id=integration.id,
        user_id=user_id,
        provider_resource_type="cloudflare_dns_zone",
        provider_resource_id=SEED_PROVIDER_RESOURCE_ID,
        display_name="example.com",
        resource_metadata={
            "zone_name": "example.com",
            "provider": "cloudflare",
            "environment": "production",
        },
        last_snapshot_at=t3,
        is_active=True,
    )
    db.add(resource)
    db.flush()
    db.refresh(resource)

    # ── 4. Snapshots ─────────────────────────────────────────────────────────
    s1 = _create_snapshot(resource, integration.id, user_id, SNAPSHOT_1_STATE, t1, db)
    s2 = _create_snapshot(resource, integration.id, user_id, SNAPSHOT_2_STATE, t2, db)
    s3 = _create_snapshot(resource, integration.id, user_id, SNAPSHOT_3_STATE, t3, db)

    # ── 5. Changes (snapshot 1 → 2) ──────────────────────────────────────────

    # 5a. TTL reduced on apex A record — high risk
    rec1_v1 = next(r for r in SNAPSHOT_1_STATE if r["record_id"] == "cf-rec-001")
    rec1_v2 = next(r for r in SNAPSHOT_2_STATE if r["record_id"] == "cf-rec-001")
    _create_change(
        resource=resource,
        integration_id=integration.id,
        user_id=user_id,
        prev_snapshot=s1,
        new_snapshot=s2,
        change_type="modified",
        record_identifier="A example.com",
        field_path="ttl",
        prev_value=3600,
        new_value=60,
        risk_level="high",
        risk_reason=(
            "TTL reduced to 60 seconds. Very short TTLs shrink the rollback "
            "window if a bad change needs to be reverted."
        ),
        provider_metadata=_make_provider_metadata(rec1_v1, rec1_v2),
        created_at=t2,
        db=db,
    )

    # 5b. CNAME target changed — high risk
    rec2_v1 = next(r for r in SNAPSHOT_1_STATE if r["record_id"] == "cf-rec-002")
    rec2_v2 = next(r for r in SNAPSHOT_2_STATE if r["record_id"] == "cf-rec-002")
    _create_change(
        resource=resource,
        integration_id=integration.id,
        user_id=user_id,
        prev_snapshot=s1,
        new_snapshot=s2,
        change_type="modified",
        record_identifier="CNAME checkout.example.com",
        field_path="content",
        prev_value="checkout-prod.vercel.app",
        new_value="checkout-staging.vercel.app",
        risk_level="high",
        risk_reason=(
            "CNAME target changed. This may route production traffic to a "
            "different service."
        ),
        provider_metadata=_make_provider_metadata(rec2_v1, rec2_v2),
        created_at=t2,
        db=db,
    )

    # 5c. TXT comment changed — low risk
    rec4_v1 = next(r for r in SNAPSHOT_1_STATE if r["record_id"] == "cf-rec-004")
    rec4_v2 = next(r for r in SNAPSHOT_2_STATE if r["record_id"] == "cf-rec-004")
    _create_change(
        resource=resource,
        integration_id=integration.id,
        user_id=user_id,
        prev_snapshot=s1,
        new_snapshot=s2,
        change_type="modified",
        record_identifier="TXT _dmarc.example.com",
        field_path="comment",
        prev_value=None,
        new_value="Updated DMARC policy comment",
        risk_level="low",
        risk_reason=(
            "Comment-only change does not affect DNS resolution."
        ),
        provider_metadata=_make_provider_metadata(rec4_v1, rec4_v2),
        created_at=t2,
        db=db,
    )

    # ── 6. Changes (snapshot 2 → 3) ──────────────────────────────────────────

    # 6a. Apex A record removed — critical
    rec1_v2_full = next(r for r in SNAPSHOT_2_STATE if r["record_id"] == "cf-rec-001")
    _create_change(
        resource=resource,
        integration_id=integration.id,
        user_id=user_id,
        prev_snapshot=s2,
        new_snapshot=s3,
        change_type="removed",
        record_identifier="A example.com",
        field_path=None,
        prev_value=rec1_v2_full,
        new_value=None,
        risk_level="critical",
        risk_reason=(
            "Deletion of an apex A record disrupts DNS resolution for the root "
            "domain and can take all services offline."
        ),
        provider_metadata=_make_provider_metadata(rec1_v2_full),
        created_at=t3,
        db=db,
    )

    # 6b. Subdomain A record added — medium risk
    rec5 = next(r for r in SNAPSHOT_3_STATE if r["record_id"] == "cf-rec-005")
    _create_change(
        resource=resource,
        integration_id=integration.id,
        user_id=user_id,
        prev_snapshot=s2,
        new_snapshot=s3,
        change_type="added",
        record_identifier="A api.example.com",
        field_path=None,
        prev_value=None,
        new_value=rec5,
        risk_level="medium",
        risk_reason=(
            "Addition of a new subdomain A record creates a new DNS entry "
            "point that was not previously configured."
        ),
        provider_metadata=_make_provider_metadata(rec5),
        created_at=t3,
        db=db,
    )

    db.flush()

    return {
        "user_id": str(user_id),
        "integration_id": str(integration.id),
        "resource_id": str(resource.id),
        "snapshot_count": 3,
        "change_count": 5,
    }


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    """Connect to the database, seed dev data, and print a summary."""
    print("ConfigTrace dev seed script")
    print("=" * 48)

    db: Session = SessionLocal()
    try:
        # Resolve (or create) the dev user
        user = _get_or_create_dev_user(db)
        db.commit()
        db.refresh(user)
        print(f"Dev user : {user.email}  (id={user.id})")

        # Seed data
        print("Seeding  : deleting old seed data and recreating…")
        summary = seed_for_user(user.id, db)
        db.commit()

    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    print()
    print("Done.")
    print(f"  Created integration : {summary['integration_id']}")
    print(f"  Created resource    : {summary['resource_id']}")
    print(f"  Created snapshots   : {summary['snapshot_count']}")
    print(f"  Created changes     : {summary['change_count']}")
    print()
    print("Verify with:")
    print("  curl http://localhost:8000/changes | python3 -m json.tool")
    print("  curl http://localhost:8000/resources | python3 -m json.tool")


if __name__ == "__main__":
    main()
