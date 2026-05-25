#!/usr/bin/env python3
"""Admin helper — override a workspace's billing plan/status without Stripe.

Use this for local smoke-testing and manual QA on production when you need to
verify billing-gated features (e.g. invite emails, member limits) without going
through a real Stripe checkout.

This script is intentionally NOT an API endpoint.  It must be run with direct
database access (i.e. the correct DATABASE_URL must be reachable).

Usage
-----
    # From /backend with the venv active:
    python scripts/set_workspace_plan.py "Whoa"
    python scripts/set_workspace_plan.py "Whoa" --plan team --status active
    python scripts/set_workspace_plan.py <workspace-uuid> --plan pro --status trialing
    python scripts/set_workspace_plan.py "Whoa" --plan free --status active   # revert
    python scripts/set_workspace_plan.py "Whoa" --dry-run                     # preview only

    # Inside Docker:
    docker compose exec api python scripts/set_workspace_plan.py "Whoa"

Arguments
---------
workspace       Workspace display name (case-insensitive) OR UUID.
--plan          Target plan: free | pro | team  (default: team)
--status        Target status: active | trialing | past_due | canceled | unpaid
                (default: active)
--dry-run       Print what would happen without writing to the database.

Notes
-----
- Free plan limits (PLAN_LIMITS["free"]) are NOT touched; this only updates the
  billing row for a specific workspace.
- No Stripe subscription is created; the billing row is updated directly.
- The change is immediately visible to the billing enforcement checks.
- To revert: run with --plan free --status active.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from typing import Optional

# ── Path setup ───────────────────────────────────────────────────────────────
# Allow running from /backend or from the project root.
import os as _os

_SCRIPT_DIR = _os.path.dirname(_os.path.abspath(__file__))
_BACKEND_DIR = _os.path.dirname(_SCRIPT_DIR)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

# ── Validation constants ──────────────────────────────────────────────────────

VALID_PLANS = {"free", "pro", "team"}
VALID_STATUSES = {"active", "trialing", "past_due", "canceled", "unpaid"}


# ── Core helpers (importable for tests) ──────────────────────────────────────


def resolve_workspace(identifier: str, db):  # type: ignore[type-arg]
    """Return a Workspace row matched by UUID or display name (case-insensitive).

    Raises LookupError when no match is found.
    Raises ValueError when more than one workspace matches the name.
    """
    from app.models.workspace import Workspace

    # Try UUID first.
    try:
        ws_id = uuid.UUID(identifier)
        workspace = db.get(Workspace, ws_id)
        if workspace is not None:
            return workspace
        raise LookupError(f"No workspace found with id={ws_id!r}")
    except (ValueError, AttributeError):
        pass  # Not a valid UUID — fall through to name lookup.

    # Name lookup (case-insensitive).
    matches = (
        db.query(Workspace)
        .filter(Workspace.name.ilike(identifier))
        .all()
    )
    if not matches:
        raise LookupError(f"No workspace found with name={identifier!r}")
    if len(matches) > 1:
        ids = ", ".join(str(m.id) for m in matches)
        raise ValueError(
            f"Ambiguous: {len(matches)} workspaces match {identifier!r}.  "
            f"Use the UUID instead: {ids}"
        )
    return matches[0]


def apply_plan_change(
    workspace_id: uuid.UUID,
    plan: str,
    status: str,
    db,  # type: ignore[type-arg]
    *,
    dry_run: bool = False,
) -> dict:
    """Update the WorkspaceBilling row and return a summary dict.

    Returns a dict with keys: workspace_id, plan_before, status_before,
    plan_after, status_after, created (bool), dry_run (bool).
    """
    if plan not in VALID_PLANS:
        raise ValueError(f"Invalid plan {plan!r}.  Must be one of: {sorted(VALID_PLANS)}")
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status {status!r}.  Must be one of: {sorted(VALID_STATUSES)}")

    from app.services.billing_service import get_or_create_billing

    billing = get_or_create_billing(workspace_id, db)
    created = billing.plan == "free" and billing.status == "active" and billing.stripe_customer_id is None

    result = {
        "workspace_id": str(workspace_id),
        "plan_before": billing.plan,
        "status_before": billing.status,
        "plan_after": plan,
        "status_after": status,
        "created": created,
        "dry_run": dry_run,
    }

    if not dry_run:
        billing.plan = plan
        billing.status = status
        db.flush()

    return result


# ── CLI entrypoint ────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="set_workspace_plan.py",
        description="Override a workspace's billing plan/status for smoke-testing.",
    )
    p.add_argument(
        "workspace",
        help="Workspace display name (case-insensitive) or UUID.",
    )
    p.add_argument(
        "--plan",
        default="team",
        choices=sorted(VALID_PLANS),
        help="Target plan (default: team).",
    )
    p.add_argument(
        "--status",
        default="active",
        choices=sorted(VALID_STATUSES),
        help="Target billing status (default: active).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would happen without writing to the database.",
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    from app.database import SessionLocal

    db = SessionLocal()
    try:
        # 1. Resolve the workspace.
        try:
            workspace = resolve_workspace(args.workspace, db)
        except LookupError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

        # 2. Apply (or preview) the plan change.
        result = apply_plan_change(
            workspace_id=workspace.id,
            plan=args.plan,
            status=args.status,
            db=db,
            dry_run=args.dry_run,
        )

        # 3. Commit (skip on dry-run).
        if not args.dry_run:
            db.commit()

        # 4. Print summary.
        tag = "[DRY RUN] " if args.dry_run else ""
        action = "would update" if args.dry_run else "updated"
        print(f"\n{tag}set_workspace_plan: {action} workspace {workspace.name!r} ({workspace.id})")
        print(f"  plan  : {result['plan_before']!r} → {result['plan_after']!r}")
        print(f"  status: {result['status_before']!r} → {result['status_after']!r}")
        if args.dry_run:
            print("\n  (no changes written — rerun without --dry-run to apply)")
        else:
            print(f"\n  ✓ Committed.  Billing enforcement now uses plan={result['plan_after']!r}.")
            print(
                f"\n  To revert:\n"
                f"    python scripts/set_workspace_plan.py {args.workspace!r} "
                f"--plan free --status active"
            )
        return 0

    except Exception as exc:
        db.rollback()
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
