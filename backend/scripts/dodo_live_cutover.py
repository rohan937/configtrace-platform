#!/usr/bin/env python3
"""Dodo Payments live-cutover operational commands (Dodo Payments live-
cutover preparation — see docs/deployment/dodo-live-cutover.md).

Every subcommand here is READ-ONLY unless explicitly documented otherwise.
None of these commands can switch ``BILLING_PROVIDER`` — that remains a
manual Render dashboard edit, by design (see the rollback section of
docs/deployment/dodo-live-cutover.md). None of these commands can flip the
``DODO_PILOT_WORKSPACE_ID`` Render variable either — Render environment
variables are not reachable from this script; ``pilot-override`` only
prints the exact value to set/unset by hand.

Safety rules enforced throughout this file:
  * Never print a secret value (DODO_API_KEY, DODO_WEBHOOK_SECRET,
    STRIPE_*, PADDLE_*, etc.) — only whether a variable IS SET.
  * Read-only by default — the only network call anywhere in this file is
    a GET (catalog-verify's read-only product lookup). No POST/PATCH ever.
  * ``catalog-verify`` (the one subcommand that calls the real Dodo API)
    refuses to run against a Live-mode configuration unless the operator
    passes ``--live`` explicitly — an accidental default invocation can
    never touch the Live catalog.
  * There is no Live-*mutating* command in this file (nothing here calls a
    POST/PATCH Dodo endpoint or writes BILLING_PROVIDER/DODO_PILOT_WORKSPACE_ID
    anywhere) — by design, this script cannot perform the cutover itself,
    only verify preconditions and report state. ``pilot-override`` still
    requires ``--yes`` and always prints its target before that gate, in
    the same spirit, since it hands the operator a value to apply by hand.
  * No script may switch the global provider automatically.

Usage
-----
    # From /backend with the venv active and DATABASE_URL reachable:
    python scripts/dodo_live_cutover.py readiness
    python scripts/dodo_live_cutover.py env-check
    python scripts/dodo_live_cutover.py catalog-verify            # refuses if configured env is live
    python scripts/dodo_live_cutover.py catalog-verify --live     # explicit Live catalog check (stage F)
    python scripts/dodo_live_cutover.py webhook-events --limit 20
    python scripts/dodo_live_cutover.py subscription-counts
    python scripts/dodo_live_cutover.py pilot-override status
    python scripts/dodo_live_cutover.py pilot-override print "Acme Inc" --yes
    python scripts/dodo_live_cutover.py pilot-override clear --yes
    python scripts/dodo_live_cutover.py subscription "Acme Inc"
    python scripts/dodo_live_cutover.py duplicate-subscriptions
    python scripts/dodo_live_cutover.py stuck-webhooks --older-than-minutes 60
    python scripts/dodo_live_cutover.py unresolved-events
    python scripts/dodo_live_cutover.py health-check
"""

from __future__ import annotations

import argparse
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

# ── Path setup — allow running from /backend or from the project root ──────
import os as _os

_SCRIPT_DIR = _os.path.dirname(_os.path.abspath(__file__))
_BACKEND_DIR = _os.path.dirname(_SCRIPT_DIR)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

# Secret field names that must NEVER have their value printed by this
# script — presence (bool) only, everywhere.
_SECRET_SETTINGS = (
    "DODO_API_KEY",
    "DODO_WEBHOOK_SECRET",
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "PADDLE_API_KEY",
    "PADDLE_WEBHOOK_SECRET",
)

# Non-secret settings whose exact value IS useful and safe to print.
_NON_SECRET_SETTINGS = (
    "BILLING_PROVIDER",
    "DODO_ENVIRONMENT",
    "DODO_PRO_PRODUCT_ID",
    "DODO_TEAM_PRODUCT_ID",
    "DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID",
    "DODO_PILOT_WORKSPACE_ID",
    "BILLING_GRACE_PERIOD_DAYS",
)


# ── Core, importable helpers (no CLI/print side effects) ────────────────────


def resolve_workspace(identifier: str, db):  # type: ignore[type-arg]
    """Return a Workspace row matched by UUID or display name
    (case-insensitive). Raises LookupError / ValueError. Mirrors
    ``set_workspace_plan.resolve_workspace``."""
    from app.models.workspace import Workspace

    try:
        ws_id = uuid.UUID(identifier)
        workspace = db.get(Workspace, ws_id)
        if workspace is not None:
            return workspace
        raise LookupError(f"No workspace found with id={ws_id!r}")
    except (ValueError, AttributeError):
        pass

    matches = db.query(Workspace).filter(Workspace.name.ilike(identifier)).all()
    if not matches:
        raise LookupError(f"No workspace found with name={identifier!r}")
    if len(matches) > 1:
        ids = ", ".join(str(m.id) for m in matches)
        raise ValueError(
            f"Ambiguous: {len(matches)} workspaces match {identifier!r}. Use the UUID instead: {ids}"
        )
    return matches[0]


def build_env_check_report(settings) -> dict:  # type: ignore[no-untyped-def]
    """Masked environment-variable presence report. Never returns a
    secret's value — only booleans for secret fields, real values for
    documented non-secret fields."""
    secrets_present = {name: bool(getattr(settings, name, None)) for name in _SECRET_SETTINGS}
    non_secrets = {name: getattr(settings, name, None) for name in _NON_SECRET_SETTINGS}
    return {
        "secrets_present": secrets_present,
        "non_secrets": non_secrets,
        "dodo_environment_normalized": settings.dodo_environment_normalized,
        "is_dodo_configured": settings.is_dodo_configured,
    }


def build_subscription_counts(db) -> dict:  # type: ignore[type-arg]
    """Count NormalizedSubscription rows grouped by (provider, status).
    Read-only."""
    from app.billing.models import NormalizedSubscription

    rows = db.query(NormalizedSubscription.provider, NormalizedSubscription.status).all()
    counts: dict[str, dict[str, int]] = {}
    for provider, status in rows:
        counts.setdefault(provider, {}).setdefault(status, 0)
        counts[provider][status] += 1
    return counts


def find_duplicate_subscriptions(db) -> list[dict]:
    """Integrity check, NOT a catalog check: flags any provider-side
    reference (subscription or customer) that appears on more than one
    ``NormalizedSubscription`` row. Each workspace has at most one row
    (``workspace_id`` is unique), so any repeated provider reference here
    indicates two different workspaces sharing one provider object — a
    data-integrity condition, not an expected outcome under any provider's
    documented behavior."""
    from app.billing.models import NormalizedSubscription

    rows = db.query(NormalizedSubscription).all()
    by_sub_ref: dict[str, list] = {}
    by_cust_ref: dict[str, list] = {}
    for row in rows:
        if row.provider_subscription_reference:
            by_sub_ref.setdefault(row.provider_subscription_reference, []).append(row)
        if row.provider_customer_reference:
            by_cust_ref.setdefault(row.provider_customer_reference, []).append(row)

    findings = []
    for ref, matched in by_sub_ref.items():
        if len(matched) > 1:
            findings.append(
                {
                    "kind": "duplicate_subscription_reference",
                    "reference": ref,
                    "workspace_ids": [str(r.workspace_id) for r in matched],
                    "provider": matched[0].provider,
                }
            )
    for ref, matched in by_cust_ref.items():
        if len(matched) > 1:
            findings.append(
                {
                    "kind": "duplicate_customer_reference",
                    "reference": ref,
                    "workspace_ids": [str(r.workspace_id) for r in matched],
                    "provider": matched[0].provider,
                }
            )
    return findings


def find_stuck_webhooks(db, *, older_than_minutes: int = 60) -> list[dict]:
    """Webhook rows still 'pending' or 'failed' older than the threshold —
    a signal that reconciliation or manual investigation is needed. Never
    returns the raw payload — only the small, already-normalized summary
    fields already considered safe to store on the row itself."""
    from app.billing.models import BillingWebhookEvent

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=older_than_minutes)
    rows = (
        db.query(BillingWebhookEvent)
        .filter(BillingWebhookEvent.processing_status.in_(["pending", "failed"]))
        .filter(BillingWebhookEvent.received_at < cutoff)
        .order_by(BillingWebhookEvent.received_at.asc())
        .all()
    )
    return [
        {
            "id": str(row.id),
            "provider": row.provider,
            "external_event_id": row.external_event_id,
            "event_type": row.event_type,
            "processing_status": row.processing_status,
            "error_category": row.error_category,
            "attempt_count": row.attempt_count,
            "received_at": row.received_at.isoformat() if row.received_at else None,
        }
        for row in rows
    ]


def find_unresolved_workspace_events(db, *, provider: str = "dodo", limit: int = 50) -> list[dict]:
    """Webhook events that verified and parsed correctly but could NOT be
    associated with any ConfigTrace workspace — ``processing_status ==
    "failed"`` with ``error_category == "unknown_reference"`` (see
    ``app.billing.dodo_webhook_service.process_dodo_webhook`` /
    ``_apply_normalized_event``). This is a distinct, previously-invisible
    category: before this diagnostic existed, an event like this could
    only be found by noticing a subscription that should exist but
    doesn't — this surfaces it directly. Read-only."""
    from app.billing.models import BillingWebhookEvent

    rows = (
        db.query(BillingWebhookEvent)
        .filter(BillingWebhookEvent.provider == provider)
        .filter(BillingWebhookEvent.processing_status == "failed")
        .filter(BillingWebhookEvent.error_category == "unknown_reference")
        .order_by(BillingWebhookEvent.received_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": str(row.id),
            "external_event_id": row.external_event_id,
            "event_type": row.event_type,
            "customer_reference": row.customer_reference,
            "subscription_reference": row.subscription_reference,
            "received_at": row.received_at.isoformat() if row.received_at else None,
        }
        for row in rows
    ]


def list_webhook_events(db, *, provider: Optional[str] = None, status: Optional[str] = None, limit: int = 20) -> list[dict]:
    """Most recent webhook events, optionally filtered. Read-only."""
    from app.billing.models import BillingWebhookEvent

    query = db.query(BillingWebhookEvent)
    if provider:
        query = query.filter(BillingWebhookEvent.provider == provider)
    if status:
        query = query.filter(BillingWebhookEvent.processing_status == status)
    rows = query.order_by(BillingWebhookEvent.received_at.desc()).limit(limit).all()
    return [
        {
            "id": str(row.id),
            "provider": row.provider,
            "external_event_id": row.external_event_id,
            "event_type": row.event_type,
            "processing_status": row.processing_status,
            "error_category": row.error_category,
            "attempt_count": row.attempt_count,
            "received_at": row.received_at.isoformat() if row.received_at else None,
        }
        for row in rows
    ]


def inspect_subscription(workspace_id: uuid.UUID, db) -> Optional[dict]:  # type: ignore[type-arg]
    """Full, non-secret NormalizedSubscription snapshot for one workspace.
    Returns None if no row exists yet."""
    from app.billing.models import NormalizedSubscription

    sub = db.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == workspace_id).first()
    if sub is None:
        return None
    return {
        "workspace_id": str(sub.workspace_id),
        "provider": sub.provider,
        "provider_customer_reference": sub.provider_customer_reference,
        "provider_subscription_reference": sub.provider_subscription_reference,
        "plan_id": sub.plan_id,
        "billing_interval": sub.billing_interval,
        "status": sub.status,
        "billable_seats": sub.billable_seats,
        "base_quantity": sub.base_quantity,
        "additional_seat_quantity": sub.additional_seat_quantity,
        "current_period_start": sub.current_period_start.isoformat() if sub.current_period_start else None,
        "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
        "cancel_at_period_end": sub.cancel_at_period_end,
        "grace_period_end": sub.grace_period_end.isoformat() if sub.grace_period_end else None,
        "last_provider_event": sub.last_provider_event,
        "version": sub.version,
    }


def run_catalog_verify(settings, *, live: bool) -> dict:
    """Read-only GET against each configured Dodo product/add-on ID.
    Refuses to run against a Live-mode configuration unless ``live=True``
    was explicitly passed by the caller (CLI: ``--live``) — an accidental
    default invocation can never touch the Live catalog. Returns the raw,
    non-secret product JSON for each ID so the operator can manually check
    it against the Live catalog runbook checklist (price, currency,
    interval, status, tax category, add-on association, no duplicate
    IDs) — this codebase has NOT independently verified the exact
    field names Dodo's product response uses for price/currency/status
    (see tests/test_commercial_dodo_sandbox_optional.py), so this
    function deliberately does not assert on them itself.
    """
    from app.billing.dodo_client import DodoAPIClient, DodoClientConfig

    resolved_env = settings.dodo_environment_normalized
    if resolved_env not in ("test", "live"):
        raise RuntimeError(f"DODO_ENVIRONMENT is not fully configured (resolved: {resolved_env!r}).")
    if resolved_env == "live" and not live:
        raise PermissionError(
            "Refusing: configured Dodo environment is 'live' but --live was not passed. "
            "Pass --live explicitly to run a Live catalog verification (see stage F in "
            "docs/deployment/dodo-live-cutover.md)."
        )
    if resolved_env == "test" and live:
        raise PermissionError(
            "Refusing: --live was passed but the configured Dodo environment is 'test'. "
            "The --live flag must match the actual configured environment."
        )
    if not settings.DODO_API_KEY:
        raise RuntimeError("DODO_API_KEY is not set.")

    client = DodoAPIClient(DodoClientConfig(environment=resolved_env, api_key=settings.DODO_API_KEY))

    ids = {
        "pro": settings.DODO_PRO_PRODUCT_ID,
        "team": settings.DODO_TEAM_PRODUCT_ID,
    }
    results: dict[str, dict] = {}
    for label, product_id in ids.items():
        if not product_id:
            results[label] = {"error": f"DODO_{label.upper()}_PRODUCT_ID is not set."}
            continue
        try:
            results[label] = {"product_id": product_id, "raw": client.get_product(product_id)}
        except Exception as exc:  # DodoAPIError or network failure — never a secret in the message
            results[label] = {"product_id": product_id, "error": str(exc)}

    duplicate_ids = bool(ids["pro"]) and bool(ids["team"]) and ids["pro"] == ids["team"]

    return {
        "environment": resolved_env,
        "results": results,
        "duplicate_product_ids": duplicate_ids,
        "additional_seat_addon_id": settings.DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID,
    }


def run_health_check(settings, db) -> dict:
    """Composite, read-only post-cutover (or pre-cutover) health snapshot.
    Never calls the Dodo API — offline + local DB only, safe to run at any
    time in any environment."""
    from app.billing.dodo_config import check_dodo_readiness

    readiness = check_dodo_readiness(settings)
    counts = build_subscription_counts(db)
    stuck = find_stuck_webhooks(db, older_than_minutes=60)
    duplicates = find_duplicate_subscriptions(db)
    unresolved = find_unresolved_workspace_events(db, provider="dodo")

    healthy = readiness.all_present and not stuck and not duplicates and not unresolved
    return {
        "healthy": healthy,
        "readiness": readiness.as_dict(),
        "subscription_counts": counts,
        "stuck_webhooks_count": len(stuck),
        "duplicate_subscriptions_count": len(duplicates),
        "unresolved_workspace_events_count": len(unresolved),
        "billing_provider": settings.BILLING_PROVIDER or "stripe",
    }


# ── Printing helpers (CLI layer only — never called by tests directly) ──────


def _print_kv_table(title: str, rows: dict) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    for key, value in rows.items():
        print(f"  {key:<40} {value}")


def _print_list_table(title: str, rows: list[dict]) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    if not rows:
        print("  (none)")
        return
    for row in rows:
        print(f"  {row}")


# ── CLI entrypoint ────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dodo_live_cutover.py",
        description="Read-only Dodo Payments live-cutover verification commands.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("readiness", help="Offline Dodo configuration readiness check.")
    sub.add_parser("env-check", help="Masked environment-variable presence check.")

    cv = sub.add_parser("catalog-verify", help="Read-only GET against the configured Dodo product IDs.")
    cv.add_argument("--live", action="store_true", help="Explicitly confirm running against Live Mode.")

    we = sub.add_parser("webhook-events", help="List recent webhook events.")
    we.add_argument("--provider", default=None)
    we.add_argument("--status", default=None, choices=["pending", "processed", "failed", "duplicate_ignored"])
    we.add_argument("--limit", type=int, default=20)

    sub.add_parser("subscription-counts", help="Count subscriptions by (provider, status).")

    po = sub.add_parser("pilot-override", help="Inspect or print the one-workspace Dodo pilot override.")
    po_sub = po.add_subparsers(dest="pilot_action", required=True)
    po_sub.add_parser("status", help="Report the currently configured DODO_PILOT_WORKSPACE_ID, if any.")
    po_print = po_sub.add_parser("print", help="Resolve a workspace and print the Render env var to SET.")
    po_print.add_argument("workspace", help="Workspace display name or UUID.")
    po_print.add_argument("--yes", action="store_true", required=True, help="Required confirmation flag.")
    po_clear = po_sub.add_parser("clear", help="Print the instruction to UNSET the pilot override.")
    po_clear.add_argument("--yes", action="store_true", required=True, help="Required confirmation flag.")

    sc = sub.add_parser("subscription", help="Inspect one workspace's NormalizedSubscription row.")
    sc.add_argument("workspace", help="Workspace display name or UUID.")

    sub.add_parser("duplicate-subscriptions", help="Detect duplicate provider references across workspaces.")

    sw = sub.add_parser("stuck-webhooks", help="Detect pending/failed webhook events older than a threshold.")
    sw.add_argument("--older-than-minutes", type=int, default=60)

    uwe = sub.add_parser(
        "unresolved-events",
        help="Detect webhook events that verified but could not be matched to any workspace (error_category=unknown_reference).",
    )
    uwe.add_argument("--provider", default="dodo")

    sub.add_parser("health-check", help="Composite, read-only, offline post-cutover health snapshot.")

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    from app.config import settings
    from app.database import SessionLocal

    if args.command == "readiness":
        from app.billing.dodo_config import check_dodo_readiness

        report = check_dodo_readiness(settings)
        _print_list_table(
            "Dodo readiness checks",
            [{"name": c.name, "present": c.present, "detail": c.detail} for c in report.checks],
        )
        print(f"\n  all_present={report.all_present}")
        return report.exit_code

    if args.command == "env-check":
        report = build_env_check_report(settings)
        _print_kv_table("Secret variables (presence only — values never printed)", report["secrets_present"])
        _print_kv_table("Non-secret variables (values shown)", report["non_secrets"])
        print(f"\n  dodo_environment_normalized = {report['dodo_environment_normalized']!r}")
        print(f"  is_dodo_configured          = {report['is_dodo_configured']}")
        return 0

    if args.command == "catalog-verify":
        try:
            result = run_catalog_verify(settings, live=args.live)
        except (PermissionError, RuntimeError) as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2
        print(f"\nDodo catalog verification — environment={result['environment']!r}")
        for label, data in result["results"].items():
            print(f"\n  [{label}] product_id={data.get('product_id')!r}")
            if "error" in data:
                print(f"    ERROR: {data['error']}")
            else:
                print(f"    raw response: {data['raw']}")
        print(f"\n  duplicate_product_ids (pro == team)   : {result['duplicate_product_ids']}")
        print(f"  additional_seat_addon_id configured   : {bool(result['additional_seat_addon_id'])}")
        print(
            "\n  Manually confirm against the Live catalog runbook: Live Mode (not Test), "
            "correct price + currency, monthly interval, product status, add-on association, "
            "no duplicate objects — this script cannot assert on those fields itself (see "
            "docs/deployment/dodo-live-cutover.md)."
        )
        return 0

    db = SessionLocal()
    try:
        if args.command == "webhook-events":
            rows = list_webhook_events(db, provider=args.provider, status=args.status, limit=args.limit)
            _print_list_table(f"Webhook events (limit={args.limit})", rows)
            return 0

        if args.command == "subscription-counts":
            counts = build_subscription_counts(db)
            _print_kv_table("Subscription counts by provider", counts)
            return 0

        if args.command == "pilot-override":
            if args.pilot_action == "status":
                from app.billing.provider_routing import dodo_pilot_override_active, is_dodo_pilot_workspace

                current = settings.DODO_PILOT_WORKSPACE_ID
                print(f"\n  DODO_PILOT_WORKSPACE_ID (current) = {current!r}")
                if current:
                    parsed = settings.dodo_pilot_workspace_id_parsed
                    print(f"  parsed successfully                = {parsed is not None}")
                    if parsed is not None:
                        print(f"  override currently ACTIVE          = {dodo_pilot_override_active(parsed)}")
                return 0

            if args.pilot_action == "print":
                try:
                    workspace = resolve_workspace(args.workspace, db)
                except (LookupError, ValueError) as exc:
                    print(f"ERROR: {exc}", file=sys.stderr)
                    return 1
                print(f"\n  TARGET workspace: {workspace.name!r} ({workspace.id})")
                if not args.yes:
                    print("  Refusing without --yes.", file=sys.stderr)
                    return 1
                print(
                    f"\n  Set this exact Render environment variable to enable the pilot for this workspace:\n"
                    f"\n    DODO_PILOT_WORKSPACE_ID={workspace.id}\n"
                    f"\n  This value is NOT a secret. It has no effect unless Dodo is also fully "
                    f"configured (see 'env-check' / 'readiness'). It never changes BILLING_PROVIDER — "
                    f"every other workspace is unaffected."
                )
                return 0

            if args.pilot_action == "clear":
                print("\n  TARGET: the DODO_PILOT_WORKSPACE_ID Render environment variable (global, not workspace-scoped).")
                if not args.yes:
                    print("  Refusing without --yes.", file=sys.stderr)
                    return 1
                print(
                    "\n  Unset (delete) the DODO_PILOT_WORKSPACE_ID environment variable in Render, or set it "
                    "to an empty string, then redeploy. This reverts every workspace to the global "
                    "BILLING_PROVIDER default immediately — no code deploy required."
                )
                return 0

        if args.command == "subscription":
            try:
                workspace = resolve_workspace(args.workspace, db)
            except (LookupError, ValueError) as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1
            snapshot = inspect_subscription(workspace.id, db)
            if snapshot is None:
                print(f"\n  No NormalizedSubscription row exists yet for {workspace.name!r} ({workspace.id}).")
                return 0
            _print_kv_table(f"NormalizedSubscription — {workspace.name!r} ({workspace.id})", snapshot)
            return 0

        if args.command == "duplicate-subscriptions":
            findings = find_duplicate_subscriptions(db)
            _print_list_table("Duplicate provider references", findings)
            return 1 if findings else 0

        if args.command == "stuck-webhooks":
            stuck = find_stuck_webhooks(db, older_than_minutes=args.older_than_minutes)
            _print_list_table(f"Stuck webhooks (older than {args.older_than_minutes}m)", stuck)
            return 1 if stuck else 0

        if args.command == "unresolved-events":
            unresolved = find_unresolved_workspace_events(db, provider=args.provider)
            _print_list_table(
                f"Unresolved-workspace events (provider={args.provider!r}, error_category=unknown_reference)",
                unresolved,
            )
            if unresolved:
                print(
                    "\n  These events verified and parsed correctly but could not be matched to any "
                    "ConfigTrace workspace — check the checkout metadata.workspace_id sent for the "
                    "customer/subscription reference above against the `workspaces` table."
                )
            return 1 if unresolved else 0

        if args.command == "health-check":
            report = run_health_check(settings, db)
            _print_kv_table("Health check", {"healthy": report["healthy"], "billing_provider": report["billing_provider"]})
            _print_list_table(
                "Readiness checks",
                report["readiness"]["checks"],
            )
            _print_kv_table("Subscription counts", report["subscription_counts"])
            print(f"\n  stuck_webhooks_count        = {report['stuck_webhooks_count']}")
            print(f"  duplicate_subscriptions_count = {report['duplicate_subscriptions_count']}")
            print(f"  unresolved_workspace_events_count = {report['unresolved_workspace_events_count']}")
            return 0 if report["healthy"] else 1

        parser.error(f"Unknown command: {args.command}")
        return 2
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
