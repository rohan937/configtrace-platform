"""M58.25 — Billing activation + early-access trial pricing.

Required behaviour (one test per item from the milestone brief):

 1. Pro plan metadata is $10 / month and 14-day trial.
 2. Team plan metadata is $40 / month and 14-day trial.
 3. Checkout session for Pro uses STRIPE_PRICE_PRO_MONTHLY (from env).
 4. Checkout session for Team uses STRIPE_PRICE_TEAM_MONTHLY (from env).
 5. Checkout session includes `subscription_data[trial_period_days]=14` for Pro.
 6. Checkout session includes `subscription_data[trial_period_days]=14` for Team.
 7. Invalid price ID is rejected with HTTP 400 (no Stripe call made).
 8. Workspace authorization is preserved (non-admin → 403/404).
 9. Existing billing portal behaviour still works (400 when no Stripe customer).
10. Webhook handling sets billing.status="trialing" and trial_end when Stripe
    sends a `customer.subscription.created` event with status="trialing".
11. No Stripe secret key or price ID is hardcoded anywhere in `backend/app/`.

These tests are intentionally **DB-free**: WorkspaceBilling rows, sessions,
and authorization lookups are all mocked. That way the suite can run on a
fresh checkout without docker-compose or a live Postgres, while still
exercising the real billing-service code paths.

No real Stripe API calls are made — `_stripe_post` is mocked everywhere.
"""

from __future__ import annotations

import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest


# Fake values used only inside this test module — never read from .env.
_FAKE_PRO_PRICE_ID  = "price_test_pro_M5825"
_FAKE_TEAM_PRICE_ID = "price_test_team_M5825"
_FAKE_STRIPE_SECRET = "sk_test_M5825_fake"  # noqa: S105  (test-only literal)
_FAKE_FRONTEND_URL  = "https://app.example.test"


@pytest.fixture
def stripe_env(monkeypatch: pytest.MonkeyPatch):
    """Inject fake Stripe price IDs + secret + frontend URL into settings."""
    from app import config

    monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", _FAKE_STRIPE_SECRET)
    monkeypatch.setattr(config.settings, "STRIPE_WEBHOOK_SECRET", "whsec_test_fake")
    monkeypatch.setattr(config.settings, "STRIPE_PRICE_PRO_MONTHLY", _FAKE_PRO_PRICE_ID)
    monkeypatch.setattr(config.settings, "STRIPE_PRICE_TEAM_MONTHLY", _FAKE_TEAM_PRICE_ID)
    monkeypatch.setattr(config.settings, "FRONTEND_URL", _FAKE_FRONTEND_URL)
    yield


def _mock_billing(workspace_id: uuid.UUID | None = None) -> MagicMock:
    """Build a MagicMock that quacks like a WorkspaceBilling row."""
    b = MagicMock(name="WorkspaceBilling")
    b.workspace_id          = workspace_id or uuid.uuid4()
    b.plan                  = "free"
    b.status                = "active"
    b.stripe_customer_id    = None
    b.stripe_subscription_id = None
    b.stripe_price_id       = None
    b.current_period_start  = None
    b.current_period_end    = None
    b.cancel_at_period_end  = False
    b.trial_end             = None
    return b


def _mock_db() -> MagicMock:
    """Minimal mock SQLAlchemy session for checkout / webhook flows."""
    db = MagicMock(name="Session")
    db.flush = MagicMock(return_value=None)
    db.commit = MagicMock(return_value=None)
    return db


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Pro plan metadata
# ═══════════════════════════════════════════════════════════════════════════════

def test_pro_plan_metadata_is_10_dollars_and_14_day_trial():
    """Pro plan must be priced at $10/month with a 14-day trial."""
    from app.services.billing_service import PLAN_LIMITS

    assert "pro" in PLAN_LIMITS, "Pro plan must exist in PLAN_LIMITS"
    pro = PLAN_LIMITS["pro"]
    assert pro["monthly_price_usd"] == 10, (
        f"Pro must be $10/month per M58.25; got ${pro.get('monthly_price_usd')!r}"
    )
    assert pro["trial_days"] == 14, (
        f"Pro must have a 14-day trial per M58.25; got {pro.get('trial_days')!r}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Team plan metadata
# ═══════════════════════════════════════════════════════════════════════════════

def test_team_plan_metadata_is_40_dollars_and_14_day_trial():
    """Team plan must be priced at $40/month with a 14-day trial."""
    from app.services.billing_service import PLAN_LIMITS

    assert "team" in PLAN_LIMITS, "Team plan must exist in PLAN_LIMITS"
    team = PLAN_LIMITS["team"]
    assert team["monthly_price_usd"] == 40, (
        f"Team must be $40/month per M58.25; got ${team.get('monthly_price_usd')!r}"
    )
    assert team["trial_days"] == 14, (
        f"Team must have a 14-day trial per M58.25; got {team.get('trial_days')!r}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 3 + 5. Checkout for Pro uses STRIPE_PRICE_PRO_MONTHLY + injects trial=14
# ═══════════════════════════════════════════════════════════════════════════════

def test_checkout_for_pro_uses_pro_price_id_and_injects_14_day_trial(stripe_env):
    """Pro checkout must POST the env price ID + trial_period_days=14 to Stripe."""
    from app.services import billing_service

    billing = _mock_billing()
    db      = _mock_db()
    captured: List[Dict[str, Any]] = []

    def fake_stripe_post(path: str, data: dict) -> dict:
        captured.append({"path": path, "data": dict(data)})
        if path == "/customers":
            return {"id": "cus_test_M5825"}
        if path == "/checkout/sessions":
            return {"id": "cs_test_M5825", "url": "https://stripe.test/checkout/M5825"}
        raise AssertionError(f"unexpected Stripe path: {path}")

    with patch.object(billing_service, "_stripe_post", side_effect=fake_stripe_post):
        url = billing_service.create_checkout_session(
            billing=billing,
            price_id=_FAKE_PRO_PRICE_ID,
            workspace_name="acme",
            owner_email="owner@example.test",
            db=db,
        )

    assert url == "https://stripe.test/checkout/M5825"
    checkout_calls = [c for c in captured if c["path"] == "/checkout/sessions"]
    assert len(checkout_calls) == 1, "expected exactly one Stripe checkout call"
    data = checkout_calls[0]["data"]

    assert data["line_items[0][price]"] == _FAKE_PRO_PRICE_ID, (
        "Pro checkout must use the env-configured Pro price ID"
    )
    assert data["mode"] == "subscription"
    assert data["subscription_data[trial_period_days]"] == "14", (
        "Pro checkout must include a 14-day trial via "
        "subscription_data[trial_period_days]"
    )
    assert data["metadata[workspace_id]"] == str(billing.workspace_id)


# ═══════════════════════════════════════════════════════════════════════════════
# 4 + 6. Checkout for Team uses STRIPE_PRICE_TEAM_MONTHLY + injects trial=14
# ═══════════════════════════════════════════════════════════════════════════════

def test_checkout_for_team_uses_team_price_id_and_injects_14_day_trial(stripe_env):
    """Team checkout must POST the env price ID + trial_period_days=14 to Stripe."""
    from app.services import billing_service

    billing = _mock_billing()
    db      = _mock_db()
    captured: List[Dict[str, Any]] = []

    def fake_stripe_post(path: str, data: dict) -> dict:
        captured.append({"path": path, "data": dict(data)})
        if path == "/customers":
            return {"id": "cus_test_M5825_team"}
        if path == "/checkout/sessions":
            return {"id": "cs_test_M5825_team", "url": "https://stripe.test/checkout/team"}
        raise AssertionError(f"unexpected Stripe path: {path}")

    with patch.object(billing_service, "_stripe_post", side_effect=fake_stripe_post):
        url = billing_service.create_checkout_session(
            billing=billing,
            price_id=_FAKE_TEAM_PRICE_ID,
            workspace_name="acme",
            owner_email="owner@example.test",
            db=db,
        )

    assert url.startswith("https://stripe.test/checkout/")
    checkout_calls = [c for c in captured if c["path"] == "/checkout/sessions"]
    assert len(checkout_calls) == 1
    data = checkout_calls[0]["data"]

    assert data["line_items[0][price]"] == _FAKE_TEAM_PRICE_ID, (
        "Team checkout must use the env-configured Team price ID"
    )
    assert data["subscription_data[trial_period_days]"] == "14", (
        "Team checkout must include a 14-day trial"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Invalid price ID rejected (no Stripe call made)
# ═══════════════════════════════════════════════════════════════════════════════

def test_invalid_price_id_is_rejected_safely(stripe_env):
    """An unknown price ID must raise HTTP 400 without contacting Stripe."""
    from app.services import billing_service
    from fastapi import HTTPException

    billing = _mock_billing()
    db      = _mock_db()

    with patch.object(billing_service, "_stripe_post") as mock_post:
        with pytest.raises(HTTPException) as exc_info:
            billing_service.create_checkout_session(
                billing=billing,
                price_id="price_attacker_supplied_ABC",
                workspace_name="acme",
                owner_email="owner@example.test",
                db=db,
            )

    assert exc_info.value.status_code == 400
    assert mock_post.call_count == 0, (
        "Server must not contact Stripe when the price ID is not on the allowlist"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Workspace authorization preserved (non-admin denied without DB hits)
# ═══════════════════════════════════════════════════════════════════════════════

def test_non_admin_is_denied_via_require_role(stripe_env):
    """The billing router uses `workspace_service.require_role(..., "admin", ...)`
    for both checkout and portal. If that call raises PermissionError, the
    router must convert it to HTTP 403 and never reach Stripe.

    We assert this at the router-helper level by patching `require_role`
    directly — no DB session, no TestClient, no real workspace required.
    """
    from app.routers import billing as billing_router
    from fastapi import HTTPException

    fake_user = MagicMock(id=uuid.uuid4(), email="user@example.test")
    fake_db   = MagicMock()

    with patch.object(
        billing_router.workspace_service,
        "require_role",
        side_effect=PermissionError("not admin"),
    ):
        with pytest.raises(HTTPException) as exc_info:
            billing_router._require_admin(uuid.uuid4(), fake_user, fake_db)

    assert exc_info.value.status_code == 403, (
        f"Non-admin must get HTTP 403; got {exc_info.value.status_code}"
    )


def test_workspace_not_found_returns_404(stripe_env):
    """If the workspace doesn't exist, the router converts LookupError → 404."""
    from app.routers import billing as billing_router
    from fastapi import HTTPException

    fake_user = MagicMock(id=uuid.uuid4(), email="user@example.test")
    fake_db   = MagicMock()

    with patch.object(
        billing_router.workspace_service,
        "require_role",
        side_effect=LookupError("no such workspace"),
    ):
        with pytest.raises(HTTPException) as exc_info:
            billing_router._require_admin(uuid.uuid4(), fake_user, fake_db)

    assert exc_info.value.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Existing portal behaviour: 400 when no Stripe customer
# ═══════════════════════════════════════════════════════════════════════════════

def test_portal_returns_400_when_no_stripe_customer(stripe_env):
    """`create_portal_session` must raise HTTP 400 when the workspace has no
    Stripe customer ID — verifies M58.25 changes didn't regress this guard.
    """
    from app.services import billing_service
    from fastapi import HTTPException

    billing = _mock_billing()
    billing.stripe_customer_id = None
    db      = _mock_db()

    with patch.object(billing_service, "_stripe_post") as mock_post:
        with pytest.raises(HTTPException) as exc_info:
            billing_service.create_portal_session(billing=billing, db=db)

    assert exc_info.value.status_code == 400
    assert mock_post.call_count == 0, (
        "Portal must not contact Stripe before validating customer ID"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Webhook trialing handling
# ═══════════════════════════════════════════════════════════════════════════════

def test_webhook_subscription_created_sets_trialing_status_and_trial_end(stripe_env):
    """A `customer.subscription.created` event with status='trialing' must:

      • set billing.status to 'trialing'
      • populate billing.trial_end + current_period_*
      • set billing.plan to 'pro' (since the price ID maps to Pro)
      • _effective_plan must still return 'pro' (trialing ∈ _ACTIVE_STATUSES)
    """
    from app.services import billing_service

    billing = _mock_billing()
    billing.stripe_customer_id = "cus_test_trialing"
    db      = _mock_db()

    now        = int(time.time())
    period_end = now + (14 * 86400)

    event = {
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": "sub_test_trialing",
                "customer": "cus_test_trialing",
                "status": "trialing",
                "items": {
                    "data": [
                        {"price": {"id": _FAKE_PRO_PRICE_ID}}
                    ]
                },
                "current_period_start": now,
                "current_period_end": period_end,
                "trial_end": period_end,
                "cancel_at_period_end": False,
            }
        },
    }

    # Route the lookup by subscription / customer to our mock billing.
    with patch.object(
        billing_service, "_billing_by_subscription", return_value=billing
    ), patch.object(
        billing_service, "_billing_by_customer", return_value=billing
    ):
        billing_service.handle_webhook_event(event, db)

    assert billing.status == "trialing", (
        f"Webhook must persist trialing status; got {billing.status!r}"
    )
    assert billing.plan == "pro", (
        f"Trialing Pro sub must set plan='pro'; got {billing.plan!r}"
    )
    assert billing.trial_end == datetime.fromtimestamp(period_end, tz=timezone.utc)
    assert billing.stripe_subscription_id == "sub_test_trialing"
    assert billing_service._effective_plan(billing) == "pro", (
        "_effective_plan must return 'pro' during a trialing subscription "
        "(trialing is in _ACTIVE_STATUSES)"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 11. No Stripe secret or price ID hardcoded in source
# ═══════════════════════════════════════════════════════════════════════════════

def test_no_stripe_secret_or_price_id_hardcoded_in_source():
    """Scan `backend/app/` for any literal Stripe secret key or live price ID.

    Allowed:
      * env-var *names* like STRIPE_PRICE_PRO_MONTHLY, STRIPE_SECRET_KEY
      * Stripe API URL `https://api.stripe.com/...`
      * the placeholder-detection string `sk_test_placeholder` in config.py
        (it's part of a denylist that *blocks* placeholders from being used)

    Forbidden:
      * Real `sk_(live|test)_*` or `rk_(live|test)_*` literals with non-trivial
        suffixes (Stripe secret keys have ≥24-char Base58 suffixes).
      * `price_<id>` string literals (price IDs must come from settings).
    """
    here    = os.path.dirname(os.path.abspath(__file__))
    app_dir = os.path.normpath(os.path.join(here, "..", "app"))
    assert os.path.isdir(app_dir), f"backend/app/ not found at {app_dir}"

    # Real Stripe secret keys are very long (typically 24+ Base58 chars after
    # the prefix). Setting the minimum to 16 still catches genuine leaked
    # secrets while skipping placeholder strings like "sk_test_placeholder".
    secret_re = re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}")
    # Stripe price IDs always start with `price_` and have ≥10 trailing chars.
    # Match only if the suffix is at least 10 chars long.
    price_re  = re.compile(r"\bprice_[A-Za-z0-9_]{10,}\b")

    offenders: list[str] = []
    for root, _dirs, files in os.walk(app_dir):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            with open(path, "r", encoding="utf-8") as f:
                contents = f.read()
            for m in secret_re.finditer(contents):
                offenders.append(f"{path}: secret-key literal {m.group(0)!r}")
            for m in price_re.finditer(contents):
                offenders.append(f"{path}: hardcoded price ID {m.group(0)!r}")

    assert not offenders, (
        "Found Stripe secrets / price IDs hardcoded in source:\n  "
        + "\n  ".join(offenders)
    )
