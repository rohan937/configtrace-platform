"""M58.26 — Card-required trial + Customer Portal cancellation hardening.

This milestone proves three properties that M58.25 set up but did not lock
down in tests:

  (a) The trial is **card-required** — checkout does not pass
      `payment_method_collection="if_required"`, so Stripe's default
      ("always") applies and a payment method is collected even though
      today's charge is $0.

  (b) The **Stripe Customer Portal** is the single cancellation/management
      path for both trialing and active subscribers, and is reachable via
      the existing `POST /workspaces/{workspace_id}/billing/portal` route.

  (c) Webhook lifecycle handling treats `trialing` as paid-plan access,
      and `customer.subscription.deleted` reverts the workspace cleanly
      to the free plan.

All tests are **DB-free** (everything is mocked) — same pattern as
`test_milestone58_25.py`. No real Stripe API calls are made.
"""

from __future__ import annotations

import importlib
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest


_FAKE_PRO_PRICE_ID  = "price_test_pro_M5826"
_FAKE_TEAM_PRICE_ID = "price_test_team_M5826"
_FAKE_STRIPE_SECRET = "sk_test_M5826_fake"  # noqa: S105  (test-only literal)
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


def _mock_billing(
    workspace_id: uuid.UUID | None = None,
    *,
    customer_id: str | None = None,
    subscription_id: str | None = None,
    status: str = "active",
    plan: str = "free",
) -> MagicMock:
    b = MagicMock(name="WorkspaceBilling")
    b.workspace_id          = workspace_id or uuid.uuid4()
    b.plan                  = plan
    b.status                = status
    b.stripe_customer_id    = customer_id
    b.stripe_subscription_id = subscription_id
    b.stripe_price_id       = None
    b.current_period_start  = None
    b.current_period_end    = None
    b.cancel_at_period_end  = False
    b.trial_end             = None
    return b


def _mock_db() -> MagicMock:
    db = MagicMock(name="Session")
    db.flush  = MagicMock(return_value=None)
    db.commit = MagicMock(return_value=None)
    return db


def _run_checkout(price_id: str, captured: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    """Run a checkout flow against mocked Stripe and return the captured
    /checkout/sessions form-data payload."""
    from app.services import billing_service

    billing = _mock_billing()
    db      = _mock_db()
    captured = captured if captured is not None else []

    def fake_stripe_post(path: str, data: dict) -> dict:
        captured.append({"path": path, "data": dict(data)})
        if path == "/customers":
            return {"id": f"cus_test_{uuid.uuid4().hex[:8]}"}
        if path == "/checkout/sessions":
            return {"id": "cs_test_M5826", "url": "https://stripe.test/checkout/M5826"}
        raise AssertionError(f"unexpected Stripe path: {path}")

    with patch.object(billing_service, "_stripe_post", side_effect=fake_stripe_post):
        billing_service.create_checkout_session(
            billing=billing,
            price_id=price_id,
            workspace_name="acme",
            owner_email="owner@example.test",
            db=db,
        )

    checkout_calls = [c for c in captured if c["path"] == "/checkout/sessions"]
    assert len(checkout_calls) == 1, "expected exactly one Stripe checkout call"
    return checkout_calls[0]["data"]


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Pro checkout includes subscription_data[trial_period_days] = 14
# ═══════════════════════════════════════════════════════════════════════════════

def test_pro_checkout_includes_14_day_trial(stripe_env):
    data = _run_checkout(_FAKE_PRO_PRICE_ID)
    assert data.get("subscription_data[trial_period_days]") == "14", (
        "Pro checkout must include a 14-day trial via "
        "subscription_data[trial_period_days]"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Team checkout includes subscription_data[trial_period_days] = 14
# ═══════════════════════════════════════════════════════════════════════════════

def test_team_checkout_includes_14_day_trial(stripe_env):
    data = _run_checkout(_FAKE_TEAM_PRICE_ID)
    assert data.get("subscription_data[trial_period_days]") == "14", (
        "Team checkout must include a 14-day trial via "
        "subscription_data[trial_period_days]"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Pro/Team checkout does NOT set payment_method_collection = "if_required"
# ═══════════════════════════════════════════════════════════════════════════════

def test_checkout_does_not_set_if_required_payment_method_collection(stripe_env):
    """Card-required trial: we must rely on Stripe's default
    `payment_method_collection="always"`. Setting it to `"if_required"`
    would enable a no-card trial — out of scope per M58.26."""
    for price_id, name in [
        (_FAKE_PRO_PRICE_ID, "Pro"),
        (_FAKE_TEAM_PRICE_ID, "Team"),
    ]:
        data = _run_checkout(price_id)
        # If the key exists at all, it must NOT be "if_required".
        pmc = data.get("payment_method_collection")
        assert pmc != "if_required", (
            f"{name} checkout must not pass payment_method_collection='if_required' "
            f"(would enable no-card trial); got {pmc!r}"
        )
        # Ideal state: the key is absent (Stripe applies its default).
        assert "payment_method_collection" not in data, (
            f"{name} checkout must not pass payment_method_collection at all so "
            f"Stripe's default 'always' applies; got key with value {pmc!r}"
        )


def test_billing_service_has_no_if_required_runtime_usage():
    """Belt-and-suspenders: scan billing_service.py for **runtime** use of
    the literal `if_required`. Comments and docstrings (which legitimately
    explain *why* we don't use it) are allowed; assignments, dict values,
    and keyword arguments are not.

    The check walks the AST and looks for string literal values whose
    constant is exactly "if_required". Such a value can only end up in
    real code (a dict, an assignment, a function call kwarg) — never in
    a comment. Docstrings appear as ast.Expr statements at the top of
    functions/modules; we treat those as documentation and skip them.
    """
    import ast

    import app.services.billing_service as bs

    src_path = bs.__file__
    with open(src_path, "r", encoding="utf-8") as f:
        src = f.read()

    tree = ast.parse(src, filename=src_path)

    # Collect ids of docstring Expr nodes so we can skip them.
    docstring_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None) or []
            if body and isinstance(body[0], ast.Expr) and isinstance(
                body[0].value, ast.Constant
            ) and isinstance(body[0].value.value, str):
                docstring_ids.add(id(body[0]))

    offenders: list[str] = []
    for node in ast.walk(tree):
        # Skip the constants that are part of a docstring Expr
        if isinstance(node, ast.Expr) and id(node) in docstring_ids:
            continue
        if isinstance(node, ast.Constant) and node.value == "if_required":
            # Walk up to find whether this Constant lives inside a docstring
            # Expr; if so, skip it.
            offenders.append(
                f"{src_path}: line {getattr(node, 'lineno', '?')} has a runtime "
                "string literal == 'if_required'"
            )

    # Final guard: a docstring constant won't reach here because docstrings
    # are at body[0] of a module/function/class, but a constant inside a
    # docstring's text wouldn't be a separate Constant node — it's just part
    # of the docstring string. So any Constant("if_required") found above is
    # genuine runtime usage.
    assert not offenders, (
        "Forbidden runtime use of 'if_required' detected:\n  "
        + "\n  ".join(offenders)
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Pro/Team checkout is subscription mode
# ═══════════════════════════════════════════════════════════════════════════════

def test_checkout_is_subscription_mode(stripe_env):
    for price_id, name in [
        (_FAKE_PRO_PRICE_ID, "Pro"),
        (_FAKE_TEAM_PRICE_ID, "Team"),
    ]:
        data = _run_checkout(price_id)
        assert data.get("mode") == "subscription", (
            f"{name} checkout must use mode='subscription'; got {data.get('mode')!r}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Billing portal endpoint is mounted at the expected route
# ═══════════════════════════════════════════════════════════════════════════════

def test_billing_portal_endpoint_is_mounted_at_expected_route():
    """`POST /workspaces/{workspace_id}/billing/portal` must be reachable
    on the FastAPI app. This locks down the route shape M58.26 depends on."""
    from app.main import app

    matching = [
        r for r in app.routes
        if hasattr(r, "path")
        and r.path == "/workspaces/{workspace_id}/billing/portal"
        and "POST" in getattr(r, "methods", set())
    ]
    assert matching, (
        "POST /workspaces/{workspace_id}/billing/portal route is missing — "
        "this is the customer-portal endpoint frontend's Manage billing "
        "button targets."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Trialing workspace can open a customer portal session
# ═══════════════════════════════════════════════════════════════════════════════

def test_trialing_workspace_can_create_portal_session(stripe_env):
    """A workspace with status='trialing' and a Stripe customer ID must be
    able to open the Customer Portal — that's the cancellation path."""
    from app.services import billing_service

    billing = _mock_billing(
        customer_id="cus_trial_M5826",
        subscription_id="sub_trial_M5826",
        status="trialing",
        plan="pro",
    )
    db = _mock_db()
    captured: List[Dict[str, Any]] = []

    def fake_stripe_post(path: str, data: dict) -> dict:
        captured.append({"path": path, "data": dict(data)})
        return {"id": "ps_M5826", "url": "https://billing.stripe.test/p/session/trial"}

    with patch.object(billing_service, "_stripe_post", side_effect=fake_stripe_post):
        url = billing_service.create_portal_session(billing=billing, db=db)

    assert url == "https://billing.stripe.test/p/session/trial"
    assert len(captured) == 1
    assert captured[0]["path"] == "/billing_portal/sessions"
    assert captured[0]["data"]["customer"] == "cus_trial_M5826", (
        "Portal session must be created for the workspace's existing Stripe "
        "customer (created at first checkout)."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Active workspace can open a customer portal session
# ═══════════════════════════════════════════════════════════════════════════════

def test_active_workspace_can_create_portal_session(stripe_env):
    from app.services import billing_service

    billing = _mock_billing(
        customer_id="cus_active_M5826",
        subscription_id="sub_active_M5826",
        status="active",
        plan="team",
    )
    db = _mock_db()
    captured: List[Dict[str, Any]] = []

    def fake_stripe_post(path: str, data: dict) -> dict:
        captured.append({"path": path, "data": dict(data)})
        return {"id": "ps_M5826b", "url": "https://billing.stripe.test/p/session/active"}

    with patch.object(billing_service, "_stripe_post", side_effect=fake_stripe_post):
        url = billing_service.create_portal_session(billing=billing, db=db)

    assert url == "https://billing.stripe.test/p/session/active"
    assert captured[0]["data"]["customer"] == "cus_active_M5826"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Free workspace without a Stripe customer is rejected safely
# ═══════════════════════════════════════════════════════════════════════════════

def test_free_workspace_without_customer_is_rejected_safely(stripe_env):
    """Workspaces that have never subscribed have no `stripe_customer_id`.
    The portal endpoint must reject them with HTTP 400 and a clear message
    rather than crashing or calling Stripe with a null customer ID."""
    from app.services import billing_service
    from fastapi import HTTPException

    billing = _mock_billing(customer_id=None, status="active", plan="free")
    db      = _mock_db()

    with patch.object(billing_service, "_stripe_post") as mock_post:
        with pytest.raises(HTTPException) as exc_info:
            billing_service.create_portal_session(billing=billing, db=db)

    assert exc_info.value.status_code == 400
    assert "subscribe" in str(exc_info.value.detail).lower() or "customer" in str(exc_info.value.detail).lower(), (
        f"Expected a clear hint about needing to subscribe first; got "
        f"{exc_info.value.detail!r}"
    )
    assert mock_post.call_count == 0, (
        "No Stripe call must be made when customer ID is missing."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Portal session uses a safe return_url pointing at the app's billing page
# ═══════════════════════════════════════════════════════════════════════════════

def test_portal_session_uses_safe_return_url(stripe_env):
    """The `return_url` sent to Stripe must point at our own app billing
    page (so users come back to ConfigTrace after managing billing), and
    must use the value configured in `settings.FRONTEND_URL` rather than
    any user-supplied input."""
    from app.services import billing_service

    billing = _mock_billing(
        customer_id="cus_return_url_M5826",
        subscription_id="sub_return_url",
        status="active",
        plan="pro",
    )
    db = _mock_db()
    captured: List[Dict[str, Any]] = []

    def fake_stripe_post(path: str, data: dict) -> dict:
        captured.append({"path": path, "data": dict(data)})
        return {"id": "ps_return", "url": "https://billing.stripe.test/p/x"}

    with patch.object(billing_service, "_stripe_post", side_effect=fake_stripe_post):
        billing_service.create_portal_session(billing=billing, db=db)

    return_url = captured[0]["data"].get("return_url", "")
    # Must start with our configured frontend URL
    assert return_url.startswith(_FAKE_FRONTEND_URL), (
        f"return_url must start with FRONTEND_URL ({_FAKE_FRONTEND_URL!r}); "
        f"got {return_url!r}"
    )
    # Must end on the billing-settings path so the user lands back on a
    # sensible page.
    assert "/settings/workspace/billing" in return_url, (
        f"return_url must point at the billing page; got {return_url!r}"
    )
    # Must be https
    assert return_url.startswith("https://"), (
        f"return_url must be https; got {return_url!r}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Webhook handling treats trialing as active access
# ═══════════════════════════════════════════════════════════════════════════════

def test_trialing_is_treated_as_paid_plan_access():
    """`_effective_plan(billing)` must return the paid plan name (not 'free')
    while the subscription is in `trialing` status — otherwise trial users
    would hit free-tier limits during their trial."""
    from app.services import billing_service

    for plan in ("pro", "team"):
        b = _mock_billing(status="trialing", plan=plan)
        assert billing_service._effective_plan(b) == plan, (
            f"trialing {plan} must grant {plan}-level access; got "
            f"{billing_service._effective_plan(b)!r}"
        )

    # And `trialing` must literally be in the active-statuses set.
    assert "trialing" in billing_service._ACTIVE_STATUSES, (
        "_ACTIVE_STATUSES must include 'trialing'."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 11. customer.subscription.deleted reverts workspace to free
# ═══════════════════════════════════════════════════════════════════════════════

def test_subscription_deleted_reverts_workspace_to_free(stripe_env):
    """When a user cancels in the Stripe Customer Portal, Stripe sends a
    `customer.subscription.deleted` event. The workspace must revert to
    free/active and the Stripe IDs must be cleared so a future trial starts
    cleanly."""
    from app.services import billing_service

    billing = _mock_billing(
        customer_id="cus_deleted",
        subscription_id="sub_deleted",
        status="active",
        plan="pro",
    )
    billing.cancel_at_period_end = True
    billing.trial_end = datetime.now(timezone.utc)
    db = _mock_db()

    event = {
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": "sub_deleted",
                "customer": "cus_deleted",
                "status": "canceled",
                "items": {"data": [{"price": {"id": _FAKE_PRO_PRICE_ID}}]},
            }
        },
    }

    with patch.object(
        billing_service, "_billing_by_subscription", return_value=billing
    ):
        billing_service.handle_webhook_event(event, db)

    assert billing.plan == "free", (
        f"Cancelled subscription must revert plan to 'free'; got {billing.plan!r}"
    )
    assert billing.status == "active", (
        "After cancellation the workspace should be on free/active limits, "
        f"got status={billing.status!r}"
    )
    assert billing.stripe_subscription_id is None, (
        "stripe_subscription_id must be cleared on cancellation."
    )
    assert billing.stripe_price_id is None
    assert billing.trial_end is None, (
        "trial_end must be cleared so a future trial isn't read as still active."
    )
    assert billing.cancel_at_period_end is False


def test_payment_failed_marks_workspace_past_due(stripe_env):
    """Lifecycle coverage: `invoice.payment_failed` flips status to
    'past_due'. `_effective_plan` then enforces free limits (per existing
    M52 behaviour) until payment succeeds."""
    from app.services import billing_service

    billing = _mock_billing(
        customer_id="cus_pf",
        subscription_id="sub_pf",
        status="active",
        plan="pro",
    )
    db = _mock_db()

    event = {
        "type": "invoice.payment_failed",
        "data": {"object": {"subscription": "sub_pf"}},
    }
    with patch.object(
        billing_service, "_billing_by_subscription", return_value=billing
    ):
        billing_service.handle_webhook_event(event, db)

    assert billing.status == "past_due"
    # Past-due must drop the user to free-tier limits even though plan stays "pro"
    assert billing_service._effective_plan(billing) == "free"


# ═══════════════════════════════════════════════════════════════════════════════
# 12. No custom provider mutation or cancellation side effect introduced
# ═══════════════════════════════════════════════════════════════════════════════

def test_billing_service_does_not_import_or_call_provider_connectors():
    """The billing flow must NOT touch provider connectors (AWS, Stripe-as-
    provider-config, GitHub, Cloudflare, Vercel, Supabase, Firebase,
    Shopify) — those are read-only configuration sync connectors and have
    nothing to do with subscription lifecycle. Importing them from
    billing_service would be a layering bug."""
    import app.services.billing_service as bs

    src_path = bs.__file__
    with open(src_path, "r", encoding="utf-8") as f:
        src = f.read()

    forbidden_imports = [
        r"\bfrom\s+app\.connectors",
        r"\bimport\s+app\.connectors",
        r"\bfrom\s+app\.services\.integration_service",
        r"\bfrom\s+app\.services\.sync_service",
        r"\bfrom\s+app\.services\.diff_service",
        r"\bfrom\s+app\.services\.notification_service",
        r"\bfrom\s+app\.services\.push_notification_service",
    ]
    offenders: list[str] = []
    for pat in forbidden_imports:
        if re.search(pat, src):
            offenders.append(pat)
    assert not offenders, (
        f"billing_service.py imports forbidden modules: {offenders}. "
        "Billing should be a closed loop — no provider mutations, no sync, "
        "no alert dispatch."
    )

    # Defensive: the literal verbs we never want to see called from billing
    forbidden_call_verbs = [
        ".create_integration(",
        ".trigger_sync(",
        ".send_alert(",
        ".dispatch_notification(",
        ".create_pr(",
        ".apply_terraform(",
    ]
    call_offenders = [v for v in forbidden_call_verbs if v in src]
    assert not call_offenders, (
        f"billing_service.py contains forbidden call sites: {call_offenders}"
    )


def test_billing_router_does_not_import_provider_connectors():
    """Same closed-loop guarantee for the billing router."""
    import app.routers.billing as br

    src_path = br.__file__
    with open(src_path, "r", encoding="utf-8") as f:
        src = f.read()

    # The router may import workspace_service (for require_role) — that's OK.
    # It must NOT import provider connectors or sync/alert services.
    for pat in (
        r"\bfrom\s+app\.connectors",
        r"\bimport\s+app\.connectors",
        r"\bfrom\s+app\.services\.sync_service",
        r"\bfrom\s+app\.services\.notification_service",
    ):
        assert not re.search(pat, src), (
            f"billing router imports forbidden module matching {pat!r}"
        )
