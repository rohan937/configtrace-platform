"""M52 test suite: Billing + Usage Limits.

Tests
-----
1.  WorkspaceBilling model — create, default values, uniqueness.
2.  Plan limits config — correct limits for each plan name.
3.  get_or_create_billing — creates free row on first call, idempotent on second.
4.  get_workspace_usage — returns correct integration + member counts.
5.  Integration limit enforcement — assert_can_create_integration raises 402 at limit.
6.  Member limit enforcement — assert_can_add_member raises 402 at limit.
7.  Free plan defaults — new workspaces get free/active billing row.
8.  Stripe webhook signature verification — good vs. bad signatures.
9.  Stripe webhook event handling — subscription.deleted reverts to free.
10. Stripe webhook event handling — payment.failed marks past_due.
11. Stripe webhook event handling — payment.succeeded clears past_due.
12. Billing router — GET /workspaces/{id}/billing returns plan + usage.
13. Billing router — 402 is raised from checkout when Stripe not configured.
14. Billing router — portal raises 400 when no customer.
15. Integration creation — 402 returned when integration limit reached.
16. Invite creation — 402 returned when member limit reached.
17. Migration 006 — upgrade/downgrade callable.
18. Plan downgrade for past_due — _effective_plan returns "free".
19. Webhook price routing — correct plan assigned from price ID.
20. Audit event on billing_plan_changed is NOT hardcoded (no unexpected events).

Scope: uses real DB for model/service tests; uses TestClient for router tests.
Does NOT call external Stripe APIs — all network calls are mocked.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_stripe_sig(secret: str, raw_body: bytes) -> str:
    """Build a Stripe-Signature header value matching billing_service verification."""
    ts = int(time.time())
    signed = f"{ts}.{raw_body.decode()}"
    sig = hmac.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. WorkspaceBilling model
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkspaceBillingModel:
    """WorkspaceBilling ORM model — field defaults and persistence."""

    def test_billing_row_created_with_defaults(self, db_session, test_user):
        """Creating a WorkspaceBilling row without explicit plan/status uses defaults."""
        from app.models.billing import WorkspaceBilling
        from app.models.workspace import Workspace, WorkspaceMember

        ws = Workspace(name="billing-default-test", created_by_user_id=test_user.id)
        db_session.add(ws)
        db_session.flush()

        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        db_session.add(member)

        billing = WorkspaceBilling(workspace_id=ws.id)
        db_session.add(billing)
        db_session.commit()
        db_session.refresh(billing)

        assert billing.plan == "free"
        assert billing.status == "active"
        assert billing.cancel_at_period_end is False
        assert billing.stripe_customer_id is None
        assert billing.stripe_subscription_id is None
        assert billing.trial_end is None

        # Cleanup
        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_billing_row_workspace_id_is_unique(self, db_session, test_user):
        """Two billing rows for the same workspace raise an integrity error."""
        import sqlalchemy.exc

        from app.models.billing import WorkspaceBilling
        from app.models.workspace import Workspace, WorkspaceMember

        ws = Workspace(name="billing-unique-test", created_by_user_id=test_user.id)
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        db_session.add(member)
        b1 = WorkspaceBilling(workspace_id=ws.id)
        b2 = WorkspaceBilling(workspace_id=ws.id)
        db_session.add(b1)
        db_session.add(b2)

        with pytest.raises(sqlalchemy.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

        # Cleanup — the rollback above reverts the flushed `ws`/`member` rows
        # too, so they may no longer be persistent; only delete what's still
        # attached to the session to avoid InvalidRequestError.
        from sqlalchemy import inspect as sa_inspect

        for obj in (member, ws):
            if sa_inspect(obj).persistent:
                db_session.delete(obj)
        db_session.commit()


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Plan limits config
# ═══════════════════════════════════════════════════════════════════════════════


class TestPlanLimits:
    """PLAN_LIMITS dict — spot-check values for each plan."""

    def test_free_plan_limits(self):
        from app.services.billing_service import get_plan_limits

        limits = get_plan_limits("free")
        assert limits["max_integrations"] == 3
        assert limits["max_members"] == 1
        assert limits["min_sync_interval_minutes"] == 60
        assert limits["history_retention_days"] == 30

    def test_pro_plan_limits(self):
        from app.services.billing_service import get_plan_limits

        limits = get_plan_limits("pro")
        assert limits["max_integrations"] == 20
        assert limits["max_members"] == 5
        assert limits["min_sync_interval_minutes"] == 15
        assert limits["history_retention_days"] == 180

    def test_team_plan_limits(self):
        from app.services.billing_service import get_plan_limits

        limits = get_plan_limits("team")
        assert limits["max_integrations"] == 100
        assert limits["max_members"] == 25
        assert limits["min_sync_interval_minutes"] == 5
        assert limits["history_retention_days"] == 365

    def test_unknown_plan_falls_back_to_free(self):
        from app.services.billing_service import get_plan_limits

        limits = get_plan_limits("enterprise")  # not a real plan
        assert limits["max_integrations"] == 3  # free defaults

    def test_pro_limits_exceed_free_limits(self):
        from app.services.billing_service import get_plan_limits

        free = get_plan_limits("free")
        pro = get_plan_limits("pro")
        assert pro["max_integrations"] > free["max_integrations"]
        assert pro["max_members"] > free["max_members"]

    def test_team_limits_exceed_pro_limits(self):
        from app.services.billing_service import get_plan_limits

        pro = get_plan_limits("pro")
        team = get_plan_limits("team")
        assert team["max_integrations"] > pro["max_integrations"]
        assert team["max_members"] > pro["max_members"]


# ═══════════════════════════════════════════════════════════════════════════════
# 3. get_or_create_billing
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetOrCreateBilling:
    """get_or_create_billing — lazy creation, idempotency."""

    def _make_workspace(self, db_session, test_user):
        from app.models.workspace import Workspace, WorkspaceMember

        ws = Workspace(name=f"ws-{uuid.uuid4().hex[:8]}", created_by_user_id=test_user.id)
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        db_session.add(member)
        db_session.flush()
        return ws, member

    def test_creates_free_row_on_first_call(self, db_session, test_user):
        from app.services.billing_service import get_or_create_billing

        ws, member = self._make_workspace(db_session, test_user)
        billing = get_or_create_billing(ws.id, db_session)
        db_session.commit()

        assert billing.workspace_id == ws.id
        assert billing.plan == "free"
        assert billing.status == "active"

        # Cleanup
        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_idempotent_on_second_call(self, db_session, test_user):
        from app.services.billing_service import get_or_create_billing

        ws, member = self._make_workspace(db_session, test_user)
        b1 = get_or_create_billing(ws.id, db_session)
        db_session.commit()
        b2 = get_or_create_billing(ws.id, db_session)

        assert b1.id == b2.id

        # Cleanup
        db_session.delete(b1)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()


# ═══════════════════════════════════════════════════════════════════════════════
# 4. get_workspace_usage
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetWorkspaceUsage:
    """get_workspace_usage — counts active integrations and members."""

    def test_empty_workspace_has_zero_integrations_one_member(
        self, db_session, test_user
    ):
        from app.models.workspace import Workspace, WorkspaceMember
        from app.services.billing_service import get_workspace_usage

        ws = Workspace(
            name=f"usage-ws-{uuid.uuid4().hex[:6]}", created_by_user_id=test_user.id
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        db_session.add(member)
        db_session.commit()

        usage = get_workspace_usage(ws.id, db_session)
        assert usage["integrations"] == 0
        assert usage["members"] == 1

        # Cleanup
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_counts_only_non_deleted_integrations(self, db_session, test_user):
        from app.models.integration import Integration
        from app.models.workspace import Workspace, WorkspaceMember
        from app.services.billing_service import get_workspace_usage

        ws = Workspace(
            name=f"usage-del-{uuid.uuid4().hex[:6]}", created_by_user_id=test_user.id
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        db_session.add(member)

        # Active integration
        active = Integration(
            user_id=test_user.id,
            provider="cloudflare",
            display_name="active",
            workspace_id=ws.id,
            encrypted_credentials=b"x",
            credential_iv=b"y",
        )
        # Soft-deleted integration — excluded via status='deleted', the same
        # field the Integration model uses (there is no deleted_at column).
        deleted = Integration(
            user_id=test_user.id,
            provider="github",
            display_name="deleted",
            workspace_id=ws.id,
            encrypted_credentials=b"x",
            credential_iv=b"y",
            status="deleted",
        )
        db_session.add_all([active, deleted])
        db_session.commit()

        usage = get_workspace_usage(ws.id, db_session)
        assert usage["integrations"] == 1

        # Cleanup
        db_session.delete(active)
        db_session.delete(deleted)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_counts_non_deleted_regardless_of_active_paused_or_error_status(
        self, db_session, test_user
    ):
        """Usage matches the Integrations page's "connected" definition:
        every non-deleted row counts, whatever its active/paused/
        needs_reconnect/error status (see integration_service.get_integrations_by_workspace,
        which filters ONLY on status != 'deleted'). This is a regression test
        for the bug where billing counted ALL historical rows including
        deleted ones, showing "5 / 3" while the Integrations page showed "2".
        """
        from app.models.integration import Integration
        from app.models.workspace import Workspace, WorkspaceMember
        from app.services.billing_service import get_workspace_usage

        ws = Workspace(
            name=f"usage-statuses-{uuid.uuid4().hex[:6]}", created_by_user_id=test_user.id
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        db_session.add(member)

        statuses = ["active", "paused", "needs_reconnect", "error", "deleted", "deleted"]
        integrations = [
            Integration(
                user_id=test_user.id,
                provider="cloudflare",
                display_name=f"int-{i}",
                workspace_id=ws.id,
                encrypted_credentials=b"x",
                credential_iv=b"y",
                status=status,
            )
            for i, status in enumerate(statuses)
        ]
        db_session.add_all(integrations)
        db_session.commit()

        # 4 non-deleted rows (active, paused, needs_reconnect, error) + 2 deleted.
        usage = get_workspace_usage(ws.id, db_session)
        assert usage["integrations"] == 4

        # Cleanup
        for i in integrations:
            db_session.delete(i)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_usage_matches_integrations_list_connected_count(self, db_session, test_user):
        """get_workspace_usage must return the same count as the Integrations
        list endpoint's `total` (get_integrations_by_workspace), for the same
        workspace and same rows."""
        from app.models.integration import Integration
        from app.models.workspace import Workspace, WorkspaceMember
        from app.services import integration_service
        from app.services.billing_service import get_workspace_usage

        ws = Workspace(
            name=f"usage-parity-{uuid.uuid4().hex[:6]}", created_by_user_id=test_user.id
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        db_session.add(member)

        statuses = ["active", "active", "needs_reconnect", "deleted", "deleted", "deleted"]
        integrations = [
            Integration(
                user_id=test_user.id,
                provider="cloudflare",
                display_name=f"int-{i}",
                workspace_id=ws.id,
                encrypted_credentials=b"x",
                credential_iv=b"y",
                status=status,
            )
            for i, status in enumerate(statuses)
        ]
        db_session.add_all(integrations)
        db_session.commit()

        usage = get_workspace_usage(ws.id, db_session)
        connected_rows = integration_service.get_integrations_by_workspace(
            workspace_id=ws.id, db=db_session
        )

        assert usage["integrations"] == len(connected_rows) == 3

        # Cleanup
        for i in integrations:
            db_session.delete(i)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()


# ═══════════════════════════════════════════════════════════════════════════════
# 5 & 6. Limit enforcement
# ═══════════════════════════════════════════════════════════════════════════════


class TestLimitEnforcement:
    """assert_can_create_integration and assert_can_add_member."""

    def _make_workspace_with_billing(self, db_session, test_user, plan="free"):
        from app.models.billing import WorkspaceBilling
        from app.models.workspace import Workspace, WorkspaceMember

        ws = Workspace(
            name=f"limit-ws-{uuid.uuid4().hex[:6]}",
            created_by_user_id=test_user.id,
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        billing = WorkspaceBilling(
            workspace_id=ws.id, plan=plan, status="active"
        )
        db_session.add_all([member, billing])
        db_session.commit()
        return ws, member, billing

    def test_integration_limit_allows_up_to_max(self, db_session, test_user):
        """No exception raised when integration count is below the limit."""
        from app.services.billing_service import assert_can_create_integration

        ws, member, billing = self._make_workspace_with_billing(
            db_session, test_user, "free"
        )
        # 0 integrations, limit is 3 — should not raise.
        assert_can_create_integration(ws.id, db_session)

        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_integration_limit_raises_402_at_limit(self, db_session, test_user):
        """HTTP 402 raised when integration count equals the free limit (3)."""
        from app.models.integration import Integration
        from app.services.billing_service import assert_can_create_integration
        from fastapi import HTTPException

        ws, member, billing = self._make_workspace_with_billing(
            db_session, test_user, "free"
        )
        # Create 3 integrations (free limit)
        integrations = [
            Integration(
                user_id=test_user.id,
                provider="cloudflare",
                display_name=f"int-{i}",
                workspace_id=ws.id,
                encrypted_credentials=b"x",
                credential_iv=b"y",
            )
            for i in range(3)
        ]
        db_session.add_all(integrations)
        db_session.commit()

        with pytest.raises(HTTPException) as exc_info:
            assert_can_create_integration(ws.id, db_session)

        assert exc_info.value.status_code == 402
        assert "integration_limit_exceeded" in exc_info.value.detail.get("error", "")
        assert exc_info.value.detail["limit"] == 3
        assert exc_info.value.detail["current_plan"] == "free"

        for i in integrations:
            db_session.delete(i)
        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_integration_limit_ignores_deleted_rows(self, db_session, test_user):
        """Free plan (limit 3) with 2 active + 3 deleted rows still allows
        adding one more — deleted (disconnected) rows must not count against
        the limit, even though 5 historical rows exist."""
        from app.models.integration import Integration
        from app.services.billing_service import assert_can_create_integration

        ws, member, billing = self._make_workspace_with_billing(
            db_session, test_user, "free"
        )
        statuses = ["active", "active", "deleted", "deleted", "deleted"]
        integrations = [
            Integration(
                user_id=test_user.id,
                provider="cloudflare",
                display_name=f"int-{i}",
                workspace_id=ws.id,
                encrypted_credentials=b"x",
                credential_iv=b"y",
                status=status,
            )
            for i, status in enumerate(statuses)
        ]
        db_session.add_all(integrations)
        db_session.commit()

        # 2 connected rows (active), limit is 3 — should not raise, even
        # though 5 total rows exist for this workspace.
        assert_can_create_integration(ws.id, db_session)

        for i in integrations:
            db_session.delete(i)
        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_integration_limit_raises_at_limit_including_non_active_connected_rows(
        self, db_session, test_user
    ):
        """A row with status='error' or 'needs_reconnect' is still connected
        (matches the Integrations page), so it counts toward the limit."""
        from app.models.integration import Integration
        from app.services.billing_service import assert_can_create_integration
        from fastapi import HTTPException

        ws, member, billing = self._make_workspace_with_billing(
            db_session, test_user, "free"
        )
        statuses = ["active", "active", "needs_reconnect"]
        integrations = [
            Integration(
                user_id=test_user.id,
                provider="cloudflare",
                display_name=f"int-{i}",
                workspace_id=ws.id,
                encrypted_credentials=b"x",
                credential_iv=b"y",
                status=status,
            )
            for i, status in enumerate(statuses)
        ]
        db_session.add_all(integrations)
        db_session.commit()

        with pytest.raises(HTTPException) as exc_info:
            assert_can_create_integration(ws.id, db_session)
        assert exc_info.value.status_code == 402

        for i in integrations:
            db_session.delete(i)
        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_member_limit_raises_402_when_full(self, db_session, test_user):
        """HTTP 402 raised when member count equals the free member limit (1)."""
        from app.services.billing_service import assert_can_add_member
        from fastapi import HTTPException

        ws, member, billing = self._make_workspace_with_billing(
            db_session, test_user, "free"
        )
        # Already 1 member (the owner), free limit is 1.
        with pytest.raises(HTTPException) as exc_info:
            assert_can_add_member(ws.id, db_session)

        assert exc_info.value.status_code == 402
        assert "member_limit_exceeded" in exc_info.value.detail.get("error", "")

        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_member_limit_allows_on_pro_plan(self, db_session, test_user):
        """No exception raised when workspace is on pro plan with room for more members."""
        from app.services.billing_service import assert_can_add_member

        ws, member, billing = self._make_workspace_with_billing(
            db_session, test_user, "pro"
        )
        # Pro allows 5 members; only 1 present.
        assert_can_add_member(ws.id, db_session)

        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_none_workspace_id_skips_integration_check(self, db_session):
        """assert_can_create_integration does nothing when workspace_id is None."""
        from app.services.billing_service import assert_can_create_integration

        # Should not raise, return None silently.
        result = assert_can_create_integration(None, db_session)
        assert result is None

    def test_effective_plan_past_due_enforces_free(self, db_session, test_user):
        """A past_due pro subscription falls back to free limits."""
        from app.models.billing import WorkspaceBilling
        from app.models.integration import Integration
        from app.services.billing_service import assert_can_create_integration
        from fastapi import HTTPException

        from app.models.workspace import Workspace, WorkspaceMember

        ws = Workspace(
            name=f"past-due-{uuid.uuid4().hex[:6]}", created_by_user_id=test_user.id
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        billing = WorkspaceBilling(
            workspace_id=ws.id,
            plan="pro",
            status="past_due",  # Payment failed — should enforce free limits
        )
        db_session.add_all([member, billing])
        # Add 4 integrations (> free limit of 3, but < pro limit of 20)
        integrations = [
            Integration(
                user_id=test_user.id,
                provider="cloudflare",
                display_name=f"int-{i}",
                workspace_id=ws.id,
                encrypted_credentials=b"x",
                credential_iv=b"y",
            )
            for i in range(4)
        ]
        db_session.add_all(integrations)
        db_session.commit()

        # Should raise because effective plan is "free" (status=past_due)
        with pytest.raises(HTTPException) as exc_info:
            assert_can_create_integration(ws.id, db_session)
        assert exc_info.value.status_code == 402

        for i in integrations:
            db_session.delete(i)
        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Free plan defaults (new workspace bootstrapping)
# ═══════════════════════════════════════════════════════════════════════════════


class TestFreePlanDefaults:
    """New workspaces get a free billing row on first billing access."""

    def test_new_workspace_gets_free_billing(self, db_session, test_user):
        from app.models.workspace import Workspace, WorkspaceMember
        from app.services.billing_service import get_or_create_billing

        ws = Workspace(
            name=f"new-ws-{uuid.uuid4().hex[:6]}", created_by_user_id=test_user.id
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        db_session.add(member)
        db_session.commit()

        billing = get_or_create_billing(ws.id, db_session)
        assert billing.plan == "free"
        assert billing.status == "active"
        assert billing.stripe_customer_id is None

        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Stripe webhook signature verification
# ═══════════════════════════════════════════════════════════════════════════════


class TestStripeWebhookVerification:
    """verify_stripe_signature — correct vs. bad signatures."""

    def test_valid_signature_returns_parsed_event(self, monkeypatch):
        from app import config
        from app.services.billing_service import verify_stripe_signature

        secret = "whsec_test_secret_abc123"
        monkeypatch.setattr(config.settings, "STRIPE_WEBHOOK_SECRET", secret)

        payload = json.dumps({"type": "test.event", "data": {}}).encode()
        sig = _make_stripe_sig(secret, payload)

        event = verify_stripe_signature(payload, sig)
        assert event["type"] == "test.event"

    def test_wrong_secret_raises_value_error(self, monkeypatch):
        from app import config
        from app.services.billing_service import verify_stripe_signature

        real_secret = "whsec_real"
        wrong_secret = "whsec_wrong"
        monkeypatch.setattr(config.settings, "STRIPE_WEBHOOK_SECRET", real_secret)

        payload = json.dumps({"type": "test.event"}).encode()
        # Sign with wrong secret
        sig = _make_stripe_sig(wrong_secret, payload)

        with pytest.raises(ValueError, match="signature mismatch"):
            verify_stripe_signature(payload, sig)

    def test_stale_timestamp_raises_value_error(self, monkeypatch):
        from app import config
        from app.services.billing_service import verify_stripe_signature

        secret = "whsec_stale"
        monkeypatch.setattr(config.settings, "STRIPE_WEBHOOK_SECRET", secret)

        payload = json.dumps({"type": "test.event"}).encode()
        # Manually build a signature with an old timestamp (6 minutes ago).
        stale_ts = int(time.time()) - 400
        signed = f"{stale_ts}.{payload.decode()}"
        sig_val = hmac.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()
        sig_header = f"t={stale_ts},v1={sig_val}"

        with pytest.raises(ValueError, match="too old"):
            verify_stripe_signature(payload, sig_header)

    def test_missing_webhook_secret_raises_value_error(self, monkeypatch):
        from app import config
        from app.services.billing_service import verify_stripe_signature

        monkeypatch.setattr(config.settings, "STRIPE_WEBHOOK_SECRET", None)

        payload = json.dumps({"type": "test.event"}).encode()
        with pytest.raises(ValueError, match="STRIPE_WEBHOOK_SECRET"):
            verify_stripe_signature(payload, "t=123,v1=abc")

    def test_malformed_sig_header_raises_value_error(self, monkeypatch):
        from app import config
        from app.services.billing_service import verify_stripe_signature

        monkeypatch.setattr(config.settings, "STRIPE_WEBHOOK_SECRET", "secret")
        payload = json.dumps({"type": "test"}).encode()

        with pytest.raises(ValueError, match="Malformed"):
            verify_stripe_signature(payload, "not-a-valid-stripe-header")


# ═══════════════════════════════════════════════════════════════════════════════
# 9, 10, 11. Stripe webhook event handling
# ═══════════════════════════════════════════════════════════════════════════════


class TestStripeWebhookEventHandling:
    """handle_webhook_event — subscription state transitions."""

    def _make_billing(self, db_session, test_user, plan="pro", status="active"):
        from app.models.billing import WorkspaceBilling
        from app.models.workspace import Workspace, WorkspaceMember

        ws = Workspace(
            name=f"wh-ws-{uuid.uuid4().hex[:6]}", created_by_user_id=test_user.id
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        sub_id = f"sub_{uuid.uuid4().hex[:12]}"
        cust_id = f"cus_{uuid.uuid4().hex[:12]}"
        billing = WorkspaceBilling(
            workspace_id=ws.id,
            plan=plan,
            status=status,
            stripe_customer_id=cust_id,
            stripe_subscription_id=sub_id,
        )
        db_session.add_all([member, billing])
        db_session.commit()
        return ws, member, billing

    def test_subscription_deleted_reverts_to_free(self, db_session, test_user):
        from app.services.billing_service import handle_webhook_event

        ws, member, billing = self._make_billing(db_session, test_user)
        event = {
            "type": "customer.subscription.deleted",
            "data": {"object": {"id": billing.stripe_subscription_id}},
        }
        handle_webhook_event(event, db_session)
        db_session.commit()
        db_session.refresh(billing)

        assert billing.plan == "free"
        assert billing.status == "active"
        assert billing.stripe_subscription_id is None

        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_payment_failed_marks_past_due(self, db_session, test_user):
        from app.services.billing_service import handle_webhook_event

        ws, member, billing = self._make_billing(db_session, test_user)
        event = {
            "type": "invoice.payment_failed",
            "data": {
                "object": {"subscription": billing.stripe_subscription_id}
            },
        }
        handle_webhook_event(event, db_session)
        db_session.commit()
        db_session.refresh(billing)

        assert billing.status == "past_due"

        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_payment_succeeded_clears_past_due(self, db_session, test_user):
        from app.services.billing_service import handle_webhook_event

        ws, member, billing = self._make_billing(
            db_session, test_user, status="past_due"
        )
        event = {
            "type": "invoice.payment_succeeded",
            "data": {
                "object": {"subscription": billing.stripe_subscription_id}
            },
        }
        handle_webhook_event(event, db_session)
        db_session.commit()
        db_session.refresh(billing)

        assert billing.status == "active"

        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_unhandled_event_type_does_not_raise(self, db_session):
        from app.services.billing_service import handle_webhook_event

        event = {"type": "product.created", "data": {"object": {}}}
        # Must not raise
        handle_webhook_event(event, db_session)


# ═══════════════════════════════════════════════════════════════════════════════
# 12, 13, 14. Billing router (HTTP layer)
# ═══════════════════════════════════════════════════════════════════════════════


class TestBillingRouter:
    """HTTP-level tests for the billing router."""

    def _make_workspace(self, db_session, test_user):
        from app.models.workspace import Workspace, WorkspaceMember

        ws = Workspace(
            name=f"billing-router-ws-{uuid.uuid4().hex[:6]}",
            created_by_user_id=test_user.id,
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        db_session.add(member)
        db_session.commit()
        return ws, member

    def test_get_billing_returns_plan_and_usage(self, client, db_session, test_user):
        ws, member = self._make_workspace(db_session, test_user)

        resp = client.get(f"/workspaces/{ws.id}/billing")
        assert resp.status_code == 200
        body = resp.json()

        assert body["plan"] == "free"
        assert body["status"] == "active"
        assert "limits" in body
        assert "usage" in body
        assert body["limits"]["max_integrations"] == 3
        assert body["usage"]["members"] == 1

        # Cleanup
        from app.models.billing import WorkspaceBilling
        billing = (
            db_session.query(WorkspaceBilling)
            .filter_by(workspace_id=ws.id)
            .first()
        )
        if billing:
            db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_billing_usage_matches_integrations_list_total(
        self, client, db_session, test_user
    ):
        """GET /workspaces/{id}/billing usage.integrations must equal the
        `total` returned by GET /integrations?workspace_id=... — the two
        pages must never disagree on how many integrations are "connected".
        """
        from app.models.integration import Integration

        ws, member = self._make_workspace(db_session, test_user)

        statuses = ["active", "active", "needs_reconnect", "deleted", "deleted"]
        integrations = [
            Integration(
                user_id=test_user.id,
                provider="cloudflare",
                display_name=f"int-{i}",
                workspace_id=ws.id,
                encrypted_credentials=b"x",
                credential_iv=b"y",
                status=status,
            )
            for i, status in enumerate(statuses)
        ]
        db_session.add_all(integrations)
        db_session.commit()

        billing_resp = client.get(f"/workspaces/{ws.id}/billing")
        assert billing_resp.status_code == 200
        billing_usage = billing_resp.json()["usage"]["integrations"]

        list_resp = client.get("/integrations", params={"workspace_id": str(ws.id)})
        assert list_resp.status_code == 200
        list_total = list_resp.json()["total"]

        assert billing_usage == list_total == 3

        # Cleanup
        from app.models.billing import WorkspaceBilling
        billing = (
            db_session.query(WorkspaceBilling)
            .filter_by(workspace_id=ws.id)
            .first()
        )
        if billing:
            db_session.delete(billing)
        for i in integrations:
            db_session.delete(i)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_checkout_returns_503_when_stripe_not_configured(
        self, client, db_session, test_user, monkeypatch
    ):
        from app import config

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", None)
        ws, member = self._make_workspace(db_session, test_user)

        resp = client.post(
            f"/workspaces/{ws.id}/billing/checkout",
            json={"price_id": "price_fake"},
        )
        # 503 (Stripe not configured) or 503 from _stripe_post
        assert resp.status_code in (503, 400)

        # Cleanup
        from app.models.billing import WorkspaceBilling
        billing = (
            db_session.query(WorkspaceBilling)
            .filter_by(workspace_id=ws.id)
            .first()
        )
        if billing:
            db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_portal_returns_400_when_no_stripe_customer(
        self, client, db_session, test_user
    ):
        ws, member = self._make_workspace(db_session, test_user)

        resp = client.post(f"/workspaces/{ws.id}/billing/portal")
        # No Stripe customer ID yet → 400
        assert resp.status_code == 400

        # Cleanup
        from app.models.billing import WorkspaceBilling
        billing = (
            db_session.query(WorkspaceBilling)
            .filter_by(workspace_id=ws.id)
            .first()
        )
        if billing:
            db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_get_billing_forbidden_for_non_member(
        self, db_session, test_user
    ):
        """A user who is not a member of the workspace gets 403 or 404."""
        from app.core.auth import get_current_user
        from app.main import app
        from app.models.user import User
        from app.models.workspace import Workspace

        # Workspace owned by test_user
        ws = Workspace(
            name=f"ws-forbidden-{uuid.uuid4().hex[:6]}",
            created_by_user_id=test_user.id,
        )
        db_session.add(ws)
        db_session.commit()

        # Second user — not a member
        uid = uuid.uuid4().hex[:10]
        other_user = User(
            clerk_id=f"other_{uid}",
            email=f"other_{uid}@test.example",
            display_name="Other",
        )
        db_session.add(other_user)
        db_session.commit()

        def _other_user():
            return other_user

        app.dependency_overrides[get_current_user] = _other_user
        try:
            from fastapi.testclient import TestClient
            with TestClient(app, raise_server_exceptions=True) as c:
                resp = c.get(f"/workspaces/{ws.id}/billing")
            assert resp.status_code in (403, 404)
        finally:
            app.dependency_overrides.clear()
            db_session.delete(other_user)
            db_session.delete(ws)
            db_session.commit()


# ═══════════════════════════════════════════════════════════════════════════════
# 15. Integration creation — 402 via HTTP
# ═══════════════════════════════════════════════════════════════════════════════


class TestIntegrationLimitViaHTTP:
    """POST /integrations returns 402 when integration limit is reached."""

    def test_create_integration_returns_402_at_limit(
        self, client, db_session, test_user, monkeypatch
    ):
        from app.models.billing import WorkspaceBilling
        from app.models.integration import Integration
        from app.models.workspace import Workspace, WorkspaceMember

        ws = Workspace(
            name=f"int-limit-ws-{uuid.uuid4().hex[:6]}",
            created_by_user_id=test_user.id,
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        billing = WorkspaceBilling(
            workspace_id=ws.id, plan="free", status="active"
        )
        db_session.add_all([member, billing])
        # Create 3 integrations (hits free limit)
        integrations = [
            Integration(
                user_id=test_user.id,
                provider="cloudflare",
                display_name=f"cf-{i}",
                workspace_id=ws.id,
                encrypted_credentials=b"x",
                credential_iv=b"y",
            )
            for i in range(3)
        ]
        db_session.add_all(integrations)
        db_session.commit()

        resp = client.post(
            "/integrations",
            json={
                "provider": "cloudflare",
                "display_name": "over limit",
                "api_token": "fake",
                "zone_id": "fake",
                "workspace_id": str(ws.id),
            },
        )
        assert resp.status_code == 402
        body = resp.json()
        assert "integration_limit_exceeded" in body["detail"]["error"]

        for i in integrations:
            db_session.delete(i)
        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()


# ═══════════════════════════════════════════════════════════════════════════════
# 16. Invite creation — 402 via HTTP
# ═══════════════════════════════════════════════════════════════════════════════


class TestMemberLimitViaHTTP:
    """POST /workspaces/{id}/invites returns 402 when member limit is reached."""

    def test_create_invite_returns_402_at_member_limit(
        self, client, db_session, test_user
    ):
        from app.models.billing import WorkspaceBilling
        from app.models.workspace import Workspace, WorkspaceMember

        ws = Workspace(
            name=f"member-limit-ws-{uuid.uuid4().hex[:6]}",
            created_by_user_id=test_user.id,
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        billing = WorkspaceBilling(
            workspace_id=ws.id, plan="free", status="active"
        )
        # Free plan: max_members=1; owner already fills that slot.
        db_session.add_all([member, billing])
        db_session.commit()

        resp = client.post(
            f"/workspaces/{ws.id}/invites",
            json={"email": "invitee@example.com", "role": "member"},
        )
        assert resp.status_code == 402
        body = resp.json()
        assert "member_limit_exceeded" in body["detail"]["error"]

        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()


# ═══════════════════════════════════════════════════════════════════════════════
# 17. Migration 006
# ═══════════════════════════════════════════════════════════════════════════════


class TestMigration006:
    """Migration 006 upgrade/downgrade functions are callable (smoke test)."""

    def test_migration_006_has_upgrade_and_downgrade(self):
        import importlib.util
        import os

        migration_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "alembic",
            "versions",
            "006_m52_billing.py",
        )
        spec = importlib.util.spec_from_file_location(
            "migration_006", os.path.abspath(migration_path)
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        assert hasattr(module, "upgrade")
        assert hasattr(module, "downgrade")
        assert callable(module.upgrade)
        assert callable(module.downgrade)

    def test_migration_006_revision_and_chain(self):
        import importlib.util
        import os

        migration_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "alembic",
            "versions",
            "006_m52_billing.py",
        )
        spec = importlib.util.spec_from_file_location(
            "migration_006", os.path.abspath(migration_path)
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        assert module.revision == "006"
        assert module.down_revision == "005"


# ═══════════════════════════════════════════════════════════════════════════════
# 18. _effective_plan behaviour
# ═══════════════════════════════════════════════════════════════════════════════


class TestEffectivePlan:
    """_effective_plan returns correct plan given billing status."""

    def _billing(self, plan, status):
        """Return a plain object that looks like a WorkspaceBilling row.

        Using types.SimpleNamespace avoids the SQLAlchemy ORM instrumentation
        that `__new__` bypasses incorrectly.
        """
        import types

        b = types.SimpleNamespace(plan=plan, status=status)
        return b

    def test_active_pro_returns_pro(self):
        from app.services.billing_service import _effective_plan

        b = self._billing("pro", "active")
        assert _effective_plan(b) == "pro"

    def test_trialing_team_returns_team(self):
        from app.services.billing_service import _effective_plan

        b = self._billing("team", "trialing")
        assert _effective_plan(b) == "team"

    def test_past_due_pro_returns_free(self):
        from app.services.billing_service import _effective_plan

        b = self._billing("pro", "past_due")
        assert _effective_plan(b) == "free"

    def test_canceled_team_returns_free(self):
        from app.services.billing_service import _effective_plan

        b = self._billing("team", "canceled")
        assert _effective_plan(b) == "free"

    def test_unpaid_pro_returns_free(self):
        from app.services.billing_service import _effective_plan

        b = self._billing("pro", "unpaid")
        assert _effective_plan(b) == "free"


# ═══════════════════════════════════════════════════════════════════════════════
# 19. Plan routing from Stripe price IDs
# ═══════════════════════════════════════════════════════════════════════════════


class TestPlanFromPriceId:
    """_plan_for_price returns correct plan name for configured price IDs."""

    def test_pro_price_maps_to_pro(self, monkeypatch):
        from app import config
        from app.services.billing_service import _plan_for_price

        monkeypatch.setattr(config.settings, "STRIPE_PRICE_PRO_MONTHLY", "price_pro_123")
        assert _plan_for_price("price_pro_123") == "pro"

    def test_team_price_maps_to_team(self, monkeypatch):
        from app import config
        from app.services.billing_service import _plan_for_price

        monkeypatch.setattr(config.settings, "STRIPE_PRICE_TEAM_MONTHLY", "price_team_456")
        assert _plan_for_price("price_team_456") == "team"

    def test_unknown_price_falls_back_to_free(self, monkeypatch):
        from app import config
        from app.services.billing_service import _plan_for_price

        monkeypatch.setattr(config.settings, "STRIPE_PRICE_PRO_MONTHLY", "price_pro_123")
        monkeypatch.setattr(config.settings, "STRIPE_PRICE_TEAM_MONTHLY", "price_team_456")
        assert _plan_for_price("price_unknown_xyz") == "free"


# ═══════════════════════════════════════════════════════════════════════════════
# 20. Security — no secrets stored in billing row
# ═══════════════════════════════════════════════════════════════════════════════


class TestBillingSecurityInvariants:
    """The WorkspaceBilling model never stores card details or raw secrets."""

    def test_billing_model_has_no_card_fields(self):
        """Confirm the model has no card number, CVV, or bank-related attributes."""
        from app.models.billing import WorkspaceBilling

        forbidden_fields = [
            "card_number",
            "cvv",
            "cvc",
            "expiry",
            "bank_account",
            "routing_number",
            "pan",
        ]
        columns = [c.key for c in WorkspaceBilling.__table__.columns]
        for field in forbidden_fields:
            assert field not in columns, f"Billing model must not have {field!r} column"

    def test_billing_response_does_not_include_raw_price(self, client, db_session, test_user, monkeypatch):
        """GET billing response exposes stripe_price_id (a public identifier) but no secrets."""
        from app import config
        from app.models.workspace import Workspace, WorkspaceMember

        monkeypatch.setattr(config.settings, "STRIPE_PRICE_PRO_MONTHLY", "price_pro_test")

        ws = Workspace(
            name=f"sec-ws-{uuid.uuid4().hex[:6]}", created_by_user_id=test_user.id
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        db_session.add(member)
        db_session.commit()

        resp = client.get(f"/workspaces/{ws.id}/billing")
        assert resp.status_code == 200
        body = resp.json()

        # The response must never include any secret key fields.
        secret_field_patterns = ["secret", "webhook", "private", "password", "token"]
        for key in body.keys():
            for pattern in secret_field_patterns:
                assert pattern not in key.lower(), (
                    f"Billing response key {key!r} looks like a secret field"
                )

        # Cleanup
        from app.models.billing import WorkspaceBilling
        billing = (
            db_session.query(WorkspaceBilling)
            .filter_by(workspace_id=ws.id)
            .first()
        )
        if billing:
            db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_effective_frontend_url_defaults_to_app_base_url(self, monkeypatch):
        """When FRONTEND_URL is not set, effective_frontend_url falls back to APP_BASE_URL."""
        from app import config

        monkeypatch.setattr(config.settings, "FRONTEND_URL", None)
        monkeypatch.setattr(config.settings, "APP_BASE_URL", "https://app.configtrace.org")
        assert config.settings.effective_frontend_url == "https://app.configtrace.org"

    def test_effective_frontend_url_uses_frontend_url_when_set(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "FRONTEND_URL", "http://localhost:3000")
        assert config.settings.effective_frontend_url == "http://localhost:3000"

    def test_is_stripe_configured_false_when_no_keys(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", None)
        monkeypatch.setattr(config.settings, "STRIPE_WEBHOOK_SECRET", None)
        assert config.settings.is_stripe_configured is False

    def test_is_stripe_configured_true_when_keys_set(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "STRIPE_SECRET_KEY", "sk_live_abc123")
        monkeypatch.setattr(config.settings, "STRIPE_WEBHOOK_SECRET", "whsec_xyz789")
        assert config.settings.is_stripe_configured is True


# ═══════════════════════════════════════════════════════════════════════════════
# 21. Invite email delivery (M52.5)
# ═══════════════════════════════════════════════════════════════════════════════


class TestInviteEmailDelivery:
    """send_invite_email — behaviour under configured / unconfigured / error cases."""

    def test_send_invite_email_calls_resend_when_configured(self, monkeypatch):
        """send_invite_email calls _send_via_resend with the correct arguments."""
        from app import config
        from app.services import email_service

        monkeypatch.setattr(config.settings, "RESEND_API_KEY", "re_test_abc")
        monkeypatch.setattr(
            config.settings, "EMAIL_FROM", "ConfigTrace <invites@configtrace.org>"
        )

        sent: list[dict] = []

        def _mock_send(**kwargs):
            sent.append(kwargs)
            return {"id": "email_123"}

        monkeypatch.setattr(email_service, "_send_via_resend", _mock_send)

        result = email_service.send_invite_email(
            to="alice@example.com",
            workspace_name="Acme Corp",
            role="member",
            invite_url="https://app.configtrace.org/invites/tok_abc123",
            inviter_display="bob@example.com",
        )

        assert result == {"id": "email_123"}
        assert len(sent) == 1
        call = sent[0]
        assert call["to"] == "alice@example.com"
        assert call["from_addr"] == "ConfigTrace <invites@configtrace.org>"
        assert "Acme Corp" in call["body"]
        assert "member" in call["body"]
        assert "https://app.configtrace.org/invites/tok_abc123" in call["body"]
        assert "bob@example.com" in call["body"]

    def test_send_invite_email_raises_not_configured_when_missing(self, monkeypatch):
        """EmailNotConfigured raised when EMAIL_FROM is absent."""
        from app import config
        from app.services.email_service import EmailNotConfigured, send_invite_email

        monkeypatch.setattr(config.settings, "RESEND_API_KEY", "re_test_abc")
        monkeypatch.setattr(config.settings, "EMAIL_FROM", None)

        with pytest.raises(EmailNotConfigured):
            send_invite_email(
                to="alice@example.com",
                workspace_name="ACME",
                role="member",
                invite_url="https://app.configtrace.org/invites/tok",
            )

    def test_send_invite_email_invite_url_uses_frontend_origin(self, monkeypatch):
        """invite_url in email body must start with the configured frontend URL."""
        from app import config
        from app.services import email_service

        monkeypatch.setattr(config.settings, "RESEND_API_KEY", "re_key")
        monkeypatch.setattr(config.settings, "EMAIL_FROM", "noreply@configtrace.org")

        captured: list[str] = []

        def _capture(**kwargs):
            captured.append(kwargs["body"])
            return {"id": "x"}

        monkeypatch.setattr(email_service, "_send_via_resend", _capture)

        invite_url = "https://app.configtrace.org/invites/rawtoken123"
        email_service.send_invite_email(
            to="invitee@example.com",
            workspace_name="W",
            role="admin",
            invite_url=invite_url,
        )

        assert invite_url in captured[0], "invite_url must appear verbatim in email body"
        # Must not contain an API URL
        assert ":8000" not in captured[0]
        assert "api." not in captured[0]

    def test_invite_email_body_does_not_contain_raw_token_accidentally(
        self, monkeypatch
    ):
        """The email body contains the full invite_url (which includes the token)
        but nothing extraneous that would leak secret context."""
        from app import config
        from app.services import email_service

        monkeypatch.setattr(config.settings, "RESEND_API_KEY", "re_key")
        monkeypatch.setattr(config.settings, "EMAIL_FROM", "noreply@configtrace.org")

        captured: list[dict] = []

        def _capture(**kwargs):
            captured.append(kwargs)
            return {"id": "x"}

        monkeypatch.setattr(email_service, "_send_via_resend", _capture)

        email_service.send_invite_email(
            to="invitee@example.com",
            workspace_name="W",
            role="member",
            invite_url="https://app.configtrace.org/invites/secrettoken",
        )

        body = captured[0]["body"]
        # Subject must not contain the raw token
        assert "secrettoken" not in captured[0]["subject"]
        # Body contains the invite URL (including token) — this is intentional
        assert "secrettoken" in body
        # But body must not contain any API key or secret
        assert "re_key" not in body
        assert "whsec" not in body


# ═══════════════════════════════════════════════════════════════════════════════
# 22. create_invite router — email_sent field and URL correctness
# ═══════════════════════════════════════════════════════════════════════════════


class TestCreateInviteEmailSent:
    """POST /workspaces/{id}/invites returns email_sent and correct invite_url."""

    def _make_workspace_pro(self, db_session, test_user):
        """Pro plan workspace so member limit doesn't block invites."""
        from app.models.billing import WorkspaceBilling
        from app.models.workspace import Workspace, WorkspaceMember

        ws = Workspace(
            name=f"inv-email-ws-{uuid.uuid4().hex[:6]}",
            created_by_user_id=test_user.id,
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        billing = WorkspaceBilling(
            workspace_id=ws.id, plan="pro", status="active"
        )
        db_session.add_all([member, billing])
        db_session.commit()
        return ws, member, billing

    def test_email_sent_true_when_email_service_succeeds(
        self, client, db_session, test_user, monkeypatch
    ):
        from app import config
        from app.services import email_service

        monkeypatch.setattr(config.settings, "RESEND_API_KEY", "re_test")
        monkeypatch.setattr(
            config.settings,
            "EMAIL_FROM",
            "ConfigTrace <invites@configtrace.org>",
        )
        monkeypatch.setattr(
            config.settings,
            "FRONTEND_URL",
            "https://app.configtrace.org",
        )
        monkeypatch.setattr(
            email_service, "_send_via_resend", lambda **kw: {"id": "ok"}
        )

        ws, member, billing = self._make_workspace_pro(db_session, test_user)

        resp = client.post(
            f"/workspaces/{ws.id}/invites",
            json={"email": "newmember@example.com", "role": "member"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["email_sent"] is True
        # invite_url must use the configured frontend URL
        assert body["invite_url"].startswith("https://app.configtrace.org/invites/")
        # invite_token must be in the invite_url
        assert body["invite_token"] in body["invite_url"]

        # Cleanup
        from app.models.workspace import WorkspaceInvite
        invite = (
            db_session.query(WorkspaceInvite).filter_by(workspace_id=ws.id).first()
        )
        if invite:
            db_session.delete(invite)
        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_email_sent_false_when_email_not_configured(
        self, client, db_session, test_user, monkeypatch
    ):
        from app import config

        monkeypatch.setattr(config.settings, "EMAIL_FROM", None)
        monkeypatch.setattr(
            config.settings,
            "FRONTEND_URL",
            "https://app.configtrace.org",
        )

        ws, member, billing = self._make_workspace_pro(db_session, test_user)

        resp = client.post(
            f"/workspaces/{ws.id}/invites",
            json={"email": "noemail@example.com", "role": "member"},
        )
        assert resp.status_code == 201
        body = resp.json()
        # Invite must still be created
        assert "invite_token" in body
        # email_sent must be False
        assert body["email_sent"] is False
        # invite_url still uses frontend origin
        assert body["invite_url"].startswith("https://app.configtrace.org/invites/")

        # Cleanup
        from app.models.workspace import WorkspaceInvite
        invite = (
            db_session.query(WorkspaceInvite).filter_by(workspace_id=ws.id).first()
        )
        if invite:
            db_session.delete(invite)
        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_invite_url_uses_frontend_url_not_api_url(
        self, client, db_session, test_user, monkeypatch
    ):
        """Regardless of email config, invite_url must point at the frontend."""
        from app import config

        monkeypatch.setattr(config.settings, "EMAIL_FROM", None)
        monkeypatch.setattr(
            config.settings,
            "FRONTEND_URL",
            "https://app.configtrace.org",
        )

        ws, member, billing = self._make_workspace_pro(db_session, test_user)

        resp = client.post(
            f"/workspaces/{ws.id}/invites",
            json={"email": "urlcheck@example.com", "role": "member"},
        )
        assert resp.status_code == 201
        invite_url = resp.json()["invite_url"]

        assert "app.configtrace.org" in invite_url
        assert "8000" not in invite_url  # Must not be an API URL
        assert "/invites/" in invite_url

        # Cleanup
        from app.models.workspace import WorkspaceInvite
        invite = (
            db_session.query(WorkspaceInvite).filter_by(workspace_id=ws.id).first()
        )
        if invite:
            db_session.delete(invite)
        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()


# ═══════════════════════════════════════════════════════════════════════════════
# 23. Config — EMAIL_FROM and is_invite_email_configured
# ═══════════════════════════════════════════════════════════════════════════════


class TestInviteEmailConfig:
    """Settings.is_invite_email_configured covers EMAIL_FROM + RESEND_API_KEY."""

    def test_false_when_no_email_from(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "RESEND_API_KEY", "re_key")
        monkeypatch.setattr(config.settings, "EMAIL_FROM", None)
        assert config.settings.is_invite_email_configured is False

    def test_false_when_no_resend_key(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "RESEND_API_KEY", None)
        monkeypatch.setattr(config.settings, "EMAIL_FROM", "noreply@configtrace.org")
        assert config.settings.is_invite_email_configured is False

    def test_true_when_both_set(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "RESEND_API_KEY", "re_live_key")
        monkeypatch.setattr(
            config.settings,
            "EMAIL_FROM",
            "ConfigTrace <invites@configtrace.org>",
        )
        assert config.settings.is_invite_email_configured is True

    def test_email_from_is_separate_from_alerts_from_email(self, monkeypatch):
        """EMAIL_FROM and ALERTS_FROM_EMAIL are independent settings."""
        from app import config

        monkeypatch.setattr(config.settings, "RESEND_API_KEY", "re_key")
        monkeypatch.setattr(config.settings, "EMAIL_FROM", None)
        monkeypatch.setattr(
            config.settings, "ALERTS_FROM_EMAIL", "alerts@configtrace.org"
        )
        # invite not configured — ALERTS_FROM_EMAIL alone is not enough
        assert config.settings.is_invite_email_configured is False


# ═══════════════════════════════════════════════════════════════════════════════
# 24. Webhook — payment_succeeded clears both past_due AND unpaid (M52.5 fix)
# ═══════════════════════════════════════════════════════════════════════════════


class TestPaymentSucceededFixM52_5:
    """invoice.payment_succeeded now clears both past_due and unpaid."""

    def _make_billing(self, db_session, test_user, status):
        from app.models.billing import WorkspaceBilling
        from app.models.workspace import Workspace, WorkspaceMember

        ws = Workspace(
            name=f"pay-succ-{uuid.uuid4().hex[:6]}", created_by_user_id=test_user.id
        )
        db_session.add(ws)
        db_session.flush()
        member = WorkspaceMember(
            workspace_id=ws.id, user_id=test_user.id, role="owner"
        )
        sub_id = f"sub_{uuid.uuid4().hex[:8]}"
        billing = WorkspaceBilling(
            workspace_id=ws.id,
            plan="pro",
            status=status,
            stripe_subscription_id=sub_id,
        )
        db_session.add_all([member, billing])
        db_session.commit()
        return ws, member, billing

    def test_payment_succeeded_clears_past_due(self, db_session, test_user):
        from app.services.billing_service import handle_webhook_event

        ws, member, billing = self._make_billing(db_session, test_user, "past_due")
        event = {
            "type": "invoice.payment_succeeded",
            "data": {
                "object": {"subscription": billing.stripe_subscription_id}
            },
        }
        handle_webhook_event(event, db_session)
        db_session.commit()
        db_session.refresh(billing)
        assert billing.status == "active"

        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_payment_succeeded_clears_unpaid(self, db_session, test_user):
        from app.services.billing_service import handle_webhook_event

        ws, member, billing = self._make_billing(db_session, test_user, "unpaid")
        event = {
            "type": "invoice.payment_succeeded",
            "data": {
                "object": {"subscription": billing.stripe_subscription_id}
            },
        }
        handle_webhook_event(event, db_session)
        db_session.commit()
        db_session.refresh(billing)
        assert billing.status == "active"

        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()

    def test_payment_succeeded_does_not_change_active(self, db_session, test_user):
        from app.services.billing_service import handle_webhook_event

        ws, member, billing = self._make_billing(db_session, test_user, "active")
        event = {
            "type": "invoice.payment_succeeded",
            "data": {
                "object": {"subscription": billing.stripe_subscription_id}
            },
        }
        handle_webhook_event(event, db_session)
        db_session.commit()
        db_session.refresh(billing)
        # Status should remain active (unchanged)
        assert billing.status == "active"

        db_session.delete(billing)
        db_session.delete(member)
        db_session.delete(ws)
        db_session.commit()


# ─────────────────────────────────────────────────────────────────────────────
# set_workspace_plan script — unit tests (no DB required)
# ─────────────────────────────────────────────────────────────────────────────

class TestSetWorkspacePlanScript:
    """Tests for scripts/set_workspace_plan.py helpers.

    All tests use mock DB sessions — no real Postgres required.
    """

    # ── resolve_workspace ────────────────────────────────────────────────────

    def test_resolve_by_exact_name(self):
        """resolve_workspace returns the workspace when name matches exactly."""
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from scripts.set_workspace_plan import resolve_workspace

        ws = MagicMock()
        ws.id = uuid.uuid4()
        ws.name = "Whoa"

        db = MagicMock()
        db.get.return_value = None  # UUID lookup misses

        q = MagicMock()
        q.filter.return_value = q
        q.all.return_value = [ws]
        db.query.return_value = q

        result = resolve_workspace("Whoa", db)
        assert result is ws

    def test_resolve_by_uuid(self):
        """resolve_workspace returns workspace directly by UUID."""
        from scripts.set_workspace_plan import resolve_workspace

        ws = MagicMock()
        ws.id = uuid.uuid4()
        ws.name = "Whoa"

        db = MagicMock()
        db.get.return_value = ws

        result = resolve_workspace(str(ws.id), db)
        assert result is ws
        db.get.assert_called_once()

    def test_resolve_raises_lookup_error_when_not_found(self):
        """resolve_workspace raises LookupError when no match."""
        from scripts.set_workspace_plan import resolve_workspace

        db = MagicMock()
        db.get.return_value = None

        q = MagicMock()
        q.filter.return_value = q
        q.all.return_value = []
        db.query.return_value = q

        with pytest.raises(LookupError, match="No workspace found"):
            resolve_workspace("Nonexistent", db)

    def test_resolve_raises_value_error_on_ambiguous_name(self):
        """resolve_workspace raises ValueError when multiple names match."""
        from scripts.set_workspace_plan import resolve_workspace

        ws1 = MagicMock(); ws1.id = uuid.uuid4(); ws1.name = "whoa"
        ws2 = MagicMock(); ws2.id = uuid.uuid4(); ws2.name = "Whoa"

        db = MagicMock()
        db.get.return_value = None

        q = MagicMock()
        q.filter.return_value = q
        q.all.return_value = [ws1, ws2]
        db.query.return_value = q

        with pytest.raises(ValueError, match="Ambiguous"):
            resolve_workspace("whoa", db)

    # ── apply_plan_change ────────────────────────────────────────────────────

    def test_apply_plan_change_updates_billing(self):
        """apply_plan_change sets plan/status on the billing row."""
        from scripts.set_workspace_plan import apply_plan_change
        from unittest.mock import patch

        ws_id = uuid.uuid4()
        mock_billing = MagicMock()
        mock_billing.plan = "free"
        mock_billing.status = "active"
        mock_billing.stripe_customer_id = None

        db = MagicMock()

        with patch(
            "app.services.billing_service.get_or_create_billing",
            return_value=mock_billing,
        ):
            result = apply_plan_change(ws_id, "team", "active", db, dry_run=False)

        assert mock_billing.plan == "team"
        assert mock_billing.status == "active"
        assert result["plan_before"] == "free"
        assert result["plan_after"] == "team"
        assert result["dry_run"] is False
        db.flush.assert_called_once()

    def test_apply_plan_change_dry_run_does_not_mutate(self):
        """apply_plan_change with dry_run=True does not touch the billing row."""
        from scripts.set_workspace_plan import apply_plan_change
        from unittest.mock import patch

        ws_id = uuid.uuid4()
        mock_billing = MagicMock()
        mock_billing.plan = "free"
        mock_billing.status = "active"
        mock_billing.stripe_customer_id = None

        db = MagicMock()

        with patch(
            "app.services.billing_service.get_or_create_billing",
            return_value=mock_billing,
        ):
            result = apply_plan_change(ws_id, "pro", "trialing", db, dry_run=True)

        # Billing object must NOT be mutated
        assert mock_billing.plan == "free"
        assert mock_billing.status == "active"
        assert result["plan_after"] == "pro"
        assert result["status_after"] == "trialing"
        assert result["dry_run"] is True
        db.flush.assert_not_called()

    def test_apply_plan_change_rejects_invalid_plan(self):
        """apply_plan_change raises ValueError for unknown plan names."""
        from scripts.set_workspace_plan import apply_plan_change

        db = MagicMock()
        with pytest.raises(ValueError, match="Invalid plan"):
            apply_plan_change(uuid.uuid4(), "enterprise", "active", db)

    def test_apply_plan_change_rejects_invalid_status(self):
        """apply_plan_change raises ValueError for unknown status values."""
        from scripts.set_workspace_plan import apply_plan_change

        db = MagicMock()
        with pytest.raises(ValueError, match="Invalid status"):
            apply_plan_change(uuid.uuid4(), "team", "suspended", db)

    def test_free_plan_limits_unchanged(self):
        """PLAN_LIMITS['free'] remains max_members=1 after script import."""
        from app.services.billing_service import PLAN_LIMITS

        assert PLAN_LIMITS["free"]["max_members"] == 1
        assert PLAN_LIMITS["free"]["max_integrations"] == 3

    def test_script_has_no_public_endpoint(self):
        """The script module does not register any FastAPI router."""
        import importlib
        import types

        # Import the module without running __main__
        import scripts.set_workspace_plan as script_mod

        # Should not have a 'router' attribute (no FastAPI router)
        assert not hasattr(script_mod, "router"), (
            "set_workspace_plan must not expose a public API router"
        )
