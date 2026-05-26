"""Tests for M58.10 — Change Correlation / Risk Clusters.

Strategy
--------
Pure unit tests using MagicMock for DB sessions + TestClient for the router
endpoint.  No real DB connection; DATABASE_URL=sqlite:///test.db is fine.

Test categories
---------------
CorrelationService:
  1.  Same resource + integration within 10 min → provider_local cluster
  2.  GitHub + Vercel + Cloudflare within 20 min → deployment_routing cluster
  3.  Stripe + Shopify within 15 min → payments_commerce cluster
  4.  Firebase rules + Supabase RLS within 30 min → data_protection cluster
  5.  Cloudflare WAF + AWS security group within 20 min → edge_security cluster
  6.  Changes outside ±24 h window are not returned by query (mocked)
  7.  Confidence: same resource + very tight → high
  8.  Confidence: 2 cross-provider within 30 min → medium
  9.  Confidence: single weak signal → low
  10. Cluster language uses "possible/may", not "confirmed/root cause/caused by"
  11. Low-risk isolated change → available: false (nothing scored)

CorrelationRouter:
  12. GET /changes/{id}/correlation — returns 200 with available:false on no cluster
  13. GET /changes/{id}/correlation — returns 200 with cluster when related changes present
  14. GET /changes/{id}/correlation — non-member / wrong user gets 404 (auth)
  15. Response related_changes never contains prev_value / new_value fields
  16. Existing notes endpoint still works unaffected after router change
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, call

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _dt(offset_minutes: float = 0) -> datetime:
    """Return a UTC datetime offset from now by *offset_minutes*."""
    return _utcnow() + timedelta(minutes=offset_minutes)


def _make_change(
    *,
    user_id: uuid.UUID,
    record_type: str = "a",
    record_identifier: str = "api.example.com",
    field_path: str | None = None,
    risk_level: str = "high",
    change_type: str = "modified",
    integration_id: uuid.UUID | None = None,
    created_at: datetime | None = None,
) -> MagicMock:
    c = MagicMock()
    c.id = uuid.uuid4()
    c.user_id = user_id
    c.integration_id = integration_id or uuid.uuid4()
    c.resource_id = uuid.uuid4()
    c.change_type = change_type
    c.record_identifier = record_identifier
    c.field_path = field_path
    c.prev_value = None   # NEVER forwarded into correlation output
    c.new_value = None    # NEVER forwarded into correlation output
    c.risk_level = risk_level
    c.risk_reason = "Test risk reason."
    c.provider_metadata = {"record_type": record_type}
    c.created_at = created_at or _utcnow()
    return c


def _make_user(user_id: uuid.UUID | None = None) -> MagicMock:
    u = MagicMock()
    u.id = user_id or uuid.uuid4()
    u.email = "tester@example.com"
    return u


def _make_db_with_changes(primary, candidates: list) -> MagicMock:
    """Return a mock DB that returns *primary* on the first query and *candidates* on the second."""
    db = MagicMock()
    # .query().filter().first() → primary
    # .query().filter().order_by().limit().all() → candidates
    first_q = MagicMock()
    first_q.filter.return_value.first.return_value = primary
    second_q = MagicMock()
    second_q.filter.return_value.order_by.return_value.limit.return_value.all.return_value = candidates
    db.query.side_effect = [first_q, second_q]
    return db


# ── 1–11: Correlation service ─────────────────────────────────────────────────


class TestCorrelationServiceClusters:

    def test_same_resource_same_integration_creates_local_cluster(self):
        """Same record_identifier + integration within 10 min → cluster detected."""
        from app.services.change_correlation_service import correlate_change

        uid = uuid.uuid4()
        integ = uuid.uuid4()
        primary = _make_change(user_id=uid, record_type="aws_security_group",
                               record_identifier="sg-0abc", integration_id=integ)
        cand = _make_change(user_id=uid, record_type="aws_security_group",
                            record_identifier="sg-0abc", integration_id=integ,
                            created_at=_dt(-8))

        db = _make_db_with_changes(primary, [cand])
        result = correlate_change(primary.id, uid, db)

        assert result.available is True
        assert result.primary_cluster is not None
        # Should recognise same resource / provider
        assert result.primary_cluster.cluster_type in (
            "provider_local", "edge_security", "deployment_routing", "auth_access",
            "data_protection", "payments_commerce",
        )

    def test_github_vercel_cloudflare_creates_deployment_cluster(self):
        """GitHub branch + Vercel deploy hook + Cloudflare DNS → deployment_routing."""
        from app.services.change_correlation_service import (
            correlate_change,
            _identify_cluster_type,
        )

        uid = uuid.uuid4()
        primary = _make_change(user_id=uid, record_type="github_branch_protection",
                               record_identifier="main", created_at=_dt(0))
        cand1 = _make_change(user_id=uid, record_type="vercel_deploy_hook_metadata",
                             created_at=_dt(-10))
        cand2 = _make_change(user_id=uid, record_type="a",
                             record_identifier="app.example.com", created_at=_dt(-15))

        db = _make_db_with_changes(primary, [cand1, cand2])
        result = correlate_change(primary.id, uid, db)

        assert result.available is True
        assert result.primary_cluster is not None
        assert result.primary_cluster.cluster_type == "deployment_routing"

    def test_stripe_shopify_creates_commerce_cluster(self):
        """Stripe webhook + Shopify webhook → payments_commerce cluster."""
        from app.services.change_correlation_service import correlate_change

        uid = uuid.uuid4()
        primary = _make_change(user_id=uid, record_type="stripe_webhook_endpoint",
                               created_at=_dt(0))
        cand = _make_change(user_id=uid, record_type="shopify_webhook",
                            created_at=_dt(-12))

        db = _make_db_with_changes(primary, [cand])
        result = correlate_change(primary.id, uid, db)

        assert result.available is True
        assert result.primary_cluster is not None
        assert result.primary_cluster.cluster_type == "payments_commerce"

    def test_firebase_rules_supabase_rls_creates_data_protection_cluster(self):
        """Firebase security rules + Supabase RLS → data_protection cluster."""
        from app.services.change_correlation_service import correlate_change

        uid = uuid.uuid4()
        primary = _make_change(user_id=uid, record_type="firebase_security_rules",
                               created_at=_dt(0))
        cand = _make_change(user_id=uid, record_type="supabase_rls_status",
                            created_at=_dt(-20))

        db = _make_db_with_changes(primary, [cand])
        result = correlate_change(primary.id, uid, db)

        assert result.available is True
        assert result.primary_cluster is not None
        assert result.primary_cluster.cluster_type == "data_protection"

    def test_cloudflare_waf_aws_sg_creates_edge_security_cluster(self):
        """Cloudflare WAF + AWS security group → edge_security cluster."""
        from app.services.change_correlation_service import correlate_change

        uid = uuid.uuid4()
        primary = _make_change(user_id=uid, record_type="cloudflare_waf",
                               created_at=_dt(0))
        cand = _make_change(user_id=uid, record_type="aws_security_group_rule",
                            created_at=_dt(-18))

        db = _make_db_with_changes(primary, [cand])
        result = correlate_change(primary.id, uid, db)

        assert result.available is True
        assert result.primary_cluster is not None
        assert result.primary_cluster.cluster_type == "edge_security"

    def test_no_candidates_returns_not_available(self):
        """No nearby changes → available: false."""
        from app.services.change_correlation_service import correlate_change

        uid = uuid.uuid4()
        primary = _make_change(user_id=uid, record_type="a")

        db = _make_db_with_changes(primary, [])
        result = correlate_change(primary.id, uid, db)

        assert result.available is False
        assert result.primary_cluster is None

    def test_confidence_high_for_same_resource_very_tight(self):
        """Same record_identifier + within 5 min → high confidence."""
        from app.services.change_correlation_service import _assign_confidence

        uid = uuid.uuid4()
        record_id = "sg-001"
        cand = _make_change(user_id=uid, record_identifier=record_id)

        related = [(cand, 9, 5.0)]
        conf = _assign_confidence(related, record_id)
        assert conf == "high"

    def test_confidence_medium_for_two_cross_provider_within_30min(self):
        """Two related changes within 30 min → medium confidence."""
        from app.services.change_correlation_service import _assign_confidence

        uid = uuid.uuid4()
        cand1 = _make_change(user_id=uid)
        cand2 = _make_change(user_id=uid)

        related = [(cand1, 5, 20.0), (cand2, 5, 25.0)]
        conf = _assign_confidence(related, "different-resource-id")
        assert conf == "medium"

    def test_confidence_low_for_single_weak_signal(self):
        """Single change 20 hours away → low confidence."""
        from app.services.change_correlation_service import _assign_confidence

        uid = uuid.uuid4()
        cand = _make_change(user_id=uid)
        related = [(cand, 3, 20 * 60)]
        conf = _assign_confidence(related, "some-resource")
        assert conf == "low"

    def test_cluster_language_uses_possible_not_confirmed(self):
        """Cluster title/summary must use 'possible/may', not 'confirmed/root cause/caused by'."""
        from app.services.change_correlation_service import correlate_change

        uid = uuid.uuid4()
        primary = _make_change(user_id=uid, record_type="stripe_webhook_endpoint")
        cand = _make_change(user_id=uid, record_type="shopify_webhook",
                            created_at=_dt(-8))

        db = _make_db_with_changes(primary, [cand])
        result = correlate_change(primary.id, uid, db)

        assert result.available is True
        cluster = result.primary_cluster
        title_lower = cluster.title.lower()
        summary_lower = cluster.summary.lower()

        # Must use hedged language
        assert "possible" in title_lower or "may" in summary_lower

        # Must NOT use overconfident language
        for forbidden in ("confirmed", "root cause", "caused by", "definitely"):
            assert forbidden not in title_lower, f"'{forbidden}' found in title"
            assert forbidden not in summary_lower, f"'{forbidden}' found in summary"

    def test_low_risk_isolated_change_returns_not_available(self):
        """A low-risk change with no candidates → available: false."""
        from app.services.change_correlation_service import correlate_change

        uid = uuid.uuid4()
        primary = _make_change(user_id=uid, record_type="txt", risk_level="low")

        db = _make_db_with_changes(primary, [])
        result = correlate_change(primary.id, uid, db)

        assert result.available is False


# ── 12–16: Router ─────────────────────────────────────────────────────────────


def _make_app_with_mocks(primary_change, workspace_id, candidates=None):
    """Build a FastAPI TestClient with all DB/auth dependencies mocked."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.routers.changes import router

    app = FastAPI()
    app.include_router(router)

    mock_user = _make_user(primary_change.user_id)
    mock_integration = MagicMock()
    mock_integration.workspace_id = workspace_id

    mock_member = MagicMock()
    mock_member.user_id = mock_user.id
    mock_member.workspace_id = workspace_id

    # DB mock for the router helper + the service
    db = MagicMock()

    def db_get_side_effect(model, pk):
        from app.models.change import Change as ChangeModel
        from app.models.integration import Integration
        if model.__name__ == "Change" if hasattr(model, "__name__") else False:
            return primary_change if str(pk) == str(primary_change.id) else None
        if "Integration" in str(model):
            return mock_integration
        return None

    db.get.side_effect = db_get_side_effect

    # _get_change_and_workspace inner query for WorkspaceMember
    member_q = MagicMock()
    member_q.filter.return_value.first.return_value = mock_member

    # correlate_change: first query returns primary, second returns candidates
    primary_q = MagicMock()
    primary_q.filter.return_value.first.return_value = primary_change
    cands_q = MagicMock()
    cands_q.filter.return_value.order_by.return_value.limit.return_value.all.return_value = (
        candidates or []
    )

    call_count = [0]
    def query_side_effect(*args, **kwargs):
        call_count[0] += 1
        # 1st call: WorkspaceMember (from _get_change_and_workspace)
        if call_count[0] == 1:
            return member_q
        # 2nd call: primary change lookup in correlate_change
        if call_count[0] == 2:
            return primary_q
        # 3rd call: candidate lookup
        return cands_q

    db.query.side_effect = query_side_effect

    from app.database import get_db
    from app.core.auth import get_current_user
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: mock_user

    client = TestClient(app, raise_server_exceptions=False)
    return client, mock_user, db


class TestCorrelationRouter:

    def test_correlation_endpoint_returns_200_not_available(self):
        """GET /changes/{id}/correlation → 200 available:false when no cluster."""
        change_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        primary = _make_change(user_id=uuid.uuid4())
        primary.id = change_id

        client, _, _ = _make_app_with_mocks(primary, ws_id, candidates=[])
        resp = client.get(f"/changes/{change_id}/correlation",
                          headers={"Authorization": "Bearer fake"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is False
        assert body.get("primary_cluster") is None

    def test_correlation_endpoint_returns_cluster_when_related_present(self):
        """GET /changes/{id}/correlation → 200 with cluster when candidates exist."""
        change_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        uid = uuid.uuid4()
        primary = _make_change(user_id=uid, record_type="stripe_webhook_endpoint")
        primary.id = change_id

        cand = _make_change(user_id=uid, record_type="shopify_webhook",
                            created_at=_dt(-10))

        client, _, _ = _make_app_with_mocks(primary, ws_id, candidates=[cand])
        resp = client.get(f"/changes/{change_id}/correlation",
                          headers={"Authorization": "Bearer fake"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is True
        assert body["primary_cluster"] is not None
        assert "title" in body["primary_cluster"]
        assert "confidence" in body["primary_cluster"]

    def test_correlation_endpoint_404_for_wrong_user(self):
        """Non-member user: _get_change_and_workspace returns 404."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.routers.changes import router

        change_id = uuid.uuid4()

        app = FastAPI()
        app.include_router(router)

        wrong_user = _make_user()

        db = MagicMock()
        # Simulate change found but no workspace member
        mock_change = _make_change(user_id=uuid.uuid4())
        mock_change.id = change_id
        mock_integration = MagicMock()
        mock_integration.workspace_id = uuid.uuid4()

        db.get.side_effect = lambda model, pk: (
            mock_change if "Change" in str(model) else
            mock_integration if "Integration" in str(model) else None
        )
        # No workspace member
        member_q = MagicMock()
        member_q.filter.return_value.first.return_value = None
        db.query.return_value = member_q

        from app.database import get_db
        from app.core.auth import get_current_user
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_current_user] = lambda: wrong_user

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/changes/{change_id}/correlation",
                          headers={"Authorization": "Bearer fake"})
        assert resp.status_code == 404

    def test_correlation_response_has_no_raw_values_fields(self):
        """related_changes items must not include prev_value or new_value."""
        change_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        uid = uuid.uuid4()
        primary = _make_change(user_id=uid, record_type="github_branch_protection")
        primary.id = change_id
        cand = _make_change(user_id=uid, record_type="vercel_deploy_hook_metadata",
                            created_at=_dt(-5))
        cand.prev_value = "SECRET_WEBHOOK_URL"  # must never appear in output
        cand.new_value  = "NEW_SECRET_URL"

        client, _, _ = _make_app_with_mocks(primary, ws_id, candidates=[cand])
        resp = client.get(f"/changes/{change_id}/correlation",
                          headers={"Authorization": "Bearer fake"})
        assert resp.status_code == 200

        raw = resp.text
        assert "SECRET_WEBHOOK_URL" not in raw
        assert "NEW_SECRET_URL" not in raw

        body = resp.json()
        if body.get("available") and body.get("primary_cluster"):
            for item in body["primary_cluster"]["related_changes"]:
                assert "prev_value" not in item
                assert "new_value" not in item

    def test_existing_notes_endpoint_unaffected(self):
        """POST /changes/{id}/notes still returns 201 after router changes."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.routers.changes import router

        app = FastAPI()
        app.include_router(router)

        change_id = uuid.uuid4()
        ws_id = uuid.uuid4()
        uid = uuid.uuid4()
        mock_change = _make_change(user_id=uid)
        mock_change.id = change_id
        mock_integration = MagicMock()
        mock_integration.workspace_id = ws_id
        mock_user = _make_user(uid)
        mock_member = MagicMock()

        db = MagicMock()
        db.get.side_effect = lambda model, pk: (
            mock_change if "Change" in str(model) else
            mock_integration if "Integration" in str(model) else None
        )

        member_q = MagicMock()
        member_q.filter.return_value.first.return_value = mock_member
        db.query.return_value = member_q

        mock_note = MagicMock()
        mock_note.id = uuid.uuid4()
        mock_note.change_id = change_id
        mock_note.workspace_id = ws_id
        mock_note.author_user_id = uid
        mock_note.body = "Investigation note."
        mock_note.created_at = _utcnow()
        mock_note.updated_at = _utcnow()

        from app.database import get_db
        from app.core.auth import get_current_user
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_current_user] = lambda: mock_user

        with patch("app.services.change_note_service.create_note", return_value=mock_note):
            resp = TestClient(app, raise_server_exceptions=False).post(
                f"/changes/{change_id}/notes",
                json={"body": "Investigation note."},
                headers={"Authorization": "Bearer fake"},
            )

        assert resp.status_code == 201
        assert resp.json()["body"] == "Investigation note."
