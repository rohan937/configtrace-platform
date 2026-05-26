"""Tests for M58.11 — Blast Radius View.

Strategy
--------
Pure unit tests using MagicMock for DB sessions + TestClient for the router
endpoint.  No real DB connection; DATABASE_URL=sqlite:///test.db is fine.

Test categories
---------------
BlastRadiusService:
  1.  AWS public SSH SG → network_exposure + admin_access domains, reachability limitation
  2.  AWS public DB port SG → data_access impact item included
  3.  Cloudflare A record → dns_routing domain
  4.  Cloudflare MX record → email delivery impact item
  5.  Cloudflare WAF → edge_protection domain
  6.  Firebase public write (firestore rules) → data_access + abuse item
  7.  Supabase RLS disabled → data_access domain, anon-key limitation present
  8.  GitHub branch protection weakened → deployment_path + code-review surface
  9.  Stripe webhook removed → payment_flow + fulfillment surface
  10. Vercel deploy hook changed → deployment_path + automation surface
  11. Shopify app scope increased → commerce_operations + auth_flow
  12. Unknown provider → available: false
  13. Low-risk change (risk_level=low, provider_conf=low) → available: false

BlastRadiusRouter:
  14. GET /changes/{id}/blast-radius — 200 available:true for high-risk SG
  15. GET /changes/{id}/blast-radius — 200 available:false for unknown low-risk
  16. GET /changes/{id}/blast-radius — non-member / wrong user gets 404

Language safety:
  17. No "confirmed", "breach", "customers impacted", "publicly reachable" in output
  18. At least one limitation present for every available result
  19. No raw secret/customer data in response
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_change(
    *,
    user_id: uuid.UUID,
    record_type: str = "a",
    record_identifier: str = "api.example.com",
    field_path: str | None = None,
    risk_level: str = "high",
    risk_reason: str = "Test risk reason.",
    change_type: str = "modified",
    integration_id: uuid.UUID | None = None,
) -> MagicMock:
    c = MagicMock()
    c.id = uuid.uuid4()
    c.user_id = user_id
    c.integration_id = integration_id or uuid.uuid4()
    c.resource_id = uuid.uuid4()
    c.change_type = change_type
    c.record_identifier = record_identifier
    c.field_path = field_path
    # prev_value / new_value are intentionally NOT set — service must never access them
    c.risk_level = risk_level
    c.risk_reason = risk_reason
    c.provider_metadata = {"record_type": record_type}
    return c


def _make_db(change: MagicMock) -> MagicMock:
    """Return a mock DB session that returns *change* on query().filter().first()."""
    db = MagicMock()
    q = MagicMock()
    q.filter.return_value.first.return_value = change
    db.query.return_value = q
    return db


def _make_db_none() -> MagicMock:
    """Return a mock DB that returns None for any query (change not found)."""
    db = MagicMock()
    q = MagicMock()
    q.filter.return_value.first.return_value = None
    db.query.return_value = q
    return db


def _call(record_type: str, risk_level: str = "high", risk_reason: str = "",
          field_path: str | None = None):
    """Convenience: call compute_blast_radius for a single change."""
    from app.services.blast_radius_service import compute_blast_radius
    uid = uuid.uuid4()
    change = _make_change(
        user_id=uid, record_type=record_type,
        risk_level=risk_level, risk_reason=risk_reason,
        field_path=field_path,
    )
    db = _make_db(change)
    return compute_blast_radius(change.id, uid, db)


# ── 1–13: Blast radius service ────────────────────────────────────────────────


class TestBlastRadiusService:

    def test_aws_sg_ssh_public_includes_network_and_admin_domains(self):
        """AWS SG with SSH + 0.0.0.0/0 → network_exposure + admin_access domains."""
        result = _call(
            "aws_security_group",
            risk_level="high",
            risk_reason="Public inbound rule: SSH (port 22) open to 0.0.0.0/0",
        )
        assert result.available is True
        assert "network_exposure" in result.impact_domains
        assert "admin_access" in result.impact_domains

    def test_aws_sg_ssh_public_has_reachability_limitation(self):
        """AWS SG result must include a reachability caveats limitation."""
        result = _call(
            "aws_security_group",
            risk_level="high",
            risk_reason="Public inbound rule: port 22 open to 0.0.0.0/0",
        )
        assert result.available is True
        combined = " ".join(result.limitations).lower()
        # Must mention that SG rule alone doesn't prove reachability
        assert any(
            phrase in combined
            for phrase in ("does not prove", "route table", "subnet", "reachability")
        )

    def test_aws_sg_db_port_includes_data_access(self):
        """AWS SG with database port open → data_access impact included."""
        result = _call(
            "aws_security_group",
            risk_level="high",
            risk_reason="Public inbound rule: postgres (port 5432) open to 0.0.0.0/0",
        )
        assert result.available is True
        assert "data_access" in result.impact_domains
        # Should have a data access item
        data_items = [i for i in result.items if "data" in i.label.lower()]
        assert len(data_items) >= 1

    def test_cloudflare_a_record_has_dns_routing_domain(self):
        """Cloudflare A record → dns_routing domain."""
        result = _call("a", risk_level="high", risk_reason="A record changed")
        assert result.available is True
        assert "dns_routing" in result.impact_domains

    def test_cloudflare_mx_record_has_email_delivery_item(self):
        """Cloudflare MX record → email delivery impact item."""
        result = _call("mx", risk_level="high", risk_reason="MX record modified")
        assert result.available is True
        # Should include an email delivery / authentication item
        email_items = [
            i for i in result.items
            if any(word in i.label.lower() for word in ("email", "mail", "authentication"))
        ]
        assert len(email_items) >= 1

    def test_cloudflare_waf_has_edge_protection_domain(self):
        """Cloudflare WAF / ruleset → edge_protection domain."""
        result = _call("cloudflare_waf", risk_level="high",
                       risk_reason="WAF rule removed")
        assert result.available is True
        assert "edge_protection" in result.impact_domains

    def test_firebase_firestore_public_write_includes_data_access_and_abuse(self):
        """Firebase firestore rules with public write → data_access + abuse item."""
        result = _call(
            "firebase_firestore_rules",
            risk_level="high",
            risk_reason="Security rules allow public write access to Firestore collection.",
        )
        assert result.available is True
        assert "data_access" in result.impact_domains
        # Should have at least two items: client access + abuse/integrity
        assert len(result.items) >= 2

    def test_supabase_rls_disabled_includes_data_access_and_anon_key_limitation(self):
        """Supabase RLS disabled → data_access domain + anon key limitation."""
        result = _call(
            "supabase_rls_status",
            risk_level="high",
            risk_reason="Row Level Security was disabled on table: user_profiles.",
        )
        assert result.available is True
        assert "data_access" in result.impact_domains
        combined_lim = " ".join(result.limitations).lower()
        assert any(
            phrase in combined_lim
            for phrase in ("anon", "service role", "authenticated key", "rls")
        )

    def test_github_branch_protection_includes_deployment_path_and_review_surface(self):
        """GitHub branch protection → deployment_path domain + code-review surface."""
        result = _call(
            "github_branch_protection",
            risk_level="high",
            risk_reason="Required pull request reviews removed from branch: main.",
        )
        assert result.available is True
        assert "deployment_path" in result.impact_domains
        # Must include at least one surface about code review or deployment gates
        surface_labels = " ".join(s.label.lower() for s in result.affected_surfaces)
        assert any(
            phrase in surface_labels
            for phrase in ("review", "deployment", "code", "pipeline", "gate")
        )

    def test_stripe_webhook_removed_includes_payment_flow_and_fulfillment_surface(self):
        """Stripe webhook removed → payment_flow domain + fulfillment surface."""
        result = _call(
            "stripe_webhook_endpoint",
            risk_level="high",
            risk_reason="Webhook endpoint removed.",
            change_type="removed",
        ) if False else _call(
            "stripe_webhook_endpoint",
            risk_level="high",
            risk_reason="Stripe webhook endpoint removed.",
        )
        assert result.available is True
        assert "payment_flow" in result.impact_domains
        # Should mention checkout / fulfillment surface
        surface_labels = " ".join(s.label.lower() for s in result.affected_surfaces)
        assert any(
            phrase in surface_labels
            for phrase in ("checkout", "fulfillment", "subscription", "invoice", "payment")
        )

    def test_vercel_deploy_hook_includes_deployment_path_and_automation_surface(self):
        """Vercel deploy hook → deployment_path domain + automation surface."""
        result = _call(
            "vercel_deploy_hook_metadata",
            risk_level="high",
            risk_reason="Deploy hook added or modified.",
        )
        assert result.available is True
        assert "deployment_path" in result.impact_domains
        # Must include at least one surface about automation / deployment
        surface_labels = " ".join(s.label.lower() for s in result.affected_surfaces)
        assert any(
            phrase in surface_labels
            for phrase in ("automation", "deployment", "pipeline", "hook")
        )

    def test_shopify_app_scope_includes_commerce_and_auth_domains(self):
        """Shopify app permissions expanded → commerce_operations + auth_flow."""
        result = _call(
            "shopify_app_scope",
            risk_level="high",
            risk_reason="App permissions expanded with new write scopes.",
        )
        assert result.available is True
        assert "commerce_operations" in result.impact_domains
        assert "auth_flow" in result.impact_domains

    def test_unknown_provider_returns_unavailable(self):
        """Empty/unknown record_type → available: false."""
        from app.services.blast_radius_service import compute_blast_radius
        uid = uuid.uuid4()
        change = _make_change(user_id=uid, record_type="", risk_level="high")
        change.provider_metadata = {"record_type": ""}
        db = _make_db(change)
        result = compute_blast_radius(change.id, uid, db)
        assert result.available is False

    def test_low_risk_low_confidence_returns_unavailable(self):
        """Low-risk change with no meaningful signals → available: false.

        cloudflare_page_rule is not a DNS type, WAF, or SSL record so it hits
        the generic Cloudflare fallback with provider_conf=low.  Combined with
        risk_level=low the service returns available: false.
        """
        result = _call("cloudflare_page_rule", risk_level="low",
                       risk_reason="Page rule added.")
        assert result.available is False


# ── 14–16: Router ─────────────────────────────────────────────────────────────


class TestBlastRadiusRouter:

    def _make_router_deps(self, change_record_type="aws_security_group",
                          risk_level="high",
                          risk_reason="Public inbound SSH from 0.0.0.0/0"):
        """Return (app, user, change_id) for TestClient use."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.routers.changes import router

        app = FastAPI()
        app.include_router(router)

        uid = uuid.uuid4()
        change_id = uuid.uuid4()
        integ_id = uuid.uuid4()
        ws_id = uuid.uuid4()

        change = _make_change(
            user_id=uid,
            record_type=change_record_type,
            risk_level=risk_level,
            risk_reason=risk_reason,
        )
        change.id = change_id
        change.integration_id = integ_id

        user = MagicMock()
        user.id = uid
        user.email = "tester@example.com"

        integration = MagicMock()
        integration.workspace_id = ws_id

        workspace_member = MagicMock()
        workspace_member.workspace_id = ws_id
        workspace_member.user_id = uid

        return app, user, change_id, change, integration, workspace_member, ws_id, uid

    def test_blast_radius_endpoint_returns_200_available_true_for_sg(self):
        """GET /changes/{id}/blast-radius → 200 available:true for high-risk SG."""
        from fastapi.testclient import TestClient
        from app.routers.changes import router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        uid = uuid.uuid4()
        change_id = uuid.uuid4()
        integ_id = uuid.uuid4()
        ws_id = uuid.uuid4()

        change = _make_change(
            user_id=uid,
            record_type="aws_security_group",
            risk_level="high",
            risk_reason="Public inbound SSH from 0.0.0.0/0",
        )
        change.id = change_id
        change.integration_id = integ_id

        user = MagicMock()
        user.id = uid

        integ = MagicMock()
        integ.workspace_id = ws_id

        member = MagicMock()
        member.workspace_id = ws_id
        member.user_id = uid

        def mock_get_db():
            db = MagicMock()
            db.get.side_effect = lambda model, pk: (
                change if pk == change_id else
                integ  if pk == integ_id else None
            )
            q = MagicMock()
            q.filter.return_value.first.return_value = member
            # Also handle blast_radius_service inner query
            q2 = MagicMock()
            q2.filter.return_value.first.return_value = change
            db.query.side_effect = [q, q2]
            return db

        def mock_get_current_user():
            return user

        from app.core.auth import get_current_user
        from app.database import get_db

        app.dependency_overrides[get_db] = mock_get_db
        app.dependency_overrides[get_current_user] = mock_get_current_user

        client = TestClient(app)
        resp = client.get(f"/changes/{change_id}/blast-radius")
        assert resp.status_code == 200
        data = resp.json()
        assert data["available"] is True
        assert "items" in data
        assert len(data["items"]) >= 1

    def test_blast_radius_endpoint_returns_200_available_false_for_unknown(self):
        """GET /changes/{id}/blast-radius → 200 available:false for unknown provider."""
        from fastapi.testclient import TestClient
        from app.routers.changes import router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        uid = uuid.uuid4()
        change_id = uuid.uuid4()
        integ_id = uuid.uuid4()
        ws_id = uuid.uuid4()

        change = _make_change(
            user_id=uid,
            record_type="",     # unknown provider
            risk_level="low",
            risk_reason="",
        )
        change.id = change_id
        change.integration_id = integ_id
        change.provider_metadata = {"record_type": ""}

        user = MagicMock()
        user.id = uid

        integ = MagicMock()
        integ.workspace_id = ws_id

        member = MagicMock()
        member.workspace_id = ws_id
        member.user_id = uid

        def mock_get_db():
            db = MagicMock()
            db.get.side_effect = lambda model, pk: (
                change if pk == change_id else
                integ  if pk == integ_id else None
            )
            q_member = MagicMock()
            q_member.filter.return_value.first.return_value = member
            q_br = MagicMock()
            q_br.filter.return_value.first.return_value = change
            db.query.side_effect = [q_member, q_br]
            return db

        def mock_get_current_user():
            return user

        from app.core.auth import get_current_user
        from app.database import get_db

        app.dependency_overrides[get_db] = mock_get_db
        app.dependency_overrides[get_current_user] = mock_get_current_user

        client = TestClient(app)
        resp = client.get(f"/changes/{change_id}/blast-radius")
        assert resp.status_code == 200
        data = resp.json()
        assert data["available"] is False

    def test_blast_radius_endpoint_returns_404_for_wrong_user(self):
        """GET /changes/{id}/blast-radius — wrong user or non-member gets 404."""
        from fastapi.testclient import TestClient
        from app.routers.changes import router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        uid = uuid.uuid4()
        other_uid = uuid.uuid4()  # different user — not a member
        change_id = uuid.uuid4()
        integ_id = uuid.uuid4()
        ws_id = uuid.uuid4()

        change = _make_change(
            user_id=uid,
            record_type="aws_security_group",
            risk_level="high",
            risk_reason="Public SSH",
        )
        change.id = change_id
        change.integration_id = integ_id

        other_user = MagicMock()
        other_user.id = other_uid  # not a workspace member

        integ = MagicMock()
        integ.workspace_id = ws_id

        def mock_get_db():
            db = MagicMock()
            db.get.side_effect = lambda model, pk: (
                change if pk == change_id else
                integ  if pk == integ_id else None
            )
            q_member = MagicMock()
            q_member.filter.return_value.first.return_value = None  # not a member
            db.query.return_value = q_member
            return db

        def mock_get_current_user():
            return other_user

        from app.core.auth import get_current_user
        from app.database import get_db

        app.dependency_overrides[get_db] = mock_get_db
        app.dependency_overrides[get_current_user] = mock_get_current_user

        client = TestClient(app)
        resp = client.get(f"/changes/{change_id}/blast-radius")
        assert resp.status_code == 404


# ── 17–19: Language safety and data hygiene ───────────────────────────────────


class TestBlastRadiusLanguageSafety:

    # Phrases that must never appear in blast radius output
    FORBIDDEN = [
        "confirmed affected",
        "confirmed impact",
        "caused outage",
        "customers impacted",
        "breach",
        "publicly reachable",     # only forbidden as a claim, not as a limitation
        "definitely affected",
        "guaranteed",
    ]

    def _flatten_response(self, result) -> str:
        """Flatten all text fields of a BlastRadiusResponse into a single string."""
        parts = [
            result.title,
            result.summary,
            " ".join(result.impact_domains),
            " ".join(result.limitations),
        ]
        for item in result.items:
            parts.extend([
                item.label, item.description,
                " ".join(item.evidence),
                " ".join(item.recommended_review),
            ])
        for surface in result.affected_surfaces:
            parts.extend([surface.label, surface.description])
        return " ".join(parts).lower()

    @pytest.mark.parametrize("record_type,risk_reason", [
        ("aws_security_group",       "Public inbound SSH from 0.0.0.0/0"),
        ("github_branch_protection", "Required reviews removed from main"),
        ("stripe_webhook_endpoint",  "Webhook endpoint removed"),
        ("firebase_firestore_rules", "Public write access allowed"),
        ("supabase_rls_status",      "RLS disabled on table user_data"),
        ("vercel_deploy_hook_metadata", "Deploy hook modified"),
        ("shopify_app_scope",        "App permissions expanded"),
        ("cloudflare_waf",           "WAF rule removed"),
        ("mx",                       "MX record changed"),
    ])
    def test_no_forbidden_phrases_in_output(self, record_type, risk_reason):
        """Output must not contain forbidden overclaiming phrases."""
        result = _call(record_type, risk_level="high", risk_reason=risk_reason)
        if not result.available:
            return  # nothing to check
        text = self._flatten_response(result)
        for phrase in self.FORBIDDEN:
            assert phrase not in text, (
                f"Forbidden phrase {phrase!r} found in blast radius output "
                f"for record_type={record_type!r}"
            )

    @pytest.mark.parametrize("record_type,risk_reason", [
        ("aws_security_group",       "Public SSH from 0.0.0.0/0"),
        ("github_branch_protection", "Required reviews removed"),
        ("stripe_webhook_endpoint",  "Webhook removed"),
        ("firebase_firestore_rules", "Public write access"),
        ("supabase_rls_status",      "RLS disabled"),
    ])
    def test_available_result_always_has_limitations(self, record_type, risk_reason):
        """Every available blast radius result must include at least one limitation."""
        result = _call(record_type, risk_level="high", risk_reason=risk_reason)
        if not result.available:
            return
        assert len(result.limitations) >= 1, (
            f"No limitations for record_type={record_type!r}"
        )

    def test_no_raw_values_in_response(self):
        """Response fields must not contain 'prev_value' or 'new_value' references."""
        result = _call(
            "aws_security_group",
            risk_level="high",
            risk_reason="Public inbound SSH from 0.0.0.0/0",
        )
        assert result.available is True
        text = self._flatten_response(result)
        # Confirm the service never surfaces raw value field names
        assert "prev_value" not in text
        assert "new_value" not in text
        # Confirm items don't embed secret-looking strings
        assert "aws_secret_access_key" not in text
        assert "api_key" not in text.replace("api key", "")  # label OK, raw key not
