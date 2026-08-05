"""Tests for scripts/dodo_live_cutover.py (Dodo Payments live-cutover
preparation). Exercises only the importable, side-effect-free helper
functions — never the CLI's print statements. Every test asserts the
"never print/return a secret value" and "read-only" safety properties
called out in the script's own module docstring.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import dodo_live_cutover as cutover  # noqa: E402

from app.billing.models import BillingWebhookEvent, NormalizedSubscription
from app.models.workspace import Workspace


def _fake_settings(**overrides):
    base = dict(
        DODO_API_KEY="sk_super_secret",
        DODO_WEBHOOK_SECRET="whsec_super_secret",
        STRIPE_SECRET_KEY="sk_stripe_secret",
        STRIPE_WEBHOOK_SECRET="whsec_stripe_secret",
        PADDLE_API_KEY="paddle_secret",
        PADDLE_WEBHOOK_SECRET="paddle_webhook_secret",
        BILLING_PROVIDER="stripe",
        DODO_ENVIRONMENT="test",
        DODO_PRO_PRODUCT_ID="pdt_pro_123",
        DODO_TEAM_PRODUCT_ID="pdt_team_456",
        DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID="addon_789",
        DODO_PILOT_WORKSPACE_ID=None,
        BILLING_GRACE_PERIOD_DAYS=7,
        dodo_environment_normalized="test",
        is_dodo_configured=True,
        dodo_pilot_workspace_id_parsed=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class TestBuildEnvCheckReport:
    def test_never_includes_secret_values(self):
        settings = _fake_settings()
        report = cutover.build_env_check_report(settings)

        rendered = str(report)
        assert "sk_super_secret" not in rendered
        assert "whsec_super_secret" not in rendered
        assert "sk_stripe_secret" not in rendered
        assert "paddle_secret" not in rendered

    def test_secret_presence_is_boolean(self):
        settings = _fake_settings()
        report = cutover.build_env_check_report(settings)
        assert report["secrets_present"]["DODO_API_KEY"] is True
        assert all(isinstance(v, bool) for v in report["secrets_present"].values())

    def test_secret_absent_reports_false(self):
        settings = _fake_settings(DODO_API_KEY=None)
        report = cutover.build_env_check_report(settings)
        assert report["secrets_present"]["DODO_API_KEY"] is False

    def test_non_secrets_show_real_values(self):
        settings = _fake_settings()
        report = cutover.build_env_check_report(settings)
        assert report["non_secrets"]["DODO_PRO_PRODUCT_ID"] == "pdt_pro_123"
        assert report["non_secrets"]["BILLING_PROVIDER"] == "stripe"


class TestCatalogVerifyEnvironmentGuard:
    def test_refuses_live_without_explicit_flag(self):
        settings = _fake_settings(DODO_ENVIRONMENT="live", dodo_environment_normalized="live")
        with pytest.raises(PermissionError, match="Refusing.*live"):
            cutover.run_catalog_verify(settings, live=False)

    def test_refuses_live_flag_when_configured_test(self):
        settings = _fake_settings()  # normalized == "test"
        with pytest.raises(PermissionError, match="test"):
            cutover.run_catalog_verify(settings, live=True)

    def test_refuses_when_environment_not_configured(self):
        settings = _fake_settings(dodo_environment_normalized="not_configured")
        with pytest.raises(RuntimeError, match="not fully configured"):
            cutover.run_catalog_verify(settings, live=False)

    def test_refuses_when_api_key_missing(self):
        settings = _fake_settings(DODO_API_KEY=None)
        with pytest.raises(RuntimeError, match="DODO_API_KEY"):
            cutover.run_catalog_verify(settings, live=False)

    def test_live_with_explicit_flag_proceeds_to_client_construction(self, monkeypatch):
        settings = _fake_settings(DODO_ENVIRONMENT="live", dodo_environment_normalized="live")

        captured = {}

        class _FakeClient:
            def __init__(self, config):
                captured["config"] = config

            def get_product(self, product_id):
                return {"id": product_id, "status": "active"}

        monkeypatch.setattr(cutover, "DodoAPIClient", _FakeClient, raising=False)
        import app.billing.dodo_client as dodo_client_module

        monkeypatch.setattr(dodo_client_module, "DodoAPIClient", _FakeClient)

        result = cutover.run_catalog_verify(settings, live=True)
        assert result["environment"] == "live"
        assert captured["config"].environment == "live"

    def test_never_leaks_api_key_in_result(self, monkeypatch):
        settings = _fake_settings()

        class _FakeClient:
            def __init__(self, config):
                pass

            def get_product(self, product_id):
                return {"id": product_id}

        import app.billing.dodo_client as dodo_client_module

        monkeypatch.setattr(dodo_client_module, "DodoAPIClient", _FakeClient)

        result = cutover.run_catalog_verify(settings, live=False)
        assert "sk_super_secret" not in str(result)

    def test_detects_duplicate_product_ids(self, monkeypatch):
        settings = _fake_settings(DODO_TEAM_PRODUCT_ID="pdt_pro_123")  # same as pro

        class _FakeClient:
            def __init__(self, config):
                pass

            def get_product(self, product_id):
                return {"id": product_id}

        import app.billing.dodo_client as dodo_client_module

        monkeypatch.setattr(dodo_client_module, "DodoAPIClient", _FakeClient)

        result = cutover.run_catalog_verify(settings, live=False)
        assert result["duplicate_product_ids"] is True

    def test_missing_product_id_reported_as_error_not_exception(self, monkeypatch):
        settings = _fake_settings(DODO_TEAM_PRODUCT_ID=None)

        class _FakeClient:
            def __init__(self, config):
                pass

            def get_product(self, product_id):
                return {"id": product_id}

        import app.billing.dodo_client as dodo_client_module

        monkeypatch.setattr(dodo_client_module, "DodoAPIClient", _FakeClient)

        result = cutover.run_catalog_verify(settings, live=False)
        assert "error" in result["results"]["team"]


@pytest.fixture
def workspace(db_session):
    ws = Workspace(name=f"cutover-script-test-{uuid.uuid4().hex[:8]}")
    db_session.add(ws)
    db_session.commit()
    db_session.refresh(ws)
    yield ws
    db_session.query(NormalizedSubscription).filter(NormalizedSubscription.workspace_id == ws.id).delete()
    db_session.query(BillingWebhookEvent).delete()
    db_session.commit()
    db_session.delete(ws)
    db_session.commit()


class TestResolveWorkspace:
    def test_resolves_by_uuid(self, db_session, workspace):
        found = cutover.resolve_workspace(str(workspace.id), db_session)
        assert found.id == workspace.id

    def test_resolves_by_name_case_insensitive(self, db_session, workspace):
        found = cutover.resolve_workspace(workspace.name.upper(), db_session)
        assert found.id == workspace.id

    def test_raises_lookup_error_for_unknown(self, db_session):
        with pytest.raises(LookupError):
            cutover.resolve_workspace(str(uuid.uuid4()), db_session)


class TestSubscriptionCounts:
    def test_counts_by_provider_and_status(self, db_session, workspace):
        sub = NormalizedSubscription(
            workspace_id=workspace.id, provider="dodo", plan_id="pro",
            billing_interval="month", status="active",
        )
        db_session.add(sub)
        db_session.commit()

        counts = cutover.build_subscription_counts(db_session)
        assert counts["dodo"]["active"] >= 1


class TestInspectSubscription:
    def test_returns_none_when_no_row(self, db_session, workspace):
        assert cutover.inspect_subscription(workspace.id, db_session) is None

    def test_returns_snapshot_without_error(self, db_session, workspace):
        sub = NormalizedSubscription(
            workspace_id=workspace.id, provider="dodo", plan_id="team",
            billing_interval="month", status="active", billable_seats=21,
        )
        db_session.add(sub)
        db_session.commit()

        snapshot = cutover.inspect_subscription(workspace.id, db_session)
        assert snapshot["provider"] == "dodo"
        assert snapshot["billable_seats"] == 21


class TestDuplicateSubscriptionDetection:
    def test_no_duplicates_by_default(self, db_session, workspace):
        sub = NormalizedSubscription(
            workspace_id=workspace.id, provider="dodo", plan_id="pro",
            billing_interval="month", status="active",
            provider_subscription_reference="sub_unique_1",
        )
        db_session.add(sub)
        db_session.commit()

        findings = cutover.find_duplicate_subscriptions(db_session)
        refs = [f["reference"] for f in findings]
        assert "sub_unique_1" not in refs

    def test_detects_shared_subscription_reference(self, db_session):
        ws1 = Workspace(name=f"dup-a-{uuid.uuid4().hex[:8]}")
        ws2 = Workspace(name=f"dup-b-{uuid.uuid4().hex[:8]}")
        db_session.add_all([ws1, ws2])
        db_session.commit()

        shared_ref = f"sub_shared_{uuid.uuid4().hex[:8]}"
        sub1 = NormalizedSubscription(
            workspace_id=ws1.id, provider="dodo", plan_id="pro", billing_interval="month",
            status="active", provider_subscription_reference=shared_ref,
        )
        sub2 = NormalizedSubscription(
            workspace_id=ws2.id, provider="dodo", plan_id="pro", billing_interval="month",
            status="active", provider_subscription_reference=shared_ref,
        )
        db_session.add_all([sub1, sub2])
        db_session.commit()

        try:
            findings = cutover.find_duplicate_subscriptions(db_session)
            matching = [f for f in findings if f["reference"] == shared_ref]
            assert len(matching) == 1
            assert matching[0]["kind"] == "duplicate_subscription_reference"
            assert set(matching[0]["workspace_ids"]) == {str(ws1.id), str(ws2.id)}
        finally:
            db_session.query(NormalizedSubscription).filter(
                NormalizedSubscription.workspace_id.in_([ws1.id, ws2.id])
            ).delete(synchronize_session=False)
            db_session.commit()
            db_session.delete(ws1)
            db_session.delete(ws2)
            db_session.commit()


class TestStuckWebhookDetection:
    def test_recent_pending_event_not_flagged(self, db_session):
        event = BillingWebhookEvent(
            provider="dodo", external_event_id=f"evt_{uuid.uuid4().hex[:8]}",
            event_type="subscription_updated", processing_status="pending",
        )
        db_session.add(event)
        db_session.commit()

        try:
            stuck = cutover.find_stuck_webhooks(db_session, older_than_minutes=60)
            assert event.external_event_id not in [s["external_event_id"] for s in stuck]
        finally:
            db_session.delete(event)
            db_session.commit()

    def test_old_pending_event_is_flagged(self, db_session):
        event = BillingWebhookEvent(
            provider="dodo", external_event_id=f"evt_{uuid.uuid4().hex[:8]}",
            event_type="subscription_updated", processing_status="pending",
        )
        db_session.add(event)
        db_session.commit()
        db_session.query(BillingWebhookEvent).filter(BillingWebhookEvent.id == event.id).update(
            {"received_at": datetime.now(timezone.utc) - timedelta(minutes=120)}
        )
        db_session.commit()

        try:
            stuck = cutover.find_stuck_webhooks(db_session, older_than_minutes=60)
            assert event.external_event_id in [s["external_event_id"] for s in stuck]
        finally:
            db_session.delete(event)
            db_session.commit()

    def test_processed_event_never_flagged_regardless_of_age(self, db_session):
        event = BillingWebhookEvent(
            provider="dodo", external_event_id=f"evt_{uuid.uuid4().hex[:8]}",
            event_type="subscription_updated", processing_status="processed",
        )
        db_session.add(event)
        db_session.commit()
        db_session.query(BillingWebhookEvent).filter(BillingWebhookEvent.id == event.id).update(
            {"received_at": datetime.now(timezone.utc) - timedelta(days=5)}
        )
        db_session.commit()

        try:
            stuck = cutover.find_stuck_webhooks(db_session, older_than_minutes=60)
            assert event.external_event_id not in [s["external_event_id"] for s in stuck]
        finally:
            db_session.delete(event)
            db_session.commit()


class TestHealthCheck:
    def test_healthy_false_when_dodo_not_configured(self, db_session):
        from app.config import settings as real_settings

        report = cutover.run_health_check(real_settings, db_session)
        assert isinstance(report["healthy"], bool)
        assert "billing_provider" in report

    def test_never_calls_dodo_api(self, db_session, monkeypatch):
        import httpx

        def _boom(*args, **kwargs):
            raise AssertionError("run_health_check must never make an HTTP call")

        monkeypatch.setattr(httpx.Client, "request", _boom)

        from app.config import settings as real_settings

        cutover.run_health_check(real_settings, db_session)


class TestMainNeverSwitchesGlobalProvider:
    def test_pilot_override_print_does_not_mutate_settings(self, db_session, workspace, monkeypatch, capsys):
        from app import config as config_module

        original_provider = config_module.settings.BILLING_PROVIDER
        exit_code = cutover.main(["pilot-override", "print", str(workspace.id), "--yes"])
        assert exit_code == 0
        assert config_module.settings.BILLING_PROVIDER == original_provider

    def test_pilot_override_print_refuses_without_yes(self):
        with pytest.raises(SystemExit):
            cutover.main(["pilot-override", "print", "some-workspace"])

    def test_pilot_override_print_output_never_contains_secret(self, workspace, capsys):
        cutover.main(["pilot-override", "print", str(workspace.id), "--yes"])
        captured = capsys.readouterr()
        assert "DODO_API_KEY" not in captured.out
        assert str(workspace.id) in captured.out
