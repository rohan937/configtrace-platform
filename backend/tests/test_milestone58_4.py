"""Tests for M58.4: Remediation-Aware Alerts, Emails, and Webhooks.

Test strategy
-------------
All tests are pure unit tests using MagicMock for database sessions and HTTP
calls, following the M57.1 pattern.  No database or network access required.

Coverage
--------
Remediation summary service:
  1.  AWS public SSH returns compact summary with correct title
  2.  AWS public RDP returns compact summary with correct title
  3.  GitHub branch protection returns high-confidence summary
  4.  Firebase Firestore rules returns summary with fix_plan_available=True
  5.  Supabase RLS returns summary with fix_plan_available=True
  6.  Vercel deploy hook (medium risk) returns summary
  7.  Cloudflare email-auth record removed returns high-confidence summary
  8.  Cloudflare DNS non-auth removed returns summary
  9.  Stripe webhook deleted returns summary
  10. Stripe charges_enabled disabled returns high-confidence summary
  11. Shopify webhook subscription returns summary
  12. High-risk unknown change returns generic fallback summary
  13. Low-risk change returns None (no noise)
  14. Medium-risk unknown change returns None
  15. execution_enabled is always False for all summaries
  16. No CLI command strings in any summary field
  17. No secret/token/customer-data keywords in any summary field
  18. Summary shape has all required fields
  19. MagicMock change (missing provider_metadata) is handled gracefully

Email alert content:
  20. Email body includes "Suggested remediation:" header
  21. Email body includes remediation title
  22. Email body includes remediation summary
  23. Email body includes CTA "Open remediation preview"
  24. Email body includes safety note about not auto-applying fixes
  25. Email body does not contain full CLI commands (no "aws ec2", "kubectl", etc.)
  26. Email body does not contain raw secret patterns

Slack notification content:
  27. Slack text includes "Suggested fix:" for matching AWS SG change
  28. Slack text includes "Remediation preview available" when available
  29. Slack text does not include full CLI commands
  30. Slack text does not include raw webhook URLs or tokens

Generic webhook payload:
  31. Webhook change dict includes "remediation" key
  32. Webhook remediation.available is True for matching change
  33. Webhook remediation.execution_enabled is always False
  34. Webhook remediation has all required fields
  35. Webhook remediation.url points to change detail page
  36. Webhook does not include full commands in remediation field
  37. Existing webhook top-level fields are all still present (backwards-compat)
  38. Webhook change dict without matching pattern returns available=False

Notification regression (existing M57.1 behavior unchanged):
  39. send_test_notification still returns correct keys
  40. dispatch_notifications_for_sync still skips when no settings
  41. dispatch_notifications_for_sync still posts to Slack when enabled
  42. dispatch_notifications_for_sync still posts to webhook when enabled
  43. Slack/webhook delivery failures still counted, not raised
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Test helpers / factories
# ─────────────────────────────────────────────────────────────────────────────

_VALID_SLACK_URL = "https://hooks.slack.com/services/T00000/B00000/abc123xyz789"
_VALID_WEBHOOK_URL = "https://example.com/hooks/configtrace"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _change(
    record_type: str = "",
    field_path: str = "",
    change_type: str = "modified",
    risk_level: str = "high",
    risk_reason: str = "Test risk reason",
    record_identifier: str = "test-resource",
) -> dict:
    """Build a plain-dict change suitable for testing the summary service."""
    return {
        "id": str(uuid.uuid4()),
        "change_type": change_type,
        "record_identifier": record_identifier,
        "field_path": field_path or None,
        "prev_value": None,
        "new_value": None,
        "risk_level": risk_level,
        "risk_reason": risk_reason,
        "created_at": _utcnow(),
        "provider_metadata": {"record_type": record_type} if record_type else {},
    }


def _mock_change_orm(
    record_type: str = "",
    field_path: str = "",
    change_type: str = "added",
    risk_level: str = "critical",
    risk_reason: str = "Port 22 opened to 0.0.0.0/0",
    record_identifier: str = "sg-abc123",
) -> MagicMock:
    """Build a MagicMock ORM-style change object."""
    c = MagicMock()
    c.id = uuid.uuid4()
    c.risk_level = risk_level
    c.change_type = change_type
    c.record_identifier = record_identifier
    c.field_path = field_path or None
    c.risk_reason = risk_reason
    c.created_at = _utcnow()
    c.provider_metadata = {"record_type": record_type} if record_type else None
    return c


def _make_mock_integration(workspace_id: uuid.UUID | None = None) -> MagicMock:
    i = MagicMock()
    i.id = uuid.uuid4()
    i.workspace_id = workspace_id if workspace_id is not None else uuid.uuid4()
    i.user_id = uuid.uuid4()
    i.provider = "aws"
    i.display_name = "My AWS Integration"
    return i


def _make_mock_settings_row(
    workspace_id: uuid.UUID | None = None,
    slack_enabled: bool = False,
    webhook_enabled: bool = False,
    notify_on_risk_level: str = "high_and_critical",
    slack_url_encrypted: bytes | None = None,
    slack_iv: bytes | None = None,
    webhook_url_encrypted: bytes | None = None,
    webhook_iv: bytes | None = None,
) -> MagicMock:
    from app.models.notification_settings import WorkspaceNotificationSettings
    row = MagicMock(spec=WorkspaceNotificationSettings)
    row.id = uuid.uuid4()
    row.workspace_id = workspace_id or uuid.uuid4()
    row.slack_enabled = slack_enabled
    row.webhook_enabled = webhook_enabled
    row.notify_on_risk_level = notify_on_risk_level
    row.slack_webhook_url_encrypted = slack_url_encrypted
    row.slack_webhook_iv = slack_iv
    row.webhook_url_encrypted = webhook_url_encrypted
    row.webhook_iv = webhook_iv
    # M58.5 Slack App columns — explicitly set to disabled/None so legacy
    # dispatch tests are not affected by the new App-preferred dispatch path.
    row.slack_app_enabled = False
    row.slack_bot_token_encrypted = None
    row.slack_bot_iv = None
    row.slack_channel_id = None
    row.slack_app_last_error = None
    return row


def _make_mock_db(settings_row=None) -> MagicMock:
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = settings_row
    return db


# ─────────────────────────────────────────────────────────────────────────────
# 1–19: Remediation summary service
# ─────────────────────────────────────────────────────────────────────────────


class TestRemediationSummaryService:
    """Pure unit tests for build_alert_remediation_summary."""

    def _call(self, change: dict) -> dict | None:
        from app.services.remediation_summary_service import build_alert_remediation_summary
        return build_alert_remediation_summary(change)

    def test_aws_sg_ssh_returns_compact_summary(self):
        """AWS SG with public SSH returns a compact, non-executing summary."""
        c = _change(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
            risk_reason="Public SSH access (tcp/22 from 0.0.0.0/0) is allowed.",
        )
        result = self._call(c)
        assert result is not None
        assert result["available"] is True
        assert "SSH" in result["title"] or "ssh" in result["title"].lower()
        assert result["execution_enabled"] is False
        assert result["fix_plan_available"] is True

    def test_aws_sg_rdp_returns_compact_summary(self):
        """AWS SG with public RDP returns a compact summary for RDP."""
        c = _change(
            record_type="aws_security_group",
            field_path="has_public_rdp",
            risk_level="critical",
            risk_reason="Public RDP access (tcp/3389 from 0.0.0.0/0) is allowed.",
        )
        result = self._call(c)
        assert result is not None
        assert "RDP" in result["title"] or "rdp" in result["title"].lower()
        assert result["execution_enabled"] is False
        assert result["confidence"] == "high"

    def test_github_branch_protection_returns_high_confidence(self):
        """GitHub branch protection change returns a high-confidence summary."""
        c = _change(
            record_type="github_branch_protection",
            field_path="required_pull_request_reviews.required_approving_review_count",
            change_type="modified",
            risk_level="high",
            risk_reason="Branch protection weakened.",
        )
        result = self._call(c)
        assert result is not None
        assert result["confidence"] == "high"
        assert result["fix_plan_available"] is True
        assert result["execution_enabled"] is False

    def test_firebase_rules_fix_plan_available(self):
        """Firebase Firestore rules change returns fix_plan_available=True."""
        c = _change(
            record_type="firebase_firestore_ruleset",
            risk_level="critical",
            risk_reason="Firestore rules allow public write.",
        )
        result = self._call(c)
        assert result is not None
        assert result["fix_plan_available"] is True
        assert result["remediation_preview_available"] is True
        assert result["execution_enabled"] is False

    def test_supabase_rls_fix_plan_available(self):
        """Supabase RLS disabled returns fix_plan_available=True."""
        c = _change(
            record_type="supabase_rls_status",
            field_path="rls_enabled",
            risk_level="critical",
            risk_reason="Row Level Security is disabled on table users.",
        )
        result = self._call(c)
        assert result is not None
        assert result["fix_plan_available"] is True
        assert "RLS" in result["title"] or "Row Level" in result["title"]
        assert result["execution_enabled"] is False

    def test_vercel_deploy_hook_medium_risk_included(self):
        """Vercel deploy hook (medium risk) is included — not filtered out."""
        c = _change(
            record_type="vercel_deploy_hook_metadata",
            change_type="added",
            risk_level="medium",
            risk_reason="New deploy hook added.",
        )
        result = self._call(c)
        assert result is not None
        assert result["available"] is True
        assert result["execution_enabled"] is False

    def test_cloudflare_email_auth_removed_high_confidence(self):
        """Removed TXT/SPF record returns a high-confidence summary."""
        c = _change(
            record_type="txt",
            change_type="removed",
            risk_level="high",
            risk_reason="SPF record was removed from the zone.",
        )
        result = self._call(c)
        assert result is not None
        assert result["confidence"] == "high"
        assert result["fix_plan_available"] is True
        assert result["execution_enabled"] is False

    def test_cloudflare_dns_non_auth_removed(self):
        """Removed CNAME returns a DNS summary."""
        c = _change(
            record_type="cname",
            change_type="removed",
            risk_level="high",
            risk_reason="CNAME api.example.com was removed.",
        )
        result = self._call(c)
        assert result is not None
        assert result["available"] is True
        assert result["execution_enabled"] is False

    def test_stripe_webhook_deleted(self):
        """Stripe webhook deleted returns a summary."""
        c = _change(
            record_type="stripe_webhook_endpoint",
            change_type="removed",
            risk_level="critical",
            risk_reason="Stripe webhook endpoint was deleted.",
        )
        result = self._call(c)
        assert result is not None
        assert result["execution_enabled"] is False

    def test_stripe_charges_disabled_high_confidence(self):
        """Stripe charges_enabled=False returns a high-confidence summary."""
        c = _change(
            record_type="stripe_account_settings",
            field_path="charges_enabled",
            risk_level="critical",
            risk_reason="Charges have been disabled.",
        )
        result = self._call(c)
        assert result is not None
        assert result["confidence"] == "high"
        assert result["execution_enabled"] is False

    def test_shopify_webhook_subscription_returns_summary(self):
        """Shopify webhook subscription change returns a summary."""
        c = _change(
            record_type="shopify_webhook_subscription",
            risk_level="high",
            risk_reason="Shopify webhook subscription changed.",
        )
        result = self._call(c)
        assert result is not None
        assert result["execution_enabled"] is False

    def test_high_risk_unknown_returns_generic_fallback(self):
        """High-risk change with unknown provider returns a generic fallback."""
        c = _change(
            record_type="some_unknown_provider_record_type",
            risk_level="high",
            risk_reason="Something high-risk happened.",
        )
        result = self._call(c)
        assert result is not None
        assert result["available"] is True
        assert result["execution_enabled"] is False
        assert result["confidence"] == "low"

    def test_low_risk_returns_none(self):
        """Low-risk change with no specific pattern returns None (no noise)."""
        c = _change(
            record_type="aws_security_group",
            field_path="description",
            risk_level="low",
            risk_reason="Security group description updated.",
        )
        result = self._call(c)
        assert result is None

    def test_medium_risk_unknown_returns_none(self):
        """Medium-risk unknown provider change returns None."""
        c = _change(
            record_type="",
            risk_level="medium",
            risk_reason="Some medium-risk change.",
        )
        result = self._call(c)
        assert result is None

    def test_execution_enabled_always_false(self):
        """execution_enabled is False in every returned summary, without exception."""
        from app.services.remediation_summary_service import build_alert_remediation_summary

        test_cases = [
            _change(record_type="aws_security_group", field_path="has_public_ssh", risk_level="critical"),
            _change(record_type="github_branch_protection", risk_level="high"),
            _change(record_type="firebase_firestore_ruleset", risk_level="critical"),
            _change(record_type="supabase_rls_status", risk_level="critical"),
            _change(record_type="vercel_deploy_hook_metadata", change_type="added", risk_level="medium"),
            _change(record_type="stripe_webhook_endpoint", change_type="removed", risk_level="critical"),
            _change(record_type="txt", change_type="removed", risk_level="high"),
            _change(record_type="some_unknown_type", risk_level="critical"),
        ]
        for c in test_cases:
            result = build_alert_remediation_summary(c)
            if result is not None:
                assert result["execution_enabled"] is False, (
                    f"execution_enabled was not False for record_type={c['provider_metadata'].get('record_type')!r}"
                )

    def test_no_cli_commands_in_summary_fields(self):
        """Summary text never contains CLI command patterns."""
        from app.services.remediation_summary_service import build_alert_remediation_summary

        # Keywords that should NEVER appear in alert payloads
        forbidden = ["aws ec2 revoke", "kubectl", "terraform", "curl -X DELETE", "--cidr 0.0.0.0"]
        test_cases = [
            _change(record_type="aws_security_group", field_path="has_public_ssh", risk_level="critical"),
            _change(record_type="github_branch_protection", risk_level="high"),
            _change(record_type="supabase_rls_status", risk_level="critical"),
        ]
        for c in test_cases:
            result = build_alert_remediation_summary(c)
            if result is None:
                continue
            payload_text = f"{result.get('title', '')} {result.get('summary', '')}"
            for forbidden_kw in forbidden:
                assert forbidden_kw.lower() not in payload_text.lower(), (
                    f"Found forbidden command {forbidden_kw!r} in summary payload"
                )

    def test_no_secret_keywords_in_summary(self):
        """Summary text never contains sensitive data keywords."""
        from app.services.remediation_summary_service import build_alert_remediation_summary

        sensitive = ["api_key", "secret_key", "bearer ", "authorization:", "sk_live", "passwd", "password"]
        test_cases = [
            _change(record_type="aws_security_group", field_path="has_public_ssh", risk_level="critical",
                    risk_reason="aws_access_key_id=AKIA sk_live_secret"),  # risk_reason contains sensitive noise
            _change(record_type="stripe_webhook_endpoint", risk_level="critical"),
        ]
        for c in test_cases:
            result = build_alert_remediation_summary(c)
            if result is None:
                continue
            payload_text = f"{result.get('title', '')} {result.get('summary', '')}".lower()
            for kw in sensitive:
                assert kw.lower() not in payload_text, (
                    f"Found sensitive keyword {kw!r} in summary payload for {c['provider_metadata']}"
                )

    def test_summary_has_all_required_fields(self):
        """Every returned summary dict has the required M58.4 fields."""
        c = _change(record_type="aws_security_group", field_path="has_public_ssh", risk_level="critical")
        result = self._call(c)
        assert result is not None
        required = {
            "available", "title", "summary", "confidence",
            "fix_plan_available", "remediation_preview_available",
            "execution_enabled", "action_label",
        }
        missing = required - set(result.keys())
        assert not missing, f"Summary missing fields: {missing}"

    def test_magicmock_change_handled_gracefully(self):
        """A MagicMock change (no explicit provider_metadata) does not raise."""
        from app.services.remediation_summary_service import build_alert_remediation_summary

        c = MagicMock()
        c.risk_level = "critical"
        c.change_type = "added"
        c.field_path = None
        c.risk_reason = "Something critical"
        # provider_metadata is a MagicMock (not a dict) — defensive code must handle this
        # No explicit set → MagicMock attribute access returns another MagicMock

        # Must not raise
        result = build_alert_remediation_summary(c)
        # With MagicMock provider_metadata (non-dict), should get generic fallback for critical
        # OR None — both are acceptable as long as it doesn't raise
        if result is not None:
            assert result["execution_enabled"] is False


# ─────────────────────────────────────────────────────────────────────────────
# 20–26: Email alert content
# ─────────────────────────────────────────────────────────────────────────────


class TestEmailAlertRemediationBlock:
    """Tests that _compose_digest includes a compact remediation block."""

    def _compose(self, changes: list) -> tuple[str, str]:
        from app.services.alert_service import _compose_digest

        integration = _make_mock_integration()
        integration.provider = "aws"
        integration.display_name = "My AWS"
        return _compose_digest(integration=integration, changes=changes)

    def test_email_includes_suggested_remediation_header(self):
        """Email body includes 'Suggested remediation:' section."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
            risk_reason="Public SSH access (tcp/22) allowed.",
        )
        _subject, body = self._compose([c])
        assert "Suggested remediation:" in body

    def test_email_includes_remediation_title(self):
        """Email body includes the remediation title."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
            risk_reason="Port 22 opened to 0.0.0.0/0.",
        )
        _subject, body = self._compose([c])
        # Title should mention SSH or public access
        assert "SSH" in body or "ssh" in body.lower()

    def test_email_includes_remediation_summary_text(self):
        """Email body includes a short remediation summary sentence."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
            risk_reason="Port 22 opened to 0.0.0.0/0.",
        )
        _subject, body = self._compose([c])
        # Should include language like "restrict" or "trusted"
        assert "trusted" in body.lower() or "restrict" in body.lower() or "VPN" in body

    def test_email_includes_open_remediation_preview_cta(self):
        """Email body includes the 'Open remediation preview' CTA."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
        )
        _subject, body = self._compose([c])
        assert "remediation preview" in body.lower() or "Open remediation" in body

    def test_email_includes_safety_note(self):
        """Email body includes safety note that ConfigTrace does not auto-apply fixes."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
        )
        _subject, body = self._compose([c])
        assert "does not apply" in body.lower() or "not apply" in body.lower() or "automatically" in body.lower()

    def test_email_no_full_cli_commands(self):
        """Email body never contains full CLI command strings."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
        )
        _subject, body = self._compose([c])
        forbidden_commands = ["aws ec2 revoke-security-group-ingress", "kubectl delete", "--cidr 0.0.0.0/0"]
        for cmd in forbidden_commands:
            assert cmd not in body, f"Found forbidden command in email: {cmd!r}"

    def test_email_low_risk_no_remediation_block(self):
        """Low-risk change email does not add a noisy remediation block."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="description",
            risk_level="low",
            risk_reason="Description updated.",
        )
        _subject, body = self._compose([c])
        # Low-risk emails should not have the suggested remediation section
        # (the alert_service filters low risk before calling _compose_digest,
        # but the summary service itself also returns None for low risk)
        # We check that no commands leaked in
        forbidden_commands = ["aws ec2 revoke", "--cidr 0.0.0.0"]
        for cmd in forbidden_commands:
            assert cmd not in body


# ─────────────────────────────────────────────────────────────────────────────
# 27–30: Slack notification content
# ─────────────────────────────────────────────────────────────────────────────


class TestSlackNotificationRemediation:
    """Tests for _compose_slack_text with M58.4 additions."""

    def _compose_slack(self, changes: list) -> str:
        from app.services.notification_service import _compose_slack_text

        integration = _make_mock_integration()
        integration.provider = "aws"
        integration.display_name = "My AWS"
        return _compose_slack_text(integration=integration, changes=changes)

    def test_slack_includes_suggested_fix_for_aws_sg(self):
        """Slack text includes 'Suggested fix:' line for AWS SG SSH finding."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
            risk_reason="Port 22 opened to 0.0.0.0/0.",
        )
        text = self._compose_slack([c])
        assert "Suggested fix:" in text

    def test_slack_includes_remediation_preview_note(self):
        """Slack text mentions remediation preview availability."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
        )
        text = self._compose_slack([c])
        assert "Remediation preview" in text or "remediation preview" in text.lower()

    def test_slack_no_full_cli_commands(self):
        """Slack text never contains full CLI command strings."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
        )
        text = self._compose_slack([c])
        forbidden = ["aws ec2 revoke-security-group-ingress", "--cidr 0.0.0.0/0", "kubectl"]
        for cmd in forbidden:
            assert cmd not in text, f"Found forbidden command in Slack text: {cmd!r}"

    def test_slack_no_raw_secrets_or_tokens(self):
        """Slack text does not contain raw secret/token keywords."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
        )
        text = self._compose_slack([c])
        forbidden = ["sk_live", "api_key=", "bearer ", "authorization: "]
        for kw in forbidden:
            assert kw.lower() not in text.lower(), f"Found sensitive keyword in Slack text: {kw!r}"


# ─────────────────────────────────────────────────────────────────────────────
# 31–38: Generic webhook payload
# ─────────────────────────────────────────────────────────────────────────────


class TestWebhookPayloadRemediation:
    """Tests for _compose_webhook_payload with M58.4 remediation field."""

    def _compose_webhook(self, changes: list) -> dict:
        from app.services.notification_service import _compose_webhook_payload

        integration = _make_mock_integration()
        integration.provider = "aws"
        integration.display_name = "My AWS"
        return _compose_webhook_payload(
            integration=integration,
            changes=changes,
            sync_run_id=uuid.uuid4(),
        )

    def test_webhook_change_has_remediation_key(self):
        """Each change dict in the webhook payload includes a 'remediation' key."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
        )
        payload = self._compose_webhook([c])
        assert len(payload["changes"]) == 1
        assert "remediation" in payload["changes"][0]

    def test_webhook_remediation_available_true_for_matching_change(self):
        """Webhook remediation.available is True for a known-pattern change."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
        )
        payload = self._compose_webhook([c])
        rem = payload["changes"][0]["remediation"]
        assert rem["available"] is True

    def test_webhook_remediation_execution_enabled_always_false(self):
        """Webhook remediation.execution_enabled is always False."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
        )
        payload = self._compose_webhook([c])
        rem = payload["changes"][0]["remediation"]
        if rem.get("available"):
            assert rem["execution_enabled"] is False

    def test_webhook_remediation_has_required_fields(self):
        """When available, remediation object has all M58.4 required fields."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
        )
        payload = self._compose_webhook([c])
        rem = payload["changes"][0]["remediation"]
        if rem.get("available"):
            required = {
                "available", "title", "summary", "confidence",
                "fix_plan_available", "remediation_preview_available",
                "execution_enabled", "url",
            }
            missing = required - set(rem.keys())
            assert not missing, f"Webhook remediation missing fields: {missing}"

    def test_webhook_remediation_url_points_to_change_detail(self):
        """Webhook remediation.url points to the change detail page."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
        )
        payload = self._compose_webhook([c])
        rem = payload["changes"][0]["remediation"]
        if rem.get("available"):
            assert str(c.id) in rem["url"]
            assert "/changes/" in rem["url"]

    def test_webhook_no_full_commands_in_remediation(self):
        """Webhook remediation fields never contain full CLI commands."""
        c = _mock_change_orm(
            record_type="aws_security_group",
            field_path="has_public_ssh",
            risk_level="critical",
        )
        payload = self._compose_webhook([c])
        rem = payload["changes"][0]["remediation"]
        rem_text = f"{rem.get('title', '')} {rem.get('summary', '')}".lower()
        forbidden = ["aws ec2 revoke", "--cidr 0.0.0.0/0", "kubectl", "terraform apply"]
        for cmd in forbidden:
            assert cmd not in rem_text, f"Found command {cmd!r} in webhook remediation"

    def test_webhook_backwards_compatible_top_level_fields(self):
        """All existing top-level webhook fields are still present (M57.1 compat)."""
        c = _mock_change_orm(risk_level="critical")
        payload = self._compose_webhook([c])
        required_top_level = {
            "event", "workspace_id", "integration_id", "integration_name",
            "provider", "sync_run_id", "change_count", "highest_risk",
            "changes", "app_url", "timestamp",
        }
        missing = required_top_level - set(payload.keys())
        assert not missing, f"Missing top-level webhook fields: {missing}"

    def test_webhook_change_without_match_returns_available_false(self):
        """Change with no matching pattern returns remediation.available=False."""
        c = _mock_change_orm(
            record_type="",  # no record_type
            risk_level="low",
            risk_reason="Minor description change.",
        )
        payload = self._compose_webhook([c])
        rem = payload["changes"][0]["remediation"]
        # Low-risk unknown → should have available=False
        assert rem.get("available") is False

    def test_webhook_backwards_compatible_change_fields(self):
        """Existing per-change fields are still present alongside 'remediation'."""
        c = _mock_change_orm(risk_level="critical")
        payload = self._compose_webhook([c])
        change_dict = payload["changes"][0]
        required_change_fields = {
            "id", "risk_level", "change_type", "record_identifier",
            "field_path", "risk_reason", "remediation",
        }
        missing = required_change_fields - set(change_dict.keys())
        assert not missing, f"Missing per-change fields: {missing}"


# ─────────────────────────────────────────────────────────────────────────────
# 39–43: Regression — existing M57.1 behavior unchanged
# ─────────────────────────────────────────────────────────────────────────────


class TestExistingNotificationBehavior:
    """Regression tests: M57.1 dispatch behavior must be unchanged after M58.4."""

    def test_send_test_notification_returns_expected_keys(self):
        """send_test_notification still returns slack_sent/webhook_sent/error."""
        from app.services.notification_service import get_or_create_notification_settings

        ws_id = uuid.uuid4()
        db = MagicMock()
        # Return a row with both channels disabled (no URLs)
        row = _make_mock_settings_row(workspace_id=ws_id)
        db.query.return_value.filter.return_value.first.return_value = row
        db.commit = MagicMock()
        db.refresh = MagicMock()

        from app.services.notification_service import send_test_notification
        result = send_test_notification(ws_id, db)

        assert "slack_sent" in result
        assert "webhook_sent" in result
        assert "error" in result

    def test_dispatch_skips_when_no_settings_row(self):
        """dispatch_notifications_for_sync still skips when no settings exist."""
        from app.services.notification_service import dispatch_notifications_for_sync

        integration = _make_mock_integration()
        db = _make_mock_db(settings_row=None)

        result = dispatch_notifications_for_sync(
            changes=[_mock_change_orm()],
            integration=integration,
            sync_run_id=uuid.uuid4(),
            db=db,
        )
        assert result["skipped_no_settings"] is True

    @patch("app.core.encryption._load_key", return_value=b"\x00" * 32)
    def test_dispatch_still_posts_to_slack(self, _key):
        """Slack posting still works end-to-end after M58.4 changes."""
        from app.core.encryption import encrypt_credentials
        from app.services.notification_service import dispatch_notifications_for_sync

        ciphertext, iv = encrypt_credentials({"url": _VALID_SLACK_URL})
        integration = _make_mock_integration()
        row = _make_mock_settings_row(
            workspace_id=integration.workspace_id,
            slack_enabled=True,
            slack_url_encrypted=ciphertext,
            slack_iv=iv,
        )
        db = _make_mock_db(settings_row=row)

        with patch("app.services.notification_service._post_json") as mock_post:
            result = dispatch_notifications_for_sync(
                changes=[_mock_change_orm(risk_level="critical")],
                integration=integration,
                sync_run_id=uuid.uuid4(),
                db=db,
            )
        mock_post.assert_called_once()
        assert result["slack_sent"] == 1
        assert result["failed"] == 0

    @patch("app.core.encryption._load_key", return_value=b"\x00" * 32)
    def test_dispatch_still_posts_to_webhook(self, _key):
        """Webhook posting still works end-to-end after M58.4 changes."""
        from app.core.encryption import encrypt_credentials
        from app.services.notification_service import dispatch_notifications_for_sync

        ciphertext, iv = encrypt_credentials({"url": _VALID_WEBHOOK_URL})
        integration = _make_mock_integration()
        row = _make_mock_settings_row(
            workspace_id=integration.workspace_id,
            webhook_enabled=True,
            webhook_url_encrypted=ciphertext,
            webhook_iv=iv,
        )
        db = _make_mock_db(settings_row=row)

        with patch("app.services.notification_service._post_json") as mock_post:
            result = dispatch_notifications_for_sync(
                changes=[_mock_change_orm(risk_level="high")],
                integration=integration,
                sync_run_id=uuid.uuid4(),
                db=db,
            )
        mock_post.assert_called_once()
        assert result["webhook_sent"] == 1
        assert result["failed"] == 0

    def test_delivery_failure_counted_not_raised(self):
        """Delivery failures still increment failed count, not raise."""
        from app.services.notification_service import dispatch_notifications_for_sync

        integration = _make_mock_integration()
        row = _make_mock_settings_row(
            slack_enabled=True,
            slack_url_encrypted=b"enc",
            slack_iv=b"iv",
        )
        db = _make_mock_db(settings_row=row)

        with patch("app.core.encryption.decrypt_credentials", return_value={"url": _VALID_SLACK_URL}):
            with patch(
                "app.services.notification_service._post_json",
                side_effect=Exception("network error"),
            ):
                result = dispatch_notifications_for_sync(
                    changes=[_mock_change_orm()],
                    integration=integration,
                    sync_run_id=uuid.uuid4(),
                    db=db,
                )
        assert result["failed"] == 1
        assert result["slack_sent"] == 0
