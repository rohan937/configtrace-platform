"""Test suite for Milestone 58.6 — Slack Interactive Alert Actions.

Covers:
  1.  verify_request_signature: valid signature passes
  2.  verify_request_signature: wrong secret fails
  3.  verify_request_signature: stale timestamp (>5 min) rejected
  4.  verify_request_signature: future timestamp (>5 min) rejected
  5.  verify_request_signature: non-integer timestamp fails
  6.  handle_action: URL buttons return ephemeral "Opening..." (no DB)
  7.  handle_action: missing actions list returns ephemeral error
  8.  handle_action: unknown team_id returns ephemeral workspace error
  9.  handle_action: malformed action value returns ephemeral error
  10. handle_action: acknowledge action returns success message
  11. handle_action: snooze action returns success message
  12. handle_action: unknown action_id returns ephemeral
  13. handle_action: RuntimeError from service is surfaced safely
  14. handle_action: unexpected exceptions are caught and return ephemeral
  15. compose_alert_blocks: contains 4 action buttons with correct action_ids
  16. compose_alert_blocks: remediation block included when available (fail-open)
  17. compose_alert_blocks: remediation block omitted on error (fail-open)
  18. compose_multi_alert_blocks: has no action buttons for 2-5 changes
  19. compose_multi_alert_blocks: all changes listed with View links
  20. dispatch_alert_message: 1 change → interactive blocks
  21. dispatch_alert_message: 2-5 changes → multi-change blocks
  22. dispatch_alert_message: >5 changes → plain text fallback
  23. POST /slack/actions: missing headers → 403
  24. POST /slack/actions: invalid signature → 403
  25. POST /slack/actions: valid signature → 200 with ephemeral body
  26. get_workspace_by_team_id: returns None when not found
  27. get_change_for_workspace: returns None on bad UUID
  28. _get_actor_user_id: prefers installer over change.user_id
  29. acknowledge_change_from_slack: change not found raises RuntimeError
  30. snooze_change_from_slack: calls snooze_change with 24h duration
"""

from __future__ import annotations

import hashlib
import hmac as hmac_lib
import json
import time
import urllib.parse
import uuid
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ── Shared test fixtures ───────────────────────────────────────────────────────

_WORKSPACE_ID = str(uuid.uuid4())
_USER_ID = str(uuid.uuid4())
_INSTALLER_USER_ID = uuid.uuid4()
_TEAM_ID = "T98765432"
_CHANNEL_ID = "C01234567"
_CHANGE_ID = str(uuid.uuid4())
_SLACK_USER_ID = "USLACKUSER"
_SIGNING_SECRET = "test-slack-signing-secret-for-m58-6-tests"
_FAKE_BOT_TOKEN = "xoxb-fake-test-token-m58-6"


def _make_valid_signature(signing_secret: str, timestamp: str, body: str) -> str:
    """Compute a valid Slack HMAC-SHA256 request signature."""
    base_string = f"v0:{timestamp}:{body}"
    mac = hmac_lib.new(
        signing_secret.encode("utf-8"),
        base_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"v0={mac}"


def _make_action_payload(
    action_id: str,
    action_value: str,
    team_id: str = _TEAM_ID,
    slack_user_id: str = _SLACK_USER_ID,
) -> dict:
    """Build a minimal Slack interactive action payload dict."""
    return {
        "type": "block_actions",
        "team": {"id": team_id, "domain": "example"},
        "user": {"id": slack_user_id, "username": "testuser"},
        "actions": [
            {
                "action_id": action_id,
                "value": action_value,
                "type": "button",
            }
        ],
    }


def _make_settings_row(**kwargs) -> MagicMock:
    """Build a MagicMock WorkspaceNotificationSettings row with sane defaults."""
    row = MagicMock()
    row.workspace_id = uuid.UUID(_WORKSPACE_ID)
    row.slack_app_enabled = True
    row.slack_bot_token_encrypted = b"enc"
    row.slack_bot_iv = b"iv"
    row.slack_team_id = _TEAM_ID
    row.slack_channel_id = _CHANNEL_ID
    row.slack_installed_by_user_id = _INSTALLER_USER_ID
    row.slack_app_last_error = None
    # Legacy webhook columns (not involved in M58.6)
    row.slack_enabled = False
    row.slack_webhook_url_encrypted = None
    row.slack_webhook_iv = None
    row.webhook_enabled = False
    row.webhook_url_encrypted = None
    row.webhook_iv = None
    for k, v in kwargs.items():
        setattr(row, k, v)
    return row


def _make_change(change_id: str = _CHANGE_ID, risk_level: str = "high") -> MagicMock:
    """Build a MagicMock Change row."""
    c = MagicMock()
    c.id = uuid.UUID(change_id)
    c.risk_level = risk_level
    c.risk_reason = "Security group allows unrestricted SSH access."
    c.record_identifier = "sg-0abc123def456789"
    c.field_path = "IpPermissions[0].IpRanges[0].CidrIp"
    c.user_id = uuid.uuid4()
    return c


# ═══════════════════════════════════════════════════════════════════════════════
# 1–5: Signature verification
# ═══════════════════════════════════════════════════════════════════════════════

class TestVerifyRequestSignature:
    """Tests for verify_request_signature (HMAC-SHA256 + replay window)."""

    def test_valid_signature_passes(self):
        """A correctly signed, fresh request is accepted."""
        from app.services.slack_service import verify_request_signature

        timestamp = str(int(time.time()))
        body = "payload=%7B%22type%22%3A%22block_actions%22%7D"
        sig = _make_valid_signature(_SIGNING_SECRET, timestamp, body)

        assert verify_request_signature(_SIGNING_SECRET, timestamp, body.encode(), sig) is True

    def test_wrong_secret_fails(self):
        """A request signed with a different secret is rejected."""
        from app.services.slack_service import verify_request_signature

        timestamp = str(int(time.time()))
        body = "payload=something"
        sig = _make_valid_signature("wrong-secret", timestamp, body)

        assert verify_request_signature(_SIGNING_SECRET, timestamp, body.encode(), sig) is False

    def test_stale_timestamp_rejected(self):
        """Timestamps older than 5 minutes are rejected (replay protection)."""
        from app.services.slack_service import verify_request_signature

        stale_ts = str(int(time.time()) - 310)  # 5m10s ago
        body = "payload=test"
        sig = _make_valid_signature(_SIGNING_SECRET, stale_ts, body)

        assert verify_request_signature(_SIGNING_SECRET, stale_ts, body.encode(), sig) is False

    def test_future_timestamp_rejected(self):
        """Timestamps more than 5 minutes in the future are rejected."""
        from app.services.slack_service import verify_request_signature

        future_ts = str(int(time.time()) + 310)
        body = "payload=test"
        sig = _make_valid_signature(_SIGNING_SECRET, future_ts, body)

        assert verify_request_signature(_SIGNING_SECRET, future_ts, body.encode(), sig) is False

    def test_non_integer_timestamp_fails(self):
        """A non-integer timestamp value is rejected gracefully."""
        from app.services.slack_service import verify_request_signature

        body = "payload=test"
        sig = "v0=deadbeef"

        assert verify_request_signature(_SIGNING_SECRET, "not-a-number", body.encode(), sig) is False


# ═══════════════════════════════════════════════════════════════════════════════
# 6–9: handle_action — payload parsing and routing edge cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestHandleActionEdgeCases:
    """Tests for handle_action routing and error handling."""

    def test_url_button_open_change_returns_ephemeral(self):
        """Open Change (URL button) returns ephemeral without touching DB."""
        from app.services.slack_service import handle_action, ACTION_OPEN_CHANGE

        payload = _make_action_payload(
            action_id=ACTION_OPEN_CHANGE,
            action_value="",  # URL buttons have no value
        )
        db = MagicMock()
        result = handle_action(payload, db)

        assert result["response_type"] == "ephemeral"
        assert "Opening" in result["text"]
        db.query.assert_not_called()

    def test_url_button_view_remediation_returns_ephemeral(self):
        """View Remediation (URL button) returns ephemeral without touching DB."""
        from app.services.slack_service import handle_action, ACTION_VIEW_REMEDIATION

        payload = _make_action_payload(
            action_id=ACTION_VIEW_REMEDIATION,
            action_value="",
        )
        db = MagicMock()
        result = handle_action(payload, db)

        assert result["response_type"] == "ephemeral"
        assert "Opening" in result["text"]

    def test_missing_actions_list_returns_ephemeral(self):
        """Payload with empty actions list is handled gracefully."""
        from app.services.slack_service import handle_action

        payload = {"type": "block_actions", "team": {"id": _TEAM_ID}, "user": {"id": "U123"}, "actions": []}
        db = MagicMock()
        result = handle_action(payload, db)

        assert result["response_type"] == "ephemeral"
        assert "No action" in result["text"]

    def test_unknown_team_id_returns_ephemeral(self):
        """A team_id with no installed workspace returns an error ephemeral."""
        from app.services.slack_service import handle_action, ACTION_ACKNOWLEDGE

        action_value = json.dumps({"change_id": _CHANGE_ID})
        payload = _make_action_payload(
            action_id=ACTION_ACKNOWLEDGE,
            action_value=action_value,
            team_id="T_UNKNOWN",
        )
        db = MagicMock()

        with patch("app.services.slack_service.get_workspace_by_team_id", return_value=None):
            result = handle_action(payload, db)

        assert result["response_type"] == "ephemeral"
        assert "no longer be installed" in result["text"] or "could not complete" in result["text"].lower()

    def test_malformed_action_value_returns_ephemeral(self):
        """Malformed JSON in action value returns an error ephemeral."""
        from app.services.slack_service import handle_action, ACTION_ACKNOWLEDGE

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        payload = _make_action_payload(
            action_id=ACTION_ACKNOWLEDGE,
            action_value="not-valid-json",
        )
        db = MagicMock()

        with patch("app.services.slack_service.get_workspace_by_team_id", return_value=workspace_id):
            result = handle_action(payload, db)

        assert result["response_type"] == "ephemeral"
        assert "complete" in result["text"].lower() or "open" in result["text"].lower()


# ═══════════════════════════════════════════════════════════════════════════════
# 10–14: handle_action — action routing
# ═══════════════════════════════════════════════════════════════════════════════

class TestHandleActionRouting:
    """Tests for handle_action routing to acknowledge/snooze handlers."""

    def test_acknowledge_action_returns_success(self):
        """Acknowledge button routes to acknowledge_change_from_slack."""
        from app.services.slack_service import handle_action, ACTION_ACKNOWLEDGE

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        action_value = json.dumps({"change_id": _CHANGE_ID})
        payload = _make_action_payload(ACTION_ACKNOWLEDGE, action_value)
        db = MagicMock()

        with patch("app.services.slack_service.get_workspace_by_team_id", return_value=workspace_id):
            with patch(
                "app.services.slack_service.acknowledge_change_from_slack",
                return_value="✓ Acknowledged in ConfigTrace.",
            ) as mock_ack:
                result = handle_action(payload, db)

        assert result["response_type"] == "ephemeral"
        assert "Acknowledged" in result["text"]
        mock_ack.assert_called_once_with(_CHANGE_ID, workspace_id, _SLACK_USER_ID, db)

    def test_snooze_action_returns_success(self):
        """Snooze 24h button routes to snooze_change_from_slack."""
        from app.services.slack_service import handle_action, ACTION_SNOOZE_24H

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        action_value = json.dumps({"change_id": _CHANGE_ID})
        payload = _make_action_payload(ACTION_SNOOZE_24H, action_value)
        db = MagicMock()

        with patch("app.services.slack_service.get_workspace_by_team_id", return_value=workspace_id):
            with patch(
                "app.services.slack_service.snooze_change_from_slack",
                return_value="⏸ Snoozed for 24 hours in ConfigTrace.",
            ) as mock_snooze:
                result = handle_action(payload, db)

        assert result["response_type"] == "ephemeral"
        assert "Snoozed" in result["text"]
        mock_snooze.assert_called_once_with(
            _CHANGE_ID, workspace_id, _SLACK_USER_ID, db, hours=24
        )

    def test_unknown_action_id_returns_ephemeral(self):
        """An unrecognised action_id returns a safe ephemeral message."""
        from app.services.slack_service import handle_action

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        action_value = json.dumps({"change_id": _CHANGE_ID})
        payload = _make_action_payload("configtrace_unknown_action", action_value)
        db = MagicMock()

        with patch("app.services.slack_service.get_workspace_by_team_id", return_value=workspace_id):
            result = handle_action(payload, db)

        assert result["response_type"] == "ephemeral"
        assert "Unknown action" in result["text"] or "open" in result["text"].lower()

    def test_runtime_error_from_service_surfaced_as_ephemeral(self):
        """RuntimeError from the action handler is returned as an ephemeral, not re-raised."""
        from app.services.slack_service import handle_action, ACTION_ACKNOWLEDGE

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        action_value = json.dumps({"change_id": _CHANGE_ID})
        payload = _make_action_payload(ACTION_ACKNOWLEDGE, action_value)
        db = MagicMock()

        with patch("app.services.slack_service.get_workspace_by_team_id", return_value=workspace_id):
            with patch(
                "app.services.slack_service.acknowledge_change_from_slack",
                side_effect=RuntimeError("Change not found or does not belong to this workspace."),
            ):
                result = handle_action(payload, db)

        assert result["response_type"] == "ephemeral"
        assert "ConfigTrace could not complete" in result["text"]

    def test_unexpected_exception_never_raises(self):
        """Unexpected exceptions inside handle_action are caught — never 500."""
        from app.services.slack_service import handle_action, ACTION_ACKNOWLEDGE

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        action_value = json.dumps({"change_id": _CHANGE_ID})
        payload = _make_action_payload(ACTION_ACKNOWLEDGE, action_value)
        db = MagicMock()

        with patch(
            "app.services.slack_service.get_workspace_by_team_id",
            side_effect=Exception("Unexpected DB explosion"),
        ):
            # Must not raise.
            result = handle_action(payload, db)

        assert result["response_type"] == "ephemeral"
        assert "unexpected error" in result["text"].lower() or "open" in result["text"].lower()


# ═══════════════════════════════════════════════════════════════════════════════
# 15–19: Block Kit message composition
# ═══════════════════════════════════════════════════════════════════════════════

class TestComposeAlertBlocks:
    """Tests for compose_alert_blocks (single change, interactive)."""

    def _make_change_dict(self, **kwargs) -> dict:
        defaults = {
            "id": str(uuid.uuid4()),
            "risk_level": "critical",
            "risk_reason": "Public read access enabled.",
            "record_identifier": "my-s3-bucket",
            "field_path": "PublicAccessBlockConfiguration.BlockPublicAcls",
        }
        defaults.update(kwargs)
        return defaults

    def test_contains_four_action_buttons(self):
        """compose_alert_blocks produces exactly 4 buttons in an actions block."""
        from app.services.slack_service import (
            compose_alert_blocks,
            ACTION_ACKNOWLEDGE,
            ACTION_SNOOZE_24H,
            ACTION_OPEN_CHANGE,
            ACTION_VIEW_REMEDIATION,
        )

        change = self._make_change_dict()
        # build_alert_remediation_summary is imported locally inside compose_alert_blocks;
        # patch at the source module.
        with patch(
            "app.services.remediation_summary_service.build_alert_remediation_summary",
            return_value=None,
        ):
            blocks = compose_alert_blocks(change, "My AWS", "aws", "https://app.ct.org")

        actions_blocks = [b for b in blocks if b.get("type") == "actions"]
        assert len(actions_blocks) == 1, "Expected exactly one actions block"

        elements = actions_blocks[0]["elements"]
        assert len(elements) == 4, f"Expected 4 buttons, got {len(elements)}"

        action_ids = {e["action_id"] for e in elements}
        assert ACTION_ACKNOWLEDGE in action_ids
        assert ACTION_SNOOZE_24H in action_ids
        assert ACTION_OPEN_CHANGE in action_ids
        assert ACTION_VIEW_REMEDIATION in action_ids

    def test_action_values_contain_change_id(self):
        """Stateful buttons (Acknowledge, Snooze) embed change_id in value."""
        from app.services.slack_service import (
            compose_alert_blocks,
            ACTION_ACKNOWLEDGE,
            ACTION_SNOOZE_24H,
        )

        change = self._make_change_dict()
        change_id = change["id"]

        with patch(
            "app.services.remediation_summary_service.build_alert_remediation_summary",
            return_value=None,
        ):
            blocks = compose_alert_blocks(change, "Test", "aws", "https://app.ct.org")

        actions_blocks = [b for b in blocks if b.get("type") == "actions"]
        elements = {e["action_id"]: e for e in actions_blocks[0]["elements"]}

        for action_id in (ACTION_ACKNOWLEDGE, ACTION_SNOOZE_24H):
            value = json.loads(elements[action_id]["value"])
            assert value["change_id"] == change_id, f"Missing change_id in {action_id} value"

    def test_url_buttons_link_to_correct_urls(self):
        """Open Change + View Remediation buttons link to the correct deep URLs."""
        from app.services.slack_service import (
            compose_alert_blocks,
            ACTION_OPEN_CHANGE,
            ACTION_VIEW_REMEDIATION,
        )

        change = self._make_change_dict()
        change_id = change["id"]
        base_url = "https://app.configtrace.org"

        with patch(
            "app.services.remediation_summary_service.build_alert_remediation_summary",
            return_value=None,
        ):
            blocks = compose_alert_blocks(change, "Test", "aws", base_url)

        actions_blocks = [b for b in blocks if b.get("type") == "actions"]
        elements = {e["action_id"]: e for e in actions_blocks[0]["elements"]}

        assert elements[ACTION_OPEN_CHANGE]["url"] == f"{base_url}/changes/{change_id}"
        assert elements[ACTION_VIEW_REMEDIATION]["url"] == f"{base_url}/changes/{change_id}#section-remediation"

    def test_remediation_block_included_when_available(self):
        """If remediation summary is available, a remediation section appears."""
        from app.services.slack_service import compose_alert_blocks

        change = self._make_change_dict()
        rem = {
            "available": True,
            "title": "Enable public access block",
            "summary": "Re-enable S3 public access block settings.",
            "remediation_preview_available": True,
        }

        with patch(
            "app.services.remediation_summary_service.build_alert_remediation_summary",
            return_value=rem,
        ):
            blocks = compose_alert_blocks(change, "Test", "aws", "https://app.ct.org")

        section_texts = [
            b["text"]["text"]
            for b in blocks
            if b.get("type") == "section"
        ]
        assert any("Enable public access block" in t for t in section_texts)

    def test_remediation_block_omitted_on_error(self):
        """If build_alert_remediation_summary raises, the block is omitted (fail-open)."""
        from app.services.slack_service import compose_alert_blocks

        change = self._make_change_dict()

        with patch(
            "app.services.remediation_summary_service.build_alert_remediation_summary",
            side_effect=RuntimeError("Service unavailable"),
        ):
            # Must not raise.
            blocks = compose_alert_blocks(change, "Test", "aws", "https://app.ct.org")

        # Should still have header, detail, divider, actions.
        assert len(blocks) >= 3


class TestComposeMultiAlertBlocks:
    """Tests for compose_multi_alert_blocks (2–5 changes)."""

    def _make_changes(self, n: int) -> list[dict]:
        return [
            {
                "id": str(uuid.uuid4()),
                "risk_level": "high",
                "risk_reason": f"Risk reason {i}.",
                "record_identifier": f"resource-{i}",
                "field_path": f"config.field_{i}",
            }
            for i in range(n)
        ]

    def test_no_action_buttons_for_multiple_changes(self):
        """Multi-change blocks must not include an actions block."""
        from app.services.slack_service import compose_multi_alert_blocks

        changes = self._make_changes(3)
        blocks = compose_multi_alert_blocks(changes, "AWS Prod", "aws", "https://app.ct.org")

        action_blocks = [b for b in blocks if b.get("type") == "actions"]
        assert len(action_blocks) == 0, "Multi-change alert must not have action buttons"

    def test_all_changes_have_view_links(self):
        """Each change in a multi-change alert has an inline View link."""
        from app.services.slack_service import compose_multi_alert_blocks

        changes = self._make_changes(3)
        base_url = "https://app.configtrace.org"
        blocks = compose_multi_alert_blocks(changes, "AWS Prod", "aws", base_url)

        section_texts = " ".join(
            b["text"]["text"]
            for b in blocks
            if b.get("type") == "section"
        )

        for change in changes:
            assert change["id"] in section_texts, f"Change {change['id']} missing from multi-alert"


# ═══════════════════════════════════════════════════════════════════════════════
# 20–22: dispatch_alert_message routing
# ═══════════════════════════════════════════════════════════════════════════════

class TestDispatchAlertMessage:
    """Tests for dispatch_alert_message routing logic."""

    def _make_change_list(self, n: int) -> list[MagicMock]:
        changes = []
        for i in range(n):
            c = MagicMock()
            c.id = uuid.uuid4()
            c.risk_level = "high"
            c.risk_reason = f"Reason {i}"
            c.record_identifier = f"resource-{i}"
            c.field_path = f"field.{i}"
            changes.append(c)
        return changes

    def test_single_change_uses_interactive_blocks(self):
        """1 change → send_interactive_message (not plain send_message)."""
        from app.services.slack_service import dispatch_alert_message

        changes = self._make_change_list(1)
        with patch("app.services.slack_service.compose_alert_blocks", return_value=[{"type": "section"}]):
            with patch("app.services.slack_service.send_interactive_message") as mock_interactive:
                with patch("app.services.slack_service.send_message") as mock_plain:
                    dispatch_alert_message(
                        bot_token=_FAKE_BOT_TOKEN,
                        channel_id=_CHANNEL_ID,
                        changes=changes,
                        integration_name="Test",
                        provider="aws",
                        fallback_text="1 alert",
                        base_url="https://app.ct.org",
                    )

        mock_interactive.assert_called_once()
        mock_plain.assert_not_called()

    def test_two_to_five_changes_use_multi_blocks(self):
        """2–5 changes → compose_multi_alert_blocks + send_interactive_message."""
        from app.services.slack_service import dispatch_alert_message

        for n in (2, 3, 5):
            changes = self._make_change_list(n)
            with patch(
                "app.services.slack_service.compose_multi_alert_blocks",
                return_value=[{"type": "section"}],
            ) as mock_compose:
                with patch("app.services.slack_service.send_interactive_message") as mock_interactive:
                    with patch("app.services.slack_service.send_message") as mock_plain:
                        dispatch_alert_message(
                            bot_token=_FAKE_BOT_TOKEN,
                            channel_id=_CHANNEL_ID,
                            changes=changes,
                            integration_name="Test",
                            provider="aws",
                            fallback_text=f"{n} alerts",
                            base_url="https://app.ct.org",
                        )

            mock_interactive.assert_called_once()
            mock_plain.assert_not_called()
            mock_compose.assert_called_once()

    def test_more_than_five_changes_use_plain_text(self):
        """>5 changes → plain send_message fallback (not interactive blocks)."""
        from app.services.slack_service import dispatch_alert_message

        changes = self._make_change_list(6)
        with patch("app.services.slack_service.send_interactive_message") as mock_interactive:
            with patch("app.services.slack_service.send_message") as mock_plain:
                dispatch_alert_message(
                    bot_token=_FAKE_BOT_TOKEN,
                    channel_id=_CHANNEL_ID,
                    changes=changes,
                    integration_name="Test",
                    provider="aws",
                    fallback_text="6 alerts",
                    base_url="https://app.ct.org",
                )

        mock_plain.assert_called_once()
        mock_interactive.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# 23–25: POST /slack/actions endpoint
# ═══════════════════════════════════════════════════════════════════════════════

class TestSlackActionsEndpoint:
    """Integration-style tests for POST /slack/actions via FastAPI TestClient."""

    def _get_client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.routers.slack_oauth import router
        from app.database import get_db

        app = FastAPI()
        app.include_router(router)
        db = MagicMock()
        app.dependency_overrides[get_db] = lambda: db
        return TestClient(app), db

    def _make_form_body(self, payload_dict: dict) -> bytes:
        payload_json = json.dumps(payload_dict)
        return urllib.parse.urlencode({"payload": payload_json}).encode("utf-8")

    def test_missing_signature_headers_returns_403(self):
        """Requests without Slack signature headers are rejected with 403."""
        client, _ = self._get_client()

        with patch("app.config.settings") as mock_cfg:
            mock_cfg.SLACK_SIGNING_SECRET = _SIGNING_SECRET
            response = client.post(
                "/slack/actions",
                content=b"payload={}",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        assert response.status_code == 403

    def test_invalid_signature_returns_403(self):
        """Requests with a bad HMAC signature are rejected with 403."""
        client, _ = self._get_client()

        body = b"payload=%7B%7D"
        timestamp = str(int(time.time()))

        with patch("app.config.settings") as mock_cfg:
            mock_cfg.SLACK_SIGNING_SECRET = _SIGNING_SECRET
            response = client.post(
                "/slack/actions",
                content=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Slack-Request-Timestamp": timestamp,
                    "X-Slack-Signature": "v0=badhmacsignature",
                },
            )

        assert response.status_code == 403

    def test_valid_request_returns_200_with_ephemeral(self):
        """A valid signed request returns HTTP 200 with an ephemeral JSON body."""
        client, _ = self._get_client()

        payload_dict = {
            "type": "block_actions",
            "team": {"id": _TEAM_ID},
            "user": {"id": _SLACK_USER_ID},
            "actions": [],
        }
        body = self._make_form_body(payload_dict)
        timestamp = str(int(time.time()))
        sig = _make_valid_signature(_SIGNING_SECRET, timestamp, body.decode("utf-8"))

        with patch("app.config.settings") as mock_cfg:
            mock_cfg.SLACK_SIGNING_SECRET = _SIGNING_SECRET
            with patch(
                "app.services.slack_service.handle_action",
                return_value={"response_type": "ephemeral", "text": "No action found in payload."},
            ):
                response = client.post(
                    "/slack/actions",
                    content=body,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Slack-Request-Timestamp": timestamp,
                        "X-Slack-Signature": sig,
                    },
                )

        assert response.status_code == 200
        data = response.json()
        assert data["response_type"] == "ephemeral"


# ═══════════════════════════════════════════════════════════════════════════════
# 26–27: Workspace and change lookup helpers
# ═══════════════════════════════════════════════════════════════════════════════

class TestWorkspaceLookup:
    """Tests for get_workspace_by_team_id and get_change_for_workspace."""

    def test_get_workspace_by_team_id_returns_none_when_not_found(self):
        """Returns None when no workspace has the given team_id installed."""
        from app.services.slack_service import get_workspace_by_team_id

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None

        result = get_workspace_by_team_id("T_NOTFOUND", db)
        assert result is None

    def test_get_workspace_by_team_id_returns_workspace_id(self):
        """Returns the workspace_id for a known installed team."""
        from app.services.slack_service import get_workspace_by_team_id

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        row = MagicMock()
        row.workspace_id = workspace_id
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = row

        result = get_workspace_by_team_id(_TEAM_ID, db)
        assert result == workspace_id

    def test_get_change_for_workspace_returns_none_on_bad_uuid(self):
        """A non-UUID change_id string is handled gracefully (returns None)."""
        from app.services.slack_service import get_change_for_workspace

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        db = MagicMock()

        result = get_change_for_workspace("not-a-uuid-at-all", workspace_id, db)
        assert result is None
        db.query.assert_not_called()

    def test_get_change_for_workspace_returns_none_when_not_found(self):
        """Returns None when the change doesn't exist or isn't in the workspace."""
        from app.services.slack_service import get_change_for_workspace

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        db = MagicMock()
        db.query.return_value.join.return_value.filter.return_value.first.return_value = None

        result = get_change_for_workspace(str(uuid.uuid4()), workspace_id, db)
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# 28: _get_actor_user_id preference
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetActorUserId:
    """Tests for _get_actor_user_id installer-preference logic."""

    def test_prefers_installer_over_change_owner(self):
        """Returns the Slack App installer's user_id when available."""
        from app.services.slack_service import _get_actor_user_id

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        change = MagicMock()
        change.user_id = uuid.uuid4()  # would be fallback
        db = MagicMock()

        row = _make_settings_row(slack_installed_by_user_id=_INSTALLER_USER_ID)

        with patch(
            "app.services.notification_service.get_or_create_notification_settings",
            return_value=row,
        ):
            actor = _get_actor_user_id(workspace_id, change, db)

        assert actor == _INSTALLER_USER_ID

    def test_falls_back_to_change_user_id_when_no_installer(self):
        """Falls back to change.user_id when no installer is recorded."""
        from app.services.slack_service import _get_actor_user_id

        fallback_user_id = uuid.uuid4()
        workspace_id = uuid.UUID(_WORKSPACE_ID)
        change = MagicMock()
        change.user_id = fallback_user_id
        db = MagicMock()

        row = _make_settings_row(slack_installed_by_user_id=None)

        with patch(
            "app.services.notification_service.get_or_create_notification_settings",
            return_value=row,
        ):
            actor = _get_actor_user_id(workspace_id, change, db)

        assert actor == fallback_user_id


# ═══════════════════════════════════════════════════════════════════════════════
# 29–30: acknowledge_change_from_slack / snooze_change_from_slack
# ═══════════════════════════════════════════════════════════════════════════════

class TestAcknowledgeFromSlack:
    """Tests for acknowledge_change_from_slack."""

    def test_change_not_found_raises_runtime_error(self):
        """When get_change_for_workspace returns None, RuntimeError is raised."""
        from app.services.slack_service import acknowledge_change_from_slack

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        db = MagicMock()

        with patch(
            "app.services.slack_service.get_change_for_workspace",
            return_value=None,
        ):
            with pytest.raises(RuntimeError, match="not found"):
                acknowledge_change_from_slack(_CHANGE_ID, workspace_id, _SLACK_USER_ID, db)

    def test_calls_acknowledge_change_with_attribution(self):
        """On success, calls acknowledge_change with the Slack user in the note."""
        from app.services.slack_service import acknowledge_change_from_slack

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        change = _make_change()
        db = MagicMock()

        with patch(
            "app.services.slack_service.get_change_for_workspace",
            return_value=change,
        ):
            with patch(
                "app.services.slack_service._get_actor_user_id",
                return_value=_INSTALLER_USER_ID,
            ):
                with patch(
                    "app.services.change_review_service.acknowledge_change"
                ) as mock_ack:
                    result = acknowledge_change_from_slack(
                        _CHANGE_ID, workspace_id, _SLACK_USER_ID, db
                    )

        assert "Acknowledged" in result
        mock_ack.assert_called_once()
        _, kwargs = mock_ack.call_args
        assert _SLACK_USER_ID in kwargs.get("note", "")


class TestSnoozeFromSlack:
    """Tests for snooze_change_from_slack."""

    def test_calls_snooze_change_with_24h(self):
        """On success, calls snooze_change with until = now + 24h."""
        from app.services.slack_service import snooze_change_from_slack
        from datetime import timedelta, timezone
        from app.services import change_review_service as crs

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        change = _make_change()
        db = MagicMock()

        with patch(
            "app.services.slack_service.get_change_for_workspace",
            return_value=change,
        ):
            with patch(
                "app.services.slack_service._get_actor_user_id",
                return_value=_INSTALLER_USER_ID,
            ):
                with patch.object(crs, "snooze_change") as mock_snooze:
                    result = snooze_change_from_slack(
                        _CHANGE_ID, workspace_id, _SLACK_USER_ID, db, hours=24
                    )

        assert "Snoozed" in result
        assert "24" in result
        mock_snooze.assert_called_once()
        _, kwargs = mock_snooze.call_args
        until = kwargs.get("until")
        assert until is not None
        # until should be roughly now + 24h.
        from datetime import datetime
        now = datetime.now(timezone.utc)
        expected_lower = now + timedelta(hours=23, minutes=55)
        expected_upper = now + timedelta(hours=24, minutes=5)
        assert expected_lower <= until <= expected_upper

    def test_change_not_found_raises_runtime_error(self):
        """When get_change_for_workspace returns None, RuntimeError is raised."""
        from app.services.slack_service import snooze_change_from_slack

        workspace_id = uuid.UUID(_WORKSPACE_ID)
        db = MagicMock()

        with patch(
            "app.services.slack_service.get_change_for_workspace",
            return_value=None,
        ):
            with pytest.raises(RuntimeError, match="not found"):
                snooze_change_from_slack(_CHANGE_ID, workspace_id, _SLACK_USER_ID, db)
