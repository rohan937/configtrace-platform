"""Milestone 28 tests — Alert + Change Detail Polish.

What's covered
--------------
A. change_explainer.py — pure unit tests (no DB required):

   1.  DNS CNAME modified → correct provider_label, record_label, summary,
       subject_fragment, what_changed, suggested_checks.
   2.  DNS A record removed → "removed" subject_fragment, what_changed
       describes the old IP, suggested_checks included for high/critical.
   3.  DNS record removed low-risk → suggested_checks empty.
   4.  DNS MX removal → email-auth check list used.
   5.  DNS TTL change → TTL-specific what_changed.
   6.  DNS proxied toggled → proxy-specific what_changed.
   7.  DNS added record → "added" subject_fragment and summary.
   8.  GitHub Actions secret updated → provider_label "GitHub repo configuration",
       what_changed contains privacy note.
   9.  GitHub Actions secret deleted → "deleted" in subject_fragment, privacy note.
  10.  GitHub webhook URL changed → "webhook URL changed" subject_fragment.
  11.  GitHub repo visibility changed to public → "repository visibility changed".
  12.  GitHub branch protection deleted → "branch protection rule deleted".
  13.  GitHub deploy key write-enabled added → "write-enabled deploy key added".
  14.  Unknown GitHub record type → graceful fallback.
  15.  Missing provider_metadata → treated as DNS, uses record_identifier as name.

B. alert_service._compose_digest — pure unit tests (no DB required):

  16.  Single high-risk DNS CNAME modified →
         subject starts "[ConfigTrace] High-risk DNS change:"
         body contains "What changed:", "Why this matters:", "Suggested checks:"
  17.  Single critical DNS change →
         subject starts "[ConfigTrace] Critical DNS change:"
  18.  Single high-risk GitHub secret →
         subject contains "GitHub change:"
         body contains privacy note ("never exposed")
  19.  Multi-change (2 critical) Cloudflare →
         subject is "[ConfigTrace] 2 critical DNS changes detected"
         body contains "Change 1 of 2" and "Change 2 of 2"
  20.  Multi-change (3 high-risk) GitHub →
         subject is "[ConfigTrace] 3 high-risk GitHub configuration changes detected"
  21.  High/Critical still produce non-empty suggested_checks in body.
  22.  Low/Medium: explain_change returns empty suggested_checks.
  23.  Internal UUIDs are NOT prominently in body (Change IDs only appear
       inside the "View full change: .../changes/<uuid>" URL, not as standalone
       UUID lines).
  24.  Integration display_name present in body.
  25.  Provider label present in body.

How we test
-----------
All tests are pure Python — no SQLAlchemy, no database.  explain_change and
_compose_digest both accept plain dicts for their change argument.  For
_compose_digest we build minimal Integration-like objects using a lightweight
namedtuple/SimpleNamespace.

No real HTTP traffic, no real email provider.
"""

from __future__ import annotations

import re
import types
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from app.services.change_explainer import ChangeExplanation, explain_change
from app.services.alert_service import _compose_digest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _dns_change(
    change_type: str = "modified",
    field_path: str | None = "content",
    prev_value: Any = "old.example.com",
    new_value: Any = "new.example.com",
    risk_level: str = "high",
    risk_reason: str = "CNAME target changed.",
    record_type: str = "CNAME",
    record_name: str = "exx.configtrace.org",
    record_content: str | None = None,
    record_identifier: str | None = None,
) -> dict:
    """Build a plain dict representing a Cloudflare DNS change."""
    pm: dict[str, Any] = {
        "record_type":    record_type,
        "record_name":    record_name,
    }
    if record_content is not None:
        pm["record_content"] = record_content

    return {
        "change_type":       change_type,
        "field_path":        field_path,
        "prev_value":        prev_value,
        "new_value":         new_value,
        "risk_level":        risk_level,
        "risk_reason":       risk_reason,
        "provider_metadata": pm,
        "record_identifier": record_identifier or f"{record_type} {record_name}",
    }


def _github_change(
    record_type: str = "github_actions_secret",
    change_type: str = "modified",
    field_path: str | None = "last_updated_at",
    prev_value: Any = None,
    new_value: Any = None,
    risk_level: str = "high",
    risk_reason: str = "Secret rotated.",
    record_name: str = "PROD_TEST_TOKEN",
) -> dict:
    """Build a plain dict representing a GitHub configuration change."""
    return {
        "change_type":       change_type,
        "field_path":        field_path,
        "prev_value":        prev_value,
        "new_value":         new_value,
        "risk_level":        risk_level,
        "risk_reason":       risk_reason,
        "provider_metadata": {
            "record_type": record_type,
            "record_name": record_name,
        },
        "record_identifier": f"{record_type}: {record_name}",
    }


def _fake_integration(
    provider: str = "cloudflare",
    display_name: str = "My Zone",
    user_id: object = None,
) -> types.SimpleNamespace:
    """Minimal Integration-like object for _compose_digest."""
    return types.SimpleNamespace(
        id=uuid.uuid4(),
        provider=provider,
        display_name=display_name,
        user_id=user_id or uuid.uuid4(),
    )


def _fake_change(
    *,
    risk_level: str = "high",
    risk_reason: str = "Test reason.",
    record_identifier: str = "CNAME exx.configtrace.org",
    change_type: str = "modified",
    field_path: str | None = "content",
    prev_value: Any = "old.example.com",
    new_value: Any = "new.example.com",
    provider_metadata: dict | None = None,
) -> types.SimpleNamespace:
    """Minimal Change-like object with a created_at timestamp for _compose_digest."""
    return types.SimpleNamespace(
        id=uuid.uuid4(),
        risk_level=risk_level,
        risk_reason=risk_reason,
        record_identifier=record_identifier,
        change_type=change_type,
        field_path=field_path,
        prev_value=prev_value,
        new_value=new_value,
        provider_metadata=provider_metadata,
        created_at=datetime(2026, 5, 23, 7, 30, 10, tzinfo=timezone.utc),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Part A — change_explainer tests
# ─────────────────────────────────────────────────────────────────────────────


class TestExplainDnsChange:
    """DNS explanation via explain_change()."""

    def test_cname_content_modified(self):
        chg = _dns_change(
            change_type="modified",
            field_path="content",
            record_type="CNAME",
            record_name="exx.configtrace.org",
            prev_value="www.old.com",
            new_value="www.new.com",
            risk_level="high",
        )
        exp = explain_change(chg)

        assert exp.provider_label == "Cloudflare DNS"
        assert "exx.configtrace.org" in exp.record_label
        assert "CNAME" in exp.record_label
        assert "target changed" in exp.subject_fragment
        assert "exx.configtrace.org" in exp.summary
        assert "www.new.com" in exp.what_changed
        assert "www.old.com" in exp.what_changed
        # high → suggested_checks non-empty
        assert len(exp.suggested_checks) > 0
        assert any("intentional" in c for c in exp.suggested_checks)

    def test_a_record_removed_high(self):
        chg = _dns_change(
            change_type="removed",
            field_path=None,
            record_type="A",
            record_name="api.example.com",
            record_content="1.2.3.4",
            prev_value={"content": "1.2.3.4"},
            new_value=None,
            risk_level="high",
        )
        exp = explain_change(chg)

        assert exp.provider_label == "Cloudflare DNS"
        assert "removed" in exp.subject_fragment
        assert "removed" in exp.summary
        assert "1.2.3.4" in exp.what_changed
        assert len(exp.suggested_checks) > 0

    def test_removed_low_risk_no_checks(self):
        chg = _dns_change(
            change_type="removed",
            field_path=None,
            record_type="TXT",
            record_name="verify.example.com",
            record_content="google-site-verification=abc",
            prev_value=None,
            new_value=None,
            risk_level="low",
        )
        exp = explain_change(chg)

        assert exp.suggested_checks == []

    def test_mx_removal_uses_email_auth_checks(self):
        chg = _dns_change(
            change_type="removed",
            field_path=None,
            record_type="MX",
            record_name="example.com",
            record_content="mail.example.com",
            prev_value={"content": "mail.example.com"},
            new_value=None,
            risk_level="critical",
        )
        exp = explain_change(chg)

        assert "MX" in exp.record_label
        assert "mail.example.com" in exp.what_changed
        # Email-auth checks list contains email-specific wording
        assert any("email" in c.lower() for c in exp.suggested_checks)

    def test_ttl_change(self):
        chg = _dns_change(
            change_type="modified",
            field_path="ttl",
            record_type="A",
            record_name="api.example.com",
            prev_value=3600,
            new_value=60,
            risk_level="high",
        )
        exp = explain_change(chg)

        assert "TTL" in exp.subject_fragment or "TTL" in exp.summary
        assert "3600" in exp.what_changed
        assert "60" in exp.what_changed

    def test_proxied_disabled(self):
        chg = _dns_change(
            change_type="modified",
            field_path="proxied",
            record_type="A",
            record_name="api.example.com",
            prev_value=True,
            new_value=False,
            risk_level="critical",
        )
        exp = explain_change(chg)

        assert "disabled" in exp.what_changed or "disabled" in exp.subject_fragment

    def test_a_record_added(self):
        chg = _dns_change(
            change_type="added",
            field_path=None,
            record_type="A",
            record_name="new.example.com",
            prev_value=None,
            new_value={"content": "5.6.7.8", "name": "new.example.com", "record_type": "A"},
            risk_level="medium",
        )
        exp = explain_change(chg)

        assert "added" in exp.subject_fragment
        assert "added" in exp.summary
        assert "5.6.7.8" in exp.what_changed
        # medium → no suggested_checks
        assert exp.suggested_checks == []

    def test_no_provider_metadata_uses_record_identifier(self):
        chg = {
            "change_type":       "modified",
            "field_path":        "content",
            "prev_value":        "old.vercel.app",
            "new_value":         "new.vercel.app",
            "risk_level":        "high",
            "risk_reason":       "CNAME target changed.",
            "provider_metadata": None,
            "record_identifier": "CNAME record: api.example.com",
        }
        exp = explain_change(chg)

        assert exp.provider_label == "Cloudflare DNS"
        # Falls back to record_identifier as name when no metadata
        assert "api.example.com" in exp.record_label or "api.example.com" in exp.summary


class TestExplainGithubChange:
    """GitHub explanation via explain_change()."""

    def test_actions_secret_rotated(self):
        chg = _github_change(
            record_type="github_actions_secret",
            change_type="modified",
            field_path="last_updated_at",
            risk_level="high",
            record_name="PROD_TEST_TOKEN",
        )
        exp = explain_change(chg)

        assert exp.provider_label == "GitHub repo configuration"
        assert "PROD_TEST_TOKEN" in exp.record_label
        assert "updated" in exp.subject_fragment or "rotated" in exp.subject_fragment
        assert "PROD_TEST_TOKEN" in exp.summary
        # Privacy note must be present
        assert "never exposed" in exp.what_changed or "not exposed" in exp.what_changed
        assert "ConfigTrace" in exp.what_changed
        # high → secret checks
        assert len(exp.suggested_checks) > 0
        assert any("rotation" in c.lower() or "intentional" in c.lower()
                   for c in exp.suggested_checks)

    def test_actions_secret_deleted(self):
        chg = _github_change(
            record_type="github_actions_secret",
            change_type="removed",
            field_path=None,
            risk_level="high",
            record_name="PROD_DB_PASSWORD",
        )
        exp = explain_change(chg)

        assert "deleted" in exp.subject_fragment
        assert "deleted" in exp.summary or "deleted" in exp.what_changed
        # Privacy note still present for removed secrets
        assert "never exposed" in exp.what_changed or "not exposed" in exp.what_changed

    def test_webhook_url_changed(self):
        chg = _github_change(
            record_type="github_webhook",
            change_type="modified",
            field_path="url",
            prev_value="https://old.example.com/hook",
            new_value="https://new.example.com/hook",
            risk_level="high",
        )
        exp = explain_change(chg)

        assert exp.provider_label == "GitHub repo configuration"
        assert "webhook URL changed" in exp.subject_fragment
        assert "old.example.com" in exp.what_changed
        assert "new.example.com" in exp.what_changed
        # Webhook checks include endpoint verification
        assert any("endpoint" in c.lower() for c in exp.suggested_checks)

    def test_repo_visibility_public(self):
        chg = _github_change(
            record_type="github_repo_settings",
            change_type="modified",
            field_path="visibility",
            prev_value="private",
            new_value="public",
            risk_level="critical",
        )
        exp = explain_change(chg)

        assert "repository visibility changed" in exp.subject_fragment
        assert "public" in exp.summary
        assert "'private'" in exp.what_changed and "'public'" in exp.what_changed
        # Visibility checks mention exposure
        assert any("exposed" in c.lower() for c in exp.suggested_checks)

    def test_branch_protection_deleted(self):
        chg = _github_change(
            record_type="github_branch_protection",
            change_type="removed",
            field_path=None,
            risk_level="critical",
        )
        exp = explain_change(chg)

        assert "branch protection rule deleted" in exp.subject_fragment
        assert "deleted" in exp.summary or "deleted" in exp.what_changed
        assert any("branch protection" in c.lower() for c in exp.suggested_checks)

    def test_write_deploy_key_added(self):
        chg = _github_change(
            record_type="github_deploy_key",
            change_type="added",
            field_path=None,
            new_value={"read_only": False, "title": "CI Key"},
            risk_level="critical",
        )
        exp = explain_change(chg)

        assert "write-enabled" in exp.subject_fragment
        assert "write-enabled" in exp.summary or "write-enabled" in exp.what_changed

    def test_unknown_github_record_type_graceful(self):
        chg = {
            "change_type":       "modified",
            "field_path":        "something",
            "prev_value":        "a",
            "new_value":         "b",
            "risk_level":        "low",
            "risk_reason":       "Unknown type.",
            "provider_metadata": {"record_type": "github_future_feature"},
            "record_identifier": "github_future_feature",
        }
        exp = explain_change(chg)

        assert exp.provider_label == "GitHub repo configuration"
        assert len(exp.summary) > 0   # No crash
        assert exp.suggested_checks == []  # low → no checks


# ─────────────────────────────────────────────────────────────────────────────
# Part B — _compose_digest tests (no DB)
# ─────────────────────────────────────────────────────────────────────────────


class TestComposeDigestSubject:
    """Subject line format for various single and multi-change scenarios."""

    def test_single_high_dns_cname_modified(self):
        integration = _fake_integration(provider="cloudflare", display_name="My Zone")
        change = _fake_change(
            risk_level="high",
            change_type="modified",
            field_path="content",
            record_identifier="CNAME exx.configtrace.org",
            provider_metadata={
                "record_type": "CNAME",
                "record_name": "exx.configtrace.org",
            },
        )
        subject, body = _compose_digest(integration=integration, changes=[change])

        assert subject.startswith("[ConfigTrace] High-risk DNS change:")
        assert "CNAME" in subject or "exx.configtrace.org" in subject

    def test_single_critical_dns_change(self):
        integration = _fake_integration(provider="cloudflare")
        change = _fake_change(
            risk_level="critical",
            change_type="removed",
            field_path=None,
            provider_metadata={
                "record_type": "A",
                "record_name": "api.example.com",
                "record_content": "1.2.3.4",
            },
        )
        subject, _ = _compose_digest(integration=integration, changes=[change])

        assert subject.startswith("[ConfigTrace] Critical DNS change:")

    def test_single_high_github_secret(self):
        integration = _fake_integration(provider="github", display_name="rohan937/ConfigTrace")
        change = _fake_change(
            risk_level="high",
            change_type="modified",
            field_path="last_updated_at",
            record_identifier="github_actions_secret: PROD_TEST_TOKEN",
            provider_metadata={
                "record_type": "github_actions_secret",
                "record_name": "PROD_TEST_TOKEN",
            },
        )
        subject, _ = _compose_digest(integration=integration, changes=[change])

        assert "[ConfigTrace] High-risk GitHub change:" in subject

    def test_multi_change_critical_cloudflare_subject(self):
        integration = _fake_integration(provider="cloudflare")
        c1 = _fake_change(
            risk_level="critical",
            provider_metadata={"record_type": "A", "record_name": "api.example.com"},
        )
        c2 = _fake_change(
            risk_level="high",
            provider_metadata={"record_type": "CNAME", "record_name": "www.example.com"},
        )
        subject, _ = _compose_digest(integration=integration, changes=[c1, c2])

        assert subject == "[ConfigTrace] 2 critical DNS changes detected"

    def test_multi_change_high_only_cloudflare(self):
        integration = _fake_integration(provider="cloudflare")
        changes = [
            _fake_change(risk_level="high",
                         provider_metadata={"record_type": "A", "record_name": f"h{i}.example.com"})
            for i in range(3)
        ]
        subject, _ = _compose_digest(integration=integration, changes=changes)

        assert subject == "[ConfigTrace] 3 high-risk DNS changes detected"

    def test_multi_change_github_subject(self):
        integration = _fake_integration(provider="github")
        changes = [
            _fake_change(
                risk_level="high",
                provider_metadata={
                    "record_type": "github_actions_secret",
                    "record_name": f"SECRET_{i}",
                },
            )
            for i in range(3)
        ]
        subject, _ = _compose_digest(integration=integration, changes=changes)

        assert subject == "[ConfigTrace] 3 high-risk GitHub configuration changes detected"

    def test_subject_does_not_contain_integration_name_for_single_change(self):
        """Integration display_name should be in the body, not the subject (M28)."""
        integration = _fake_integration(provider="cloudflare", display_name="Super Zone v2")
        change = _fake_change(
            risk_level="high",
            provider_metadata={"record_type": "A", "record_name": "api.example.com"},
        )
        subject, _ = _compose_digest(integration=integration, changes=[change])

        assert "Super Zone v2" not in subject


class TestComposeDigestBody:
    """Body content for various change types."""

    def _get_dns_high_body(self) -> tuple[str, str]:
        integration = _fake_integration(provider="cloudflare", display_name="My Zone")
        change = _fake_change(
            risk_level="high",
            risk_reason="CNAME target redirects traffic.",
            change_type="modified",
            field_path="content",
            prev_value="old.example.com",
            new_value="new.example.com",
            record_identifier="CNAME exx.configtrace.org",
            provider_metadata={
                "record_type": "CNAME",
                "record_name": "exx.configtrace.org",
            },
        )
        return _compose_digest(integration=integration, changes=[change])

    def test_body_contains_what_changed(self):
        _, body = self._get_dns_high_body()
        assert "What changed:" in body

    def test_body_contains_why_this_matters(self):
        _, body = self._get_dns_high_body()
        assert "Why this matters:" in body

    def test_body_contains_suggested_checks_for_high(self):
        _, body = self._get_dns_high_body()
        assert "Suggested checks:" in body
        assert "•" in body

    def test_body_contains_detected_time(self):
        _, body = self._get_dns_high_body()
        assert "Detected:" in body
        assert "2026-05-23" in body

    def test_body_contains_view_full_change_link(self):
        _, body = self._get_dns_high_body()
        assert "View full change:" in body
        assert "/changes/" in body

    def test_body_contains_integration_display_name(self):
        _, body = self._get_dns_high_body()
        assert "My Zone" in body

    def test_body_contains_provider_label(self):
        _, body = self._get_dns_high_body()
        assert "Cloudflare DNS" in body

    def test_dns_cname_what_changed_has_old_and_new_values(self):
        _, body = self._get_dns_high_body()
        assert "old.example.com" in body
        assert "new.example.com" in body

    def test_github_secret_body_has_privacy_note(self):
        integration = _fake_integration(provider="github", display_name="rohan937/Repo")
        change = _fake_change(
            risk_level="high",
            risk_reason="Secret was rotated.",
            change_type="modified",
            field_path="last_updated_at",
            record_identifier="github_actions_secret: PROD_TEST_TOKEN",
            provider_metadata={
                "record_type": "github_actions_secret",
                "record_name": "PROD_TEST_TOKEN",
            },
        )
        _, body = _compose_digest(integration=integration, changes=[change])

        # Privacy note must appear in body
        assert "never exposed" in body.lower() or "not exposed" in body.lower()

    def test_github_webhook_url_changed_body(self):
        integration = _fake_integration(provider="github", display_name="rohan937/Repo")
        change = _fake_change(
            risk_level="high",
            risk_reason="Webhook URL changed.",
            change_type="modified",
            field_path="url",
            prev_value="https://old.example.com/hook",
            new_value="https://new.example.com/hook",
            record_identifier="github_webhook",
            provider_metadata={
                "record_type": "github_webhook",
                "record_name": "",
            },
        )
        _, body = _compose_digest(integration=integration, changes=[change])

        assert "old.example.com" in body
        assert "new.example.com" in body

    def test_dns_removed_record_body(self):
        integration = _fake_integration(provider="cloudflare")
        change = _fake_change(
            risk_level="high",
            risk_reason="CNAME was removed.",
            change_type="removed",
            field_path=None,
            prev_value=None,
            new_value=None,
            record_identifier="CNAME exx.configtrace.org",
            provider_metadata={
                "record_type": "CNAME",
                "record_name": "exx.configtrace.org",
                "record_content": "old-target.example.com",
            },
        )
        _, body = _compose_digest(integration=integration, changes=[change])

        assert "old-target.example.com" in body
        assert "removed" in body.lower()

    def test_multi_change_body_has_change_numbering(self):
        integration = _fake_integration(provider="cloudflare")
        c1 = _fake_change(
            risk_level="critical",
            provider_metadata={"record_type": "A", "record_name": "a.example.com"},
        )
        c2 = _fake_change(
            risk_level="high",
            provider_metadata={"record_type": "CNAME", "record_name": "b.example.com"},
        )
        _, body = _compose_digest(integration=integration, changes=[c1, c2])

        assert "Change 1 of 2" in body
        assert "Change 2 of 2" in body

    def test_uuids_only_in_view_change_url_not_as_raw_lines(self):
        """Internal UUIDs must not appear as raw standalone lines in the body."""
        integration = _fake_integration(provider="cloudflare")
        change = _fake_change(
            risk_level="high",
            provider_metadata={"record_type": "A", "record_name": "api.example.com"},
        )
        _, body = _compose_digest(integration=integration, changes=[change])

        # The UUID should only appear inside the /changes/ URL path.
        # Pattern: a bare UUID line (not preceded by /changes/).
        change_id_str = str(change.id)
        # Split body into lines and check no line is JUST the UUID or contains
        # "Resource ID" / "Integration" UUID labels.
        lines = body.splitlines()
        bare_uuid_lines = [
            ln for ln in lines
            if change_id_str in ln and "/changes/" not in ln
        ]
        assert bare_uuid_lines == [], (
            f"Found raw UUID line(s) in body (not inside /changes/ URL): {bare_uuid_lines}"
        )

        # Also confirm "Resource ID" and "Integration:" don't appear as UUID rows
        uuid_label_lines = [
            ln for ln in lines
            if re.search(r"Resource\s+ID|Integration\s+ID", ln, re.IGNORECASE)
        ]
        assert uuid_label_lines == [], f"Found UUID label rows: {uuid_label_lines}"

    def test_suggested_checks_absent_for_low_risk(self):
        """explain_change with risk_level='low' returns empty suggested_checks."""
        chg = _dns_change(
            risk_level="low",
            change_type="modified",
            field_path="comment",
        )
        exp = explain_change(chg)
        assert exp.suggested_checks == []

    def test_suggested_checks_absent_for_medium_risk(self):
        """explain_change with risk_level='medium' returns empty suggested_checks."""
        chg = _dns_change(
            risk_level="medium",
            change_type="added",
            field_path=None,
            record_type="CNAME",
        )
        exp = explain_change(chg)
        assert exp.suggested_checks == []

    def test_high_and_critical_have_suggested_checks(self):
        for level in ("high", "critical"):
            chg = _dns_change(risk_level=level)
            exp = explain_change(chg)
            assert len(exp.suggested_checks) > 0, f"Expected checks for {level!r}"
