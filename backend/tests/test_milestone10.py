"""Milestone 10 tests: risk classification service.

Run with:
    docker compose run --rm api pytest tests/test_milestone10.py -v

Pure rule tests use plain dicts — no database required.
DB-backed tests use the shared fixtures from conftest.py.
Cloudflare API calls in sync task tests are always mocked.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.models.change import Change
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.snapshot import Snapshot
from app.services.diff_service import compute_diff, store_changes
from app.services.risk_rules.cloudflare_dns import (
    classify_dns_change,
    is_apex_or_root_record,
)
from app.services.risk_service import classify_changes, update_change_risk
from app.services.snapshot_service import store_snapshot


# ─────────────────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────────────────

def _change_dict(
    change_type: str,
    record_type: str = "A",
    record_name: str = "example.com",
    field_path: str | None = None,
    prev_value=None,
    new_value=None,
    zone_name: str | None = None,
) -> dict:
    """Build a minimal change dict suitable for classify_dns_change."""
    return {
        "change_type": change_type,
        "field_path": field_path,
        "prev_value": prev_value,
        "new_value": new_value,
        "provider_metadata": {
            "record_type": record_type,
            "record_name": record_name,
            "record_id": "rec-test",
            "record_content": "1.2.3.4",
            **({"zone_name": zone_name} if zone_name is not None else {}),
        },
    }


def _dns_record(
    record_id: str,
    name: str = "example.com",
    content: str = "1.2.3.4",
    record_type: str = "A",
    ttl: int = 300,
    proxied: bool = False,
    priority: int | None = None,
    comment: str | None = None,
) -> dict:
    """Return a minimal CloudflareDNSRecord-shaped dict."""
    return {
        "record_id": record_id,
        "record_type": record_type,
        "name": name,
        "content": content,
        "ttl": ttl,
        "proxied": proxied,
        "priority": priority,
        "comment": comment,
        "modified_on": "2026-05-21T00:00:00Z",
    }


def _mock_snapshot(state: list[dict]) -> MagicMock:
    snap = MagicMock(spec=Snapshot)
    snap.state = state
    snap.id = uuid.uuid4()
    return snap


def _make_integration(db_session, user) -> Integration:
    from app.core.encryption import encrypt_credentials

    ciphertext, iv = encrypt_credentials(
        {"api_token": "fake_tok", "zone_id": "zone123"}
    )
    integration = Integration(
        user_id=user.id,
        provider="cloudflare",
        display_name="Test Integration",
        encrypted_credentials=ciphertext,
        credential_iv=iv,
        status="active",
    )
    db_session.add(integration)
    db_session.flush()

    resource = Resource(
        integration_id=integration.id,
        user_id=user.id,
        provider_resource_type="cloudflare_dns_zone",
        provider_resource_id="zone123",
        display_name="Zone 123",
        is_active=True,
    )
    db_session.add(resource)
    db_session.commit()
    db_session.refresh(integration)
    db_session.refresh(resource)
    return integration


def _make_sync_run(db_session, user, integration):
    from app.services.sync_service import create_sync_run

    return create_sync_run(
        user_id=user.id,
        integration_id=integration.id,
        db=db_session,
    )


def _get_resource(db_session, integration) -> Resource:
    return (
        db_session.query(Resource)
        .filter(Resource.integration_id == integration.id)
        .first()
    )


def _make_snapshot(db_session, user, integration, state: list[dict]) -> Snapshot:
    resource = _get_resource(db_session, integration)
    snap, _ = store_snapshot(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=user.id,
        state=state,
        triggered_by="manual",
        db=db_session,
    )
    db_session.commit()
    return snap


# ─────────────────────────────────────────────────────────────────────────────
# 1. is_apex_or_root_record — pure unit tests (no DB)
# ─────────────────────────────────────────────────────────────────────────────

def test_apex_two_labels_is_apex() -> None:
    """example.com (2 labels) is classified as apex."""
    assert is_apex_or_root_record("example.com") is True


def test_apex_three_labels_is_not_apex() -> None:
    """api.example.com (3 labels) is not classified as apex."""
    assert is_apex_or_root_record("api.example.com") is False


def test_apex_with_zone_name_exact_match() -> None:
    """Exact match against zone_name overrides label count."""
    assert is_apex_or_root_record("example.com", zone_name="example.com") is True
    assert is_apex_or_root_record("api.example.com", zone_name="example.com") is False


def test_apex_trailing_dot_is_stripped() -> None:
    """Trailing dots in DNS names are stripped before comparison."""
    assert is_apex_or_root_record("example.com.") is True
    assert is_apex_or_root_record("api.example.com.") is False


def test_apex_empty_name_returns_false() -> None:
    """Empty record_name returns False (no record = no apex)."""
    assert is_apex_or_root_record("") is False


# ─────────────────────────────────────────────────────────────────────────────
# 2. classify_dns_change — CRITICAL rules (plain dict, no DB)
# ─────────────────────────────────────────────────────────────────────────────

def test_deleting_apex_a_record_is_critical() -> None:
    """Removing an apex A record → critical."""
    change = _change_dict("removed", record_type="A", record_name="example.com")
    level, reason = classify_dns_change(change)
    assert level == "critical"
    assert "apex" in reason.lower()


def test_deleting_apex_aaaa_record_is_critical() -> None:
    """Removing an apex AAAA record → critical."""
    change = _change_dict("removed", record_type="AAAA", record_name="example.com")
    level, reason = classify_dns_change(change)
    assert level == "critical"


def test_deleting_apex_cname_record_is_critical() -> None:
    """Removing an apex CNAME record → critical."""
    change = _change_dict("removed", record_type="CNAME", record_name="example.com")
    level, reason = classify_dns_change(change)
    assert level == "critical"


def test_deleting_mx_record_is_critical() -> None:
    """Removing any MX record → critical (stops email delivery)."""
    change = _change_dict("removed", record_type="MX", record_name="example.com")
    level, reason = classify_dns_change(change)
    assert level == "critical"
    assert "email" in reason.lower() or "mx" in reason.lower()


def test_modifying_ns_record_is_critical() -> None:
    """Any modification to an NS record → critical."""
    change = _change_dict(
        "modified",
        record_type="NS",
        record_name="example.com",
        field_path="content",
        prev_value="ns1.old.com",
        new_value="ns1.new.com",
    )
    level, reason = classify_dns_change(change)
    assert level == "critical"
    assert "NS" in reason


def test_modifying_soa_record_is_critical() -> None:
    """Any modification to an SOA record → critical."""
    change = _change_dict(
        "modified",
        record_type="SOA",
        record_name="example.com",
        field_path="content",
        prev_value="old",
        new_value="new",
    )
    level, reason = classify_dns_change(change)
    assert level == "critical"
    assert "SOA" in reason


# ─────────────────────────────────────────────────────────────────────────────
# 3. classify_dns_change — HIGH rules (plain dict, no DB)
# ─────────────────────────────────────────────────────────────────────────────

def test_deleting_non_apex_a_record_is_high() -> None:
    """Removing api.example.com A record → critical ('api' is a critical subdomain)."""
    change = _change_dict("removed", record_type="A", record_name="api.example.com")
    level, reason = classify_dns_change(change)
    assert level == "critical"


def test_deleting_txt_record_is_high() -> None:
    """Removing a generic TXT record (non-email-auth content) → medium."""
    change = _change_dict("removed", record_type="TXT", record_name="example.com")
    level, reason = classify_dns_change(change)
    assert level == "medium"


def test_modifying_cname_content_is_high() -> None:
    """Changing www.example.com CNAME target → critical ('www' is a critical subdomain)."""
    change = _change_dict(
        "modified",
        record_type="CNAME",
        record_name="www.example.com",
        field_path="content",
        prev_value="origin.example.com",
        new_value="cdn.example.com",
    )
    level, reason = classify_dns_change(change)
    assert level == "critical"
    assert "CNAME" in reason


def test_modifying_mx_content_is_high() -> None:
    """Changing an MX target → high."""
    change = _change_dict(
        "modified",
        record_type="MX",
        record_name="example.com",
        field_path="content",
        prev_value="mail1.example.com",
        new_value="mail2.example.com",
    )
    level, reason = classify_dns_change(change)
    assert level == "high"


def test_modifying_mx_priority_is_high() -> None:
    """Changing MX priority → medium (mail still delivered; only selection order changes)."""
    change = _change_dict(
        "modified",
        record_type="MX",
        record_name="example.com",
        field_path="priority",
        prev_value=10,
        new_value=20,
    )
    level, reason = classify_dns_change(change)
    assert level == "medium"
    assert "priority" in reason.lower() or "mail" in reason.lower()


def test_proxy_disabled_is_high() -> None:
    """Disabling proxy on api.example.com → critical ('api' is a critical subdomain)."""
    change = _change_dict(
        "modified",
        record_type="A",
        record_name="api.example.com",
        field_path="proxied",
        prev_value=True,
        new_value=False,
    )
    level, reason = classify_dns_change(change)
    assert level == "critical"
    assert "proxy" in reason.lower() or "ip" in reason.lower()


def test_ttl_reduced_to_exactly_60_is_high() -> None:
    """TTL reduced to exactly 60 seconds → high (boundary case)."""
    change = _change_dict(
        "modified",
        record_type="A",
        record_name="api.example.com",
        field_path="ttl",
        prev_value=3600,
        new_value=60,
    )
    level, reason = classify_dns_change(change)
    assert level == "high"
    assert "60" in reason


def test_ttl_reduced_to_below_60_is_high() -> None:
    """TTL reduced to 1 second → high."""
    change = _change_dict(
        "modified",
        record_type="A",
        record_name="api.example.com",
        field_path="ttl",
        prev_value=3600,
        new_value=1,
    )
    level, reason = classify_dns_change(change)
    assert level == "high"


# ─────────────────────────────────────────────────────────────────────────────
# 4. classify_dns_change — MEDIUM rules (plain dict, no DB)
# ─────────────────────────────────────────────────────────────────────────────

def test_ttl_changed_to_300_is_medium() -> None:
    """TTL changed to 300 (above 60 threshold) → medium."""
    change = _change_dict(
        "modified",
        record_type="A",
        record_name="api.example.com",
        field_path="ttl",
        prev_value=3600,
        new_value=300,
    )
    level, reason = classify_dns_change(change)
    assert level == "medium"
    assert "300" in reason


def test_proxy_enabled_is_medium() -> None:
    """Enabling Cloudflare proxy (False→True) → medium."""
    change = _change_dict(
        "modified",
        record_type="A",
        record_name="api.example.com",
        field_path="proxied",
        prev_value=False,
        new_value=True,
    )
    level, reason = classify_dns_change(change)
    assert level == "medium"
    assert "proxy" in reason.lower() or "cloudflare" in reason.lower()


def test_txt_content_change_is_medium() -> None:
    """Modifying SPF TXT content → high (email authentication record changed)."""
    change = _change_dict(
        "modified",
        record_type="TXT",
        record_name="example.com",
        field_path="content",
        prev_value="v=spf1 include:old.com ~all",
        new_value="v=spf1 include:new.com ~all",
    )
    level, reason = classify_dns_change(change)
    assert level == "high"
    assert "TXT" in reason or "SPF" in reason or "DKIM" in reason


def test_adding_subdomain_a_record_is_medium() -> None:
    """Adding a subdomain A record → medium (new entry point)."""
    change = _change_dict(
        "added",
        record_type="A",
        record_name="staging.example.com",
        new_value=_dns_record("rec-new", name="staging.example.com"),
    )
    level, reason = classify_dns_change(change)
    assert level == "medium"
    assert "subdomain" in reason.lower()


def test_adding_subdomain_aaaa_record_is_medium() -> None:
    """Adding a subdomain AAAA record → medium."""
    change = _change_dict(
        "added",
        record_type="AAAA",
        record_name="ipv6.example.com",
        new_value=_dns_record("rec-new", name="ipv6.example.com", record_type="AAAA"),
    )
    level, reason = classify_dns_change(change)
    assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# 5. classify_dns_change — LOW rules (plain dict, no DB)
# ─────────────────────────────────────────────────────────────────────────────

def test_comment_change_is_low() -> None:
    """Modifying comment → low (no DNS impact)."""
    change = _change_dict(
        "modified",
        record_type="A",
        record_name="api.example.com",
        field_path="comment",
        prev_value="old comment",
        new_value="new comment",
    )
    level, reason = classify_dns_change(change)
    assert level == "low"
    assert "comment" in reason.lower()


def test_unmatched_change_defaults_to_low() -> None:
    """An unrecognised modification pattern falls through to low."""
    change = _change_dict(
        "modified",
        record_type="SRV",
        record_name="_sip._tcp.example.com",
        field_path="content",
        prev_value="old",
        new_value="new",
    )
    level, reason = classify_dns_change(change)
    assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 6. update_change_risk — DB integration tests
# ─────────────────────────────────────────────────────────────────────────────

def test_update_change_risk_persists_level_and_reason(
    db_session, test_user
) -> None:
    """update_change_risk writes risk_level and risk_reason to the Change row."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)

    snap_prev = _make_snapshot(db_session, test_user, integration,
                                [_dns_record("rec-001")])
    snap_new = _make_snapshot(db_session, test_user, integration,
                               [_dns_record("rec-002")])

    change_dicts = [
        {
            "change_type": "removed",
            "record_identifier": "MX example.com",
            "field_path": None,
            "prev_value": _dns_record("rec-001", record_type="MX"),
            "new_value": None,
            "provider_metadata": {
                "record_id": "rec-001",
                "record_type": "MX",
                "record_name": "example.com",
                "record_content": "mail.example.com",
            },
        }
    ]

    changes = store_changes(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=test_user.id,
        prev_snapshot_id=snap_prev.id,
        new_snapshot_id=snap_new.id,
        change_dicts=change_dicts,
        db=db_session,
    )
    db_session.commit()

    # Confirm pre-classification state
    assert changes[0].risk_level == "unknown"

    # Run classification
    updated = update_change_risk(changes[0], db_session)
    db_session.commit()

    assert updated.risk_level == "critical"
    assert updated.risk_reason is not None
    assert "email" in updated.risk_reason.lower() or "mx" in updated.risk_reason.lower()

    # Verify persistence
    row = db_session.get(Change, updated.id)
    assert row.risk_level == "critical"
    assert row.risk_reason is not None


def test_classify_changes_bulk_update(db_session, test_user) -> None:
    """classify_changes updates all rows with one flush."""
    integration = _make_integration(db_session, test_user)
    resource = _get_resource(db_session, integration)

    snap_prev = _make_snapshot(db_session, test_user, integration,
                                [_dns_record("rec-001")])
    snap_new = _make_snapshot(db_session, test_user, integration,
                               [_dns_record("rec-001"), _dns_record("rec-002")])

    change_dicts = compute_diff(
        _mock_snapshot([_dns_record("rec-001")]),
        _mock_snapshot([_dns_record("rec-001"), _dns_record("rec-002",
                                                             name="sub.example.com")]),
    )

    changes = store_changes(
        resource_id=resource.id,
        integration_id=integration.id,
        user_id=test_user.id,
        prev_snapshot_id=snap_prev.id,
        new_snapshot_id=snap_new.id,
        change_dicts=change_dicts,
        db=db_session,
    )
    db_session.commit()

    # All initially unknown
    for c in changes:
        assert c.risk_level == "unknown"

    # Bulk classify
    classified = classify_changes(changes, db_session)
    db_session.commit()

    assert len(classified) == 1  # one added record
    assert classified[0].risk_level != "unknown"
    assert classified[0].risk_reason is not None

    row = db_session.get(Change, classified[0].id)
    assert row.risk_level != "unknown"


def test_classify_changes_empty_list_is_noop(db_session, test_user) -> None:
    """classify_changes with an empty list returns [] without errors."""
    result = classify_changes([], db_session)
    assert result == []


# ─────────────────────────────────────────────────────────────────────────────
# 7. Sync task integration — risk levels wired end-to-end (real DB)
# ─────────────────────────────────────────────────────────────────────────────

@patch("app.workers.sync_task.CloudflareConnector")
def test_sync_task_change_rows_have_risk_level_classified(
    mock_connector_cls, db_session, test_user
) -> None:
    """After a changed sync, all Change rows have risk_level != 'unknown'."""
    integration = _make_integration(db_session, test_user)

    from app.workers.sync_task import sync_integration

    # Baseline
    mock_connector_cls.return_value.fetch.return_value = [
        _dns_record("rec-001", content="1.1.1.1"),
    ]
    run1 = _make_sync_run(db_session, test_user, integration)
    sync_integration.apply(
        args=[str(run1.id), str(integration.id), str(test_user.id)]
    ).get()

    # Changed sync — content modification
    mock_connector_cls.return_value.fetch.return_value = [
        _dns_record("rec-001", content="9.9.9.9"),
    ]
    run2 = _make_sync_run(db_session, test_user, integration)
    sync_integration.apply(
        args=[str(run2.id), str(integration.id), str(test_user.id)]
    ).get()

    db_session.expire_all()

    changes = (
        db_session.query(Change)
        .filter(Change.integration_id == integration.id)
        .all()
    )
    assert len(changes) == 1

    change = changes[0]
    assert change.risk_level != "unknown", (
        f"Expected risk_level to be classified but got 'unknown' "
        f"for change_type={change.change_type!r} field={change.field_path!r}"
    )
    assert change.risk_reason is not None


@patch("app.workers.sync_task.CloudflareConnector")
def test_sync_task_mx_deletion_is_critical(
    mock_connector_cls, db_session, test_user
) -> None:
    """MX record deletion in a sync → critical risk classification."""
    integration = _make_integration(db_session, test_user)

    from app.workers.sync_task import sync_integration

    # Baseline with an MX record
    mock_connector_cls.return_value.fetch.return_value = [
        _dns_record("rec-mx", name="example.com", content="mail.example.com",
                    record_type="MX", priority=10),
    ]
    run1 = _make_sync_run(db_session, test_user, integration)
    sync_integration.apply(
        args=[str(run1.id), str(integration.id), str(test_user.id)]
    ).get()

    # Second sync — MX record removed
    mock_connector_cls.return_value.fetch.return_value = []
    run2 = _make_sync_run(db_session, test_user, integration)
    result = sync_integration.apply(
        args=[str(run2.id), str(integration.id), str(test_user.id)]
    ).get()

    assert result["change_count"] == 1

    db_session.expire_all()

    change = (
        db_session.query(Change)
        .filter(Change.integration_id == integration.id)
        .first()
    )
    assert change is not None
    assert change.change_type == "removed"
    assert change.risk_level == "critical"
    assert change.risk_reason is not None


@patch("app.workers.sync_task.CloudflareConnector")
def test_sync_task_apex_a_deletion_is_critical(
    mock_connector_cls, db_session, test_user
) -> None:
    """Deleting an apex A record in a sync → critical risk classification."""
    integration = _make_integration(db_session, test_user)

    from app.workers.sync_task import sync_integration

    # Baseline with apex A record (example.com = 2 labels = apex)
    mock_connector_cls.return_value.fetch.return_value = [
        _dns_record("rec-apex", name="example.com", content="1.2.3.4",
                    record_type="A"),
    ]
    run1 = _make_sync_run(db_session, test_user, integration)
    sync_integration.apply(
        args=[str(run1.id), str(integration.id), str(test_user.id)]
    ).get()

    # Second sync — apex A record removed
    mock_connector_cls.return_value.fetch.return_value = []
    run2 = _make_sync_run(db_session, test_user, integration)
    result = sync_integration.apply(
        args=[str(run2.id), str(integration.id), str(test_user.id)]
    ).get()

    assert result["change_count"] == 1

    db_session.expire_all()

    change = (
        db_session.query(Change)
        .filter(Change.integration_id == integration.id)
        .first()
    )
    assert change is not None
    assert change.risk_level == "critical"
    assert "apex" in change.risk_reason.lower()
