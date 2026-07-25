"""Okta application diff/risk-classification tests (Okta message 3 of 8).

Uses the REAL ``compute_diff()`` and ``classify_okta_change()`` — never
hand-built Change objects standing in for the diff pipeline — to verify
application activation/deactivation, HTTP/wildcard redirect changes,
assignment addition/removal, Everyone-group assignment, provider metadata,
and the ignored-timestamp discipline.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import _tracked_fields_for, compute_diff
from app.services.risk_rules.okta import classify_okta_change


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _app_record(**overrides) -> dict:
    base = {
        "record_type": "okta_application",
        "record_id": "id:t1/app/app1",
        "provider_resource_id": "apps/app1",
        "tenant_id": "id:t1",
        "app_id": "app1",
        "label": "My App",
        "status": "ACTIVE",
        "active": True,
        "sign_on_mode": "OPENID_CONNECT",
        "protocol_category": "OIDC_OAUTH",
        "hidden_from_self_service": False,
        "auto_submit_toolbar": None,
        "signing_key_rotation_category": None,
        "app_type_category": "web",
        "token_endpoint_auth_method_category": "client_secret_basic",
        "grant_types_summary": "authorization_code",
        "response_types_summary": "code",
        "logout_redirect_count": 0,
        "redirect_count": 1,
        "https_redirect_count": 1,
        "http_redirect_count": 0,
        "localhost_redirect_count": 0,
        "loopback_redirect_count": 0,
        "custom_scheme_redirect_count": 0,
        "wildcard_redirect_present": False,
        "user_assignment_count": 5,
        "group_assignment_count": 2,
    }
    base.update(overrides)
    return base


def _user_assignment_record(**overrides) -> dict:
    base = {
        "record_type": "okta_application_user_assignment",
        "record_id": "id:t1/app_assignment/app1/user/u1",
        "provider_resource_id": "apps/app1/users/u1",
        "tenant_id": "id:t1",
        "app_id": "app1",
        "app_label": "My App",
        "user_id": "u1",
        "user_login": "u1@example.com",
        "user_status": "ACTIVE",
        "assignment_status_category": "ACTIVE",
        "assignment_scope_category": "USER",
    }
    base.update(overrides)
    return base


def _group_assignment_record(**overrides) -> dict:
    base = {
        "record_type": "okta_application_group_assignment",
        "record_id": "id:t1/app_assignment/app1/group/g1",
        "provider_resource_id": "apps/app1/groups/g1",
        "tenant_id": "id:t1",
        "app_id": "app1",
        "app_label": "My App",
        "group_id": "g1",
        "group_name": "Engineering",
        "group_type": "OKTA_GROUP",
        "built_in_group": False,
        "everyone_group": False,
    }
    base.update(overrides)
    return base


def _find_field_change(changes: list[dict], field_path: str) -> dict:
    match = [c for c in changes if c["field_path"] == field_path]
    assert match, f"no change found for field_path={field_path!r} in {changes}"
    return match[0]


# ════════════════════════════════════════════════════════════════════════════
# Application activation/deactivation
# ════════════════════════════════════════════════════════════════════════════


class TestApplicationActivation:
    def test_active_to_inactive_is_low(self):
        prev = [_app_record(status="ACTIVE", active=True)]
        new = [_app_record(status="INACTIVE", active=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "status")
        level, reason = classify_okta_change(NS(**change))
        assert level == "low"
        assert "deactivated" in reason.lower()

    def test_inactive_to_active_is_medium(self):
        prev = [_app_record(status="INACTIVE", active=False)]
        new = [_app_record(status="ACTIVE", active=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "status")
        level, reason = classify_okta_change(NS(**change))
        assert level == "medium"
        assert "activated" in reason.lower()

    def test_unknown_new_status_is_medium(self):
        prev = [_app_record(status="ACTIVE")]
        new = [_app_record(status="SOME_FUTURE_STATUS")]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "status")
        level, reason = classify_okta_change(NS(**change))
        assert level == "medium"
        assert "unrecognized" in reason.lower()

    def test_active_flag_cleared_is_low(self):
        prev = [_app_record(active=True)]
        new = [_app_record(active=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "active")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_active_flag_set_is_medium(self):
        prev = [_app_record(active=False)]
        new = [_app_record(active=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "active")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Redirect posture changes
# ════════════════════════════════════════════════════════════════════════════


class TestRedirectPostureChanges:
    def test_http_redirect_introduced(self):
        prev = [_app_record(http_redirect_count=0)]
        new = [_app_record(http_redirect_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "http_redirect_count")
        level, reason = classify_okta_change(NS(**change))
        assert level == "medium"
        assert "http" in reason.lower()

    def test_http_redirect_removed(self):
        prev = [_app_record(http_redirect_count=1)]
        new = [_app_record(http_redirect_count=0)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "http_redirect_count")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_wildcard_redirect_added_is_high(self):
        prev = [_app_record(wildcard_redirect_present=False)]
        new = [_app_record(wildcard_redirect_present=True)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "wildcard_redirect_present")
        level, reason = classify_okta_change(NS(**change))
        assert level == "high"
        assert "wildcard" in reason.lower()

    def test_wildcard_redirect_removed_is_low(self):
        prev = [_app_record(wildcard_redirect_present=True)]
        new = [_app_record(wildcard_redirect_present=False)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "wildcard_redirect_present")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_custom_scheme_redirect_introduced_is_medium(self):
        prev = [_app_record(custom_scheme_redirect_count=0)]
        new = [_app_record(custom_scheme_redirect_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "custom_scheme_redirect_count")
        level, _ = classify_okta_change(NS(**change))
        assert level == "medium"

    def test_redirect_posture_tightened_is_low(self):
        prev = [_app_record(redirect_count=5)]
        new = [_app_record(redirect_count=2)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "redirect_count")
        level, _ = classify_okta_change(NS(**change))
        assert level == "low"

    def test_wording_never_claims_token_theft(self):
        prev = [_app_record(http_redirect_count=0)]
        new = [_app_record(http_redirect_count=1)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "http_redirect_count")
        _, reason = classify_okta_change(NS(**change))
        assert "stolen" not in reason.lower()
        assert "account takeover" not in reason.lower()


# ════════════════════════════════════════════════════════════════════════════
# Application label / added / removed
# ════════════════════════════════════════════════════════════════════════════


class TestApplicationChurn:
    def test_label_rename_same_id_is_modification(self):
        prev = [_app_record(label="Old Label")]
        new = [_app_record(label="New Label")]
        changes = compute_diff(_snap(prev), _snap(new))
        change_types = {c["change_type"] for c in changes}
        assert change_types == {"modified"}
        change = _find_field_change(changes, "label")
        level, reason = classify_okta_change(NS(**change))
        assert level == "low"
        assert "renamed" in reason.lower()

    def test_app_added_active(self):
        changes = compute_diff(_snap([]), _snap([_app_record(status="ACTIVE")]))
        assert changes[0]["change_type"] == "added"
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "low"
        assert "active" in reason.lower()

    def test_app_added_inactive(self):
        changes = compute_diff(_snap([]), _snap([_app_record(status="INACTIVE")]))
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "low"
        assert "inactive" in reason.lower()

    def test_app_removed(self):
        changes = compute_diff(_snap([_app_record()]), _snap([]))
        assert changes[0]["change_type"] == "removed"
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "low"
        assert "does not by itself confirm" in reason.lower()


# ════════════════════════════════════════════════════════════════════════════
# Assignment addition/removal
# ════════════════════════════════════════════════════════════════════════════


class TestAssignmentChanges:
    def test_user_assignment_added(self):
        changes = compute_diff(_snap([]), _snap([_user_assignment_record()]))
        assert changes[0]["change_type"] == "added"
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "medium"

    def test_user_assignment_removed(self):
        changes = compute_diff(_snap([_user_assignment_record()]), _snap([]))
        assert changes[0]["change_type"] == "removed"
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_group_assignment_added_ordinary_group(self):
        changes = compute_diff(_snap([]), _snap([_group_assignment_record(everyone_group=False)]))
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "medium"
        assert "everyone" not in reason.lower()

    def test_group_assignment_removed(self):
        changes = compute_diff(_snap([_group_assignment_record()]), _snap([]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "low"

    def test_everyone_group_assigned(self):
        changes = compute_diff(_snap([]), _snap([_group_assignment_record(everyone_group=True)]))
        level, reason = classify_okta_change(NS(**changes[0]))
        assert level == "medium"
        assert "everyone" in reason.lower()

    def test_ordinary_group_assigned_distinct_from_everyone(self):
        ordinary_changes = compute_diff(_snap([]), _snap([_group_assignment_record(everyone_group=False)]))
        everyone_changes = compute_diff(_snap([]), _snap([_group_assignment_record(
            record_id="id:t1/app_assignment/app1/group/g2", group_id="g2", everyone_group=True,
        )]))
        _, ordinary_reason = classify_okta_change(NS(**ordinary_changes[0]))
        _, everyone_reason = classify_okta_change(NS(**everyone_changes[0]))
        assert ordinary_reason != everyone_reason

    def test_active_user_assignment(self):
        changes = compute_diff(_snap([]), _snap([_user_assignment_record(user_status="ACTIVE")]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "medium"

    def test_suspended_user_assignment(self):
        changes = compute_diff(_snap([]), _snap([_user_assignment_record(user_status="SUSPENDED")]))
        level, _ = classify_okta_change(NS(**changes[0]))
        assert level == "medium"  # assignment addition itself is what's classified, not the user's own status

    def test_duplicate_user_assignment_dedup(self):
        from app.services.diff_service import build_record_index

        rec = _user_assignment_record()
        index = build_record_index([rec, dict(rec)])
        assert len(index) == 1

    def test_duplicate_group_assignment_dedup(self):
        from app.services.diff_service import build_record_index

        rec = _group_assignment_record()
        index = build_record_index([rec, dict(rec)])
        assert len(index) == 1

    def test_assignment_endpoint_denied_reflected_in_completeness_not_a_change(self):
        # Completeness gaps are surfaced via okta_organization.family_completeness,
        # never fabricated as a Change on the assignment records themselves.
        fields = _tracked_fields_for({"record_type": "okta_application_user_assignment"})
        assert "family_completeness" not in fields


# ════════════════════════════════════════════════════════════════════════════
# Counts unknown when denied / zero when actually zero
# ════════════════════════════════════════════════════════════════════════════


class TestAssignmentCountSemantics:
    def test_counts_unknown_when_denied_produces_no_fabricated_decrease(self):
        prev = [_app_record(user_assignment_count=5)]
        new = [_app_record(user_assignment_count=None)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "user_assignment_count")
        level, reason = classify_okta_change(NS(**change))
        assert "unknown" in reason.lower() or "determined" in reason.lower()

    def test_zero_assignment_actual_is_a_real_value_not_unknown(self):
        prev = [_app_record(user_assignment_count=None)]
        new = [_app_record(user_assignment_count=0)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "user_assignment_count")
        assert change["new_value"] == 0

    def test_group_assignment_count_increase(self):
        prev = [_app_record(group_assignment_count=1)]
        new = [_app_record(group_assignment_count=3)]
        changes = compute_diff(_snap(prev), _snap(new))
        change = _find_field_change(changes, "group_assignment_count")
        level, reason = classify_okta_change(NS(**change))
        assert level == "low"
        assert "increased" in reason.lower()


# ════════════════════════════════════════════════════════════════════════════
# Provider metadata
# ════════════════════════════════════════════════════════════════════════════


class TestProviderMetadata:
    def test_app_provider_metadata(self):
        changes = compute_diff(
            _snap([_app_record(status="ACTIVE")]),
            _snap([_app_record(status="INACTIVE")]),
        )
        change = _find_field_change(changes, "status")
        pm = change["provider_metadata"]
        assert pm["record_type"] == "okta_application"
        assert pm["tenant_id"] == "id:t1"
        assert pm["app_id"] == "app1"
        assert pm["label"] == "My App"
        assert pm["sign_on_mode"] == "OPENID_CONNECT"

    def test_user_assignment_provider_metadata(self):
        changes = compute_diff(_snap([]), _snap([_user_assignment_record()]))
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == "okta_application_user_assignment"
        assert pm["app_id"] == "app1"
        assert pm["app_label"] == "My App"
        assert pm["user_login"] == "u1@example.com"

    def test_group_assignment_provider_metadata(self):
        changes = compute_diff(_snap([]), _snap([_group_assignment_record()]))
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == "okta_application_group_assignment"
        assert pm["app_id"] == "app1"
        assert pm["group_name"] == "Engineering"

    def test_provider_metadata_never_includes_secrets(self):
        changes = compute_diff(_snap([]), _snap([_app_record()]))
        pm = changes[0]["provider_metadata"]
        assert "client_secret" not in pm
        assert "credentials" not in pm
        assert "settings" not in pm


# ════════════════════════════════════════════════════════════════════════════
# Ignored timestamps
# ════════════════════════════════════════════════════════════════════════════


class TestIgnoredTimestamps:
    def test_creation_timestamp_not_tracked(self):
        fields = _tracked_fields_for({"record_type": "okta_application"})
        assert "created" not in fields
        assert "lastUpdated" not in fields

    def test_no_change_from_untracked_fields_alone(self):
        prev = [_app_record()]
        prev[0]["created"] = "2020-01-01T00:00:00.000Z"
        new = [_app_record()]
        new[0]["created"] = "2024-01-01T00:00:00.000Z"
        changes = compute_diff(_snap(prev), _snap(new))
        assert changes == []

    def test_unmapped_application_subtype_returns_empty(self):
        fields = _tracked_fields_for({"record_type": "okta_application_totally_unknown_future_subtype"})
        assert fields == ()
