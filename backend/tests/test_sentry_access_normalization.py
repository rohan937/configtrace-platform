"""Sentry project/team/member/access normalization tests (Sentry message 2
of 8).

Covers the pure ``SentryConnector._normalize_*`` methods and the
``sentry_schema`` categorizers they use: stable identity (rename
preserves identity), status/platform/org-role/team-role/member-status
taxonomies, unknown-state discipline, and the sensitive-data boundary
(never email/DSN/tokens on any message-2 record). Collection-level
behavior is covered in ``test_sentry_access_collection.py``; diff/risk
behavior in ``test_sentry_access_diff.py``.
"""

from __future__ import annotations

from app.connectors.sentry import SentryConnector
from app.connectors.sentry_schema import (
    MEMBER_STATUS_ACTIVE,
    MEMBER_STATUS_EXPIRED,
    MEMBER_STATUS_PENDING,
    MEMBER_STATUS_UNKNOWN,
    ORG_ROLE_MEMBER,
    ORG_ROLE_OWNER,
    ORG_ROLE_UNKNOWN,
    PLATFORM_CATEGORY_JAVA,
    PLATFORM_CATEGORY_JAVASCRIPT,
    PLATFORM_CATEGORY_OTHER,
    PLATFORM_CATEGORY_PYTHON,
    PLATFORM_CATEGORY_UNKNOWN,
    PROJECT_STATUS_ACTIVE,
    PROJECT_STATUS_DISABLED,
    PROJECT_STATUS_UNKNOWN,
    TEAM_ROLE_ADMIN,
    TEAM_ROLE_CONTRIBUTOR,
    TEAM_ROLE_UNKNOWN,
    categorize_member_status,
    categorize_org_role,
    categorize_platform,
    categorize_project_status,
    categorize_team_role,
)

_ORG_ID = "id:999"


# ════════════════════════════════════════════════════════════════════════════
# Project normalization
# ════════════════════════════════════════════════════════════════════════════


class TestProjectNormalization:
    def test_normalizes_basic_fields(self):
        rec = SentryConnector._normalize_project(_ORG_ID, {
            "id": "p1", "slug": "My-Proj", "name": "My Project",
            "platform": "python-django", "status": "active", "dateCreated": "2020-01-01T00:00:00Z",
        })
        assert rec["record_type"] == "sentry_project"
        assert rec["record_id"] == f"{_ORG_ID}/project/p1"
        assert rec["project_id"] == "p1"
        assert rec["slug"] == "my-proj"
        assert rec["name"] == "My Project"
        assert rec["platform_category"] == PLATFORM_CATEGORY_PYTHON
        assert rec["status_category"] == PROJECT_STATUS_ACTIVE

    def test_missing_id_returns_none(self):
        assert SentryConnector._normalize_project(_ORG_ID, {"slug": "x"}) is None

    def test_rename_preserves_identity(self):
        before = SentryConnector._normalize_project(_ORG_ID, {"id": "p1", "slug": "old-slug", "name": "Old Name"})
        after = SentryConnector._normalize_project(_ORG_ID, {"id": "p1", "slug": "new-slug", "name": "New Name"})
        assert before["record_id"] == after["record_id"]
        assert before["project_id"] == after["project_id"]
        assert before["slug"] != after["slug"]

    def test_integer_id_accepted(self):
        rec = SentryConnector._normalize_project(_ORG_ID, {"id": 12345, "slug": "p"})
        assert rec["project_id"] == "12345"

    def test_missing_platform_is_unknown_not_other(self):
        rec = SentryConnector._normalize_project(_ORG_ID, {"id": "p1"})
        assert rec["platform_category"] == PLATFORM_CATEGORY_UNKNOWN

    def test_missing_status_is_unknown_not_active(self):
        rec = SentryConnector._normalize_project(_ORG_ID, {"id": "p1"})
        assert rec["status_category"] == PROJECT_STATUS_UNKNOWN

    def test_never_stores_dsn_or_client_keys(self):
        rec = SentryConnector._normalize_project(_ORG_ID, {
            "id": "p1", "slug": "p", "dsn": "https://key@sentry.io/1", "keys": [{"public": "abc"}],
        })
        blob = str(rec)
        assert "dsn" not in blob.lower() and "abc" not in blob


class TestPlatformTaxonomy:
    def test_recognized_prefixes(self):
        assert categorize_platform("python-django") == PLATFORM_CATEGORY_PYTHON
        assert categorize_platform("javascript-react") == PLATFORM_CATEGORY_JAVASCRIPT
        assert categorize_platform("java-android") == PLATFORM_CATEGORY_JAVA
        assert categorize_platform("node-express") == PLATFORM_CATEGORY_JAVASCRIPT

    def test_unrecognized_string_is_other_not_unknown(self):
        assert categorize_platform("some-brand-new-platform") == PLATFORM_CATEGORY_OTHER

    def test_missing_is_unknown_not_other(self):
        assert categorize_platform(None) == PLATFORM_CATEGORY_UNKNOWN
        assert categorize_platform("") == PLATFORM_CATEGORY_UNKNOWN
        assert categorize_platform(123) == PLATFORM_CATEGORY_UNKNOWN


class TestProjectStatusTaxonomy:
    def test_recognized_values(self):
        assert categorize_project_status("active") == PROJECT_STATUS_ACTIVE
        assert categorize_project_status("disabled") == PROJECT_STATUS_DISABLED

    def test_unrecognized_or_missing_is_unknown(self):
        assert categorize_project_status("something-new") == PROJECT_STATUS_UNKNOWN
        assert categorize_project_status(None) == PROJECT_STATUS_UNKNOWN
        assert categorize_project_status(123) == PROJECT_STATUS_UNKNOWN


# ════════════════════════════════════════════════════════════════════════════
# Team normalization
# ════════════════════════════════════════════════════════════════════════════


class TestTeamNormalization:
    def test_normalizes_basic_fields(self):
        rec = SentryConnector._normalize_team(_ORG_ID, {
            "id": "t1", "slug": "My-Team", "name": "My Team", "memberCount": 5,
            "dateCreated": "2020-01-01T00:00:00Z",
        })
        assert rec["record_type"] == "sentry_team"
        assert rec["record_id"] == f"{_ORG_ID}/team/t1"
        assert rec["team_id"] == "t1"
        assert rec["slug"] == "my-team"
        assert rec["member_count"] == 5

    def test_missing_id_returns_none(self):
        assert SentryConnector._normalize_team(_ORG_ID, {"slug": "x"}) is None

    def test_rename_preserves_identity(self):
        before = SentryConnector._normalize_team(_ORG_ID, {"id": "t1", "slug": "old", "name": "Old"})
        after = SentryConnector._normalize_team(_ORG_ID, {"id": "t1", "slug": "new", "name": "New"})
        assert before["record_id"] == after["record_id"]
        assert before["team_id"] == after["team_id"]

    def test_missing_member_count_is_none_not_zero(self):
        rec = SentryConnector._normalize_team(_ORG_ID, {"id": "t1"})
        assert rec["member_count"] is None


# ════════════════════════════════════════════════════════════════════════════
# Member normalization
# ════════════════════════════════════════════════════════════════════════════


class TestMemberNormalization:
    def test_normalizes_basic_fields(self):
        rec = SentryConnector._normalize_member(_ORG_ID, {
            "id": "m1", "orgRole": "owner", "pending": False, "expired": False,
            "email": "someone@example.com", "dateCreated": "2020-01-01T00:00:00Z",
        })
        assert rec["record_type"] == "sentry_member"
        assert rec["record_id"] == f"{_ORG_ID}/member/m1"
        assert rec["member_id"] == "m1"
        assert rec["org_role_category"] == ORG_ROLE_OWNER
        assert rec["member_status_category"] == MEMBER_STATUS_ACTIVE

    def test_missing_id_returns_none(self):
        assert SentryConnector._normalize_member(_ORG_ID, {"orgRole": "member"}) is None

    def test_falls_back_to_legacy_role_field(self):
        rec = SentryConnector._normalize_member(_ORG_ID, {"id": "m1", "role": "manager"})
        assert rec["org_role_category"] == "manager"

    def test_never_stores_email_phone_or_other_pii(self):
        rec = SentryConnector._normalize_member(_ORG_ID, {
            "id": "m1", "orgRole": "member", "email": "someone@example.com",
            "phone": "+1-555-5555", "avatarUrl": "https://example.com/a.png",
            "ip_address": "10.0.0.1",
        })
        blob = str(rec)
        assert "someone@example.com" not in blob
        assert "555-5555" not in blob
        assert "avatarUrl" not in blob
        assert "10.0.0.1" not in blob
        assert set(rec.keys()) == {
            "record_type", "record_id", "provider_resource_id", "organization_id",
            "member_id", "org_role_category", "member_status_category", "date_created",
        }

    def test_if_only_stable_id_present_email_never_used_as_identity(self):
        # Even with no other identity fields present, the member's own
        # numeric/string `id` (never email) is what identity is built from.
        rec = SentryConnector._normalize_member(_ORG_ID, {"id": "m1", "email": "someone@example.com"})
        assert rec["member_id"] == "m1"
        assert "someone@example.com" not in str(rec)


class TestOrgRoleTaxonomy:
    def test_recognized_values(self):
        assert categorize_org_role("owner") == ORG_ROLE_OWNER
        assert categorize_org_role("member") == ORG_ROLE_MEMBER
        assert categorize_org_role("MEMBER") == ORG_ROLE_MEMBER  # case-insensitive

    def test_unrecognized_or_missing_is_unknown_never_ordinary_member(self):
        assert categorize_org_role("some-new-tier") == ORG_ROLE_UNKNOWN
        assert categorize_org_role(None) == ORG_ROLE_UNKNOWN
        assert categorize_org_role(123) == ORG_ROLE_UNKNOWN


class TestTeamRoleTaxonomy:
    def test_recognized_values(self):
        assert categorize_team_role("admin") == TEAM_ROLE_ADMIN
        assert categorize_team_role("contributor") == TEAM_ROLE_CONTRIBUTOR

    def test_unrecognized_or_missing_is_unknown(self):
        assert categorize_team_role("lead") == TEAM_ROLE_UNKNOWN
        assert categorize_team_role(None) == TEAM_ROLE_UNKNOWN


class TestMemberStatusTaxonomy:
    def test_active_is_neither_pending_nor_expired(self):
        assert categorize_member_status(False, False) == MEMBER_STATUS_ACTIVE

    def test_pending_true_expired_false(self):
        assert categorize_member_status(True, False) == MEMBER_STATUS_PENDING

    def test_expired_takes_precedence_over_pending(self):
        assert categorize_member_status(True, True) == MEMBER_STATUS_EXPIRED

    def test_missing_or_non_boolean_is_unknown_never_active(self):
        assert categorize_member_status(None, None) == MEMBER_STATUS_UNKNOWN
        assert categorize_member_status(None, False) == MEMBER_STATUS_UNKNOWN
        assert categorize_member_status(False, None) == MEMBER_STATUS_UNKNOWN
        assert categorize_member_status("false", "false") == MEMBER_STATUS_UNKNOWN


# ════════════════════════════════════════════════════════════════════════════
# Team membership / project-team assignment edges
# ════════════════════════════════════════════════════════════════════════════


class TestTeamMembershipNormalization:
    def test_normalizes_edge(self):
        rec = SentryConnector._normalize_team_membership(
            _ORG_ID, team_id="t1", member_id="m1", team_role_category=TEAM_ROLE_ADMIN,
        )
        assert rec["record_type"] == "sentry_team_membership"
        assert rec["record_id"] == f"{_ORG_ID}/team_membership/t1/m1"
        assert rec["team_id"] == "t1"
        assert rec["member_id"] == "m1"
        assert rec["team_role_category"] == TEAM_ROLE_ADMIN


class TestProjectTeamAssignmentNormalization:
    def test_normalizes_edge_and_preserves_direction(self):
        rec = SentryConnector._normalize_project_team_assignment(_ORG_ID, project_id="p1", team_id="t1")
        assert rec["record_type"] == "sentry_project_team_assignment"
        assert rec["record_id"] == f"{_ORG_ID}/project_team_assignment/p1/t1"
        assert rec["project_id"] == "p1"
        assert rec["team_id"] == "t1"


# ════════════════════════════════════════════════════════════════════════════
# Stable-entity-id helper
# ════════════════════════════════════════════════════════════════════════════


class TestStableEntityId:
    def test_string_id(self):
        assert SentryConnector._stable_entity_id("abc") == "abc"

    def test_integer_id(self):
        assert SentryConnector._stable_entity_id(42) == "42"

    def test_missing_or_empty_returns_none(self):
        assert SentryConnector._stable_entity_id(None) is None
        assert SentryConnector._stable_entity_id("") is None
        assert SentryConnector._stable_entity_id("   ") is None
        assert SentryConnector._stable_entity_id(3.14) is None
