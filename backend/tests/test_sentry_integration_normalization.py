"""Sentry organization integration / repository / code-mapping /
ownership-rule normalization tests (Sentry message 4 of 8).

Covers the pure ``SentryConnector._normalize_*`` methods and the
``sentry_schema`` categorizers they use: stable identity, provider/status
taxonomies, ownership matcher/owner/auto-assignment taxonomies, unknown-
state discipline, and the sensitive-data boundary (never OAuth tokens,
webhook URLs/secrets, repository credentials, raw clone URLs, raw
ownership-rule text, or email addresses on any message-4 record).
Collection-level behavior is covered in
``test_sentry_integration_collection.py``; diff/risk behavior in
``test_sentry_integration_diff.py``.
"""

from __future__ import annotations

from app.connectors.sentry import SentryConnector
from app.connectors.sentry_schema import (
    AUTO_ASSIGNMENT_OFF,
    AUTO_ASSIGNMENT_SUSPECT_COMMITS,
    AUTO_ASSIGNMENT_UNKNOWN,
    MATCHER_CATEGORY_CODEOWNERS,
    MATCHER_CATEGORY_PATH,
    MATCHER_CATEGORY_TAG,
    MATCHER_CATEGORY_UNKNOWN,
    OBJECT_STATUS_ACTIVE,
    OBJECT_STATUS_DISABLED,
    OBJECT_STATUS_UNKNOWN,
    OWNER_TYPE_TEAM,
    OWNER_TYPE_UNKNOWN,
    OWNER_TYPE_USER,
    PROVIDER_CATEGORY_AZURE_DEVOPS,
    PROVIDER_CATEGORY_GITHUB,
    PROVIDER_CATEGORY_OTHER,
    PROVIDER_CATEGORY_UNKNOWN,
    categorize_auto_assignment,
    categorize_matcher,
    categorize_object_status,
    categorize_provider,
)

_ORG_ID = "id:999"


class TestOrganizationIntegrationNormalization:
    def test_normalizes_basic_fields(self):
        rec = SentryConnector._normalize_organization_integration(_ORG_ID, {
            "id": "i1", "name": "my-org", "provider": {"key": "github", "features": ["commits", "issue-basic"]},
            "organizationIntegrationStatus": "active", "externalId": "12345", "outOfDate": False,
        })
        assert rec["record_type"] == "sentry_organization_integration"
        assert rec["record_id"] == f"{_ORG_ID}/organization_integration/i1"
        assert rec["provider_category"] == PROVIDER_CATEGORY_GITHUB
        assert rec["status_category"] == OBJECT_STATUS_ACTIVE
        assert rec["external_id"] == "12345"
        assert rec["feature_categories"] == ["commits", "issue-basic"]
        assert rec["out_of_date"] is False

    def test_missing_id_returns_none(self):
        assert SentryConnector._normalize_organization_integration(_ORG_ID, {}) is None

    def test_falls_back_to_status_when_org_integration_status_absent(self):
        rec = SentryConnector._normalize_organization_integration(_ORG_ID, {"id": "i1", "status": "disabled"})
        assert rec["status_category"] == OBJECT_STATUS_DISABLED

    def test_never_stores_oauth_or_config_fields(self):
        rec = SentryConnector._normalize_organization_integration(_ORG_ID, {
            "id": "i1", "name": "x", "configOrganization": {"secret": "abc"},
            "configData": {"token": "xyz"}, "scopes": ["repo", "admin:org"],
        })
        blob = str(rec)
        assert "abc" not in blob and "xyz" not in blob
        assert "configOrganization" not in rec and "configData" not in rec and "scopes" not in rec

    def test_missing_feature_categories_is_none(self):
        rec = SentryConnector._normalize_organization_integration(_ORG_ID, {"id": "i1"})
        assert rec["feature_categories"] is None


class TestRepositoryNormalization:
    def test_normalizes_basic_fields(self):
        rec = SentryConnector._normalize_repository(_ORG_ID, {
            "id": "r1", "name": "my-org/my-repo", "provider": {"id": "integrations:github", "name": "GitHub"},
            "status": "active", "integrationId": "i1", "externalId": "42", "dateCreated": "2020-01-01T00:00:00Z",
            "url": "https://github.com/my-org/my-repo",
        })
        assert rec["record_type"] == "sentry_repository"
        assert rec["record_id"] == f"{_ORG_ID}/repository/r1"
        assert rec["provider_category"] == PROVIDER_CATEGORY_GITHUB
        assert rec["status_category"] == OBJECT_STATUS_ACTIVE
        assert rec["integration_id"] == "i1"
        assert "url" not in rec
        assert "github.com" not in str(rec)

    def test_missing_id_returns_none(self):
        assert SentryConnector._normalize_repository(_ORG_ID, {}) is None

    def test_never_stores_clone_url_or_credentials(self):
        rec = SentryConnector._normalize_repository(_ORG_ID, {
            "id": "r1", "name": "x", "url": "https://token:secret@github.com/org/repo.git",
        })
        assert "secret" not in str(rec)
        assert "token" not in str(rec)


class TestCodeMappingNormalization:
    def test_normalizes_basic_fields(self):
        rec = SentryConnector._normalize_code_mapping(_ORG_ID, {
            "id": "cm1", "projectId": "p1", "repoId": "r1", "integrationId": "i1",
            "stackRoot": "src/", "sourceRoot": "", "defaultBranch": "main", "automaticallyGenerated": False,
        })
        assert rec["record_type"] == "sentry_code_mapping"
        assert rec["record_id"] == f"{_ORG_ID}/code_mapping/cm1"
        assert rec["project_id"] == "p1"
        assert rec["repository_id"] == "r1"
        assert rec["stack_root_configured"] is True
        assert rec["source_root_configured"] is False
        assert rec["default_branch_configured"] is True
        assert "src/" not in str(rec)

    def test_missing_id_returns_none(self):
        assert SentryConnector._normalize_code_mapping(_ORG_ID, {}) is None

    def test_missing_roots_are_false_not_none(self):
        rec = SentryConnector._normalize_code_mapping(_ORG_ID, {"id": "cm1"})
        assert rec["stack_root_configured"] is False
        assert rec["source_root_configured"] is False
        assert rec["default_branch_configured"] is False

    def test_never_stores_raw_path_text(self):
        rec = SentryConnector._normalize_code_mapping(_ORG_ID, {
            "id": "cm1", "stackRoot": "internal/secret-service/src", "sourceRoot": "backend/app",
        })
        assert "internal/secret-service" not in str(rec)
        assert "backend/app" not in str(rec)


class TestOwnershipOwnerCategorization:
    def test_team_owner_resolved(self):
        assert SentryConnector._categorize_ownership_owner({"type": "team", "id": "55", "name": "frontend"}) == (OWNER_TYPE_TEAM, "55")

    def test_user_owner_resolved(self):
        assert SentryConnector._categorize_ownership_owner({"type": "user", "id": "9", "name": "someone"}) == (OWNER_TYPE_USER, "9")

    def test_unresolved_owner_no_id_is_unknown(self):
        assert SentryConnector._categorize_ownership_owner({"type": "user", "name": "someone@example.com"}) == (OWNER_TYPE_UNKNOWN, None)

    def test_never_returns_email_or_name_as_id(self):
        owner_type, owner_id = SentryConnector._categorize_ownership_owner({"type": "user", "name": "someone@example.com"})
        assert owner_id != "someone@example.com"
        assert owner_id is None


class TestOwnershipRuleNormalization:
    def test_normalizes_rules_from_schema(self):
        raw = {
            "raw": "path:*.js #frontend", "fallthrough": True, "isActive": True,
            "autoAssignment": "Turn off Auto-Assignment", "codeownersAutoSync": False,
            "schema": {"$version": 1, "rules": [
                {"matcher": {"type": "path", "pattern": "*.js"}, "owners": [{"type": "team", "name": "frontend", "id": "55"}]},
            ]},
        }
        recs = SentryConnector._normalize_ownership_rules(_ORG_ID, "p1", raw)
        assert len(recs) == 1
        rec = recs[0]
        assert rec["record_type"] == "sentry_ownership_rule"
        assert rec["record_id"] == f"{_ORG_ID}/ownership_rule/p1/0/0"
        assert rec["matcher_category"] == MATCHER_CATEGORY_PATH
        assert rec["owner_type_category"] == OWNER_TYPE_TEAM
        assert rec["owner_id"] == "55"
        assert rec["auto_assignment_category"] == AUTO_ASSIGNMENT_OFF
        assert rec["is_active"] is True
        assert rec["fallthrough"] is True

    def test_never_reads_raw_ownership_text(self):
        raw = {
            "raw": "path:*.js user@company-internal.example.com",
            "schema": {"$version": 1, "rules": [
                {"matcher": {"type": "path", "pattern": "*.js"}, "owners": [{"type": "user", "name": "user@company-internal.example.com"}]},
            ]},
        }
        recs = SentryConnector._normalize_ownership_rules(_ORG_ID, "p1", raw)
        assert "user@company-internal.example.com" not in str(recs)

    def test_missing_schema_returns_no_records(self):
        assert SentryConnector._normalize_ownership_rules(_ORG_ID, "p1", {"raw": None}) == []

    def test_rule_with_no_owners_still_emits_one_record(self):
        raw = {"schema": {"$version": 1, "rules": [{"matcher": {"type": "path", "pattern": "*.py"}, "owners": []}]}}
        recs = SentryConnector._normalize_ownership_rules(_ORG_ID, "p1", raw)
        assert len(recs) == 1
        assert recs[0]["owner_type_category"] == OWNER_TYPE_UNKNOWN
        assert recs[0]["owner_id"] is None

    def test_multiple_owners_per_rule_each_get_a_record(self):
        raw = {"schema": {"$version": 1, "rules": [
            {"matcher": {"type": "path", "pattern": "*.py"}, "owners": [
                {"type": "team", "id": "1"}, {"type": "user", "id": "2"},
            ]},
        ]}}
        recs = SentryConnector._normalize_ownership_rules(_ORG_ID, "p1", raw)
        assert len(recs) == 2
        assert [r["owner_index"] for r in recs] == [0, 1]
        assert [r["owner_type_category"] for r in recs] == [OWNER_TYPE_TEAM, OWNER_TYPE_USER]

    def test_rule_order_preserved_via_rule_index(self):
        raw = {"schema": {"$version": 1, "rules": [
            {"matcher": {"type": "path", "pattern": "*.py"}, "owners": [{"type": "team", "id": "1"}]},
            {"matcher": {"type": "codeowners", "pattern": "CODEOWNERS"}, "owners": [{"type": "team", "id": "2"}]},
        ]}}
        recs = SentryConnector._normalize_ownership_rules(_ORG_ID, "p1", raw)
        assert [r["rule_index"] for r in recs] == [0, 1]
        assert recs[1]["matcher_category"] == MATCHER_CATEGORY_CODEOWNERS


class TestObjectStatusTaxonomy:
    def test_recognized_values(self):
        assert categorize_object_status("active") == OBJECT_STATUS_ACTIVE
        assert categorize_object_status("disabled") == OBJECT_STATUS_DISABLED

    def test_missing_is_unknown(self):
        assert categorize_object_status(None) == OBJECT_STATUS_UNKNOWN


class TestProviderTaxonomy:
    def test_recognized_via_substring(self):
        assert categorize_provider("github") == PROVIDER_CATEGORY_GITHUB
        assert categorize_provider("integrations:github") == PROVIDER_CATEGORY_GITHUB
        assert categorize_provider("vsts") == PROVIDER_CATEGORY_AZURE_DEVOPS

    def test_unrecognized_is_other_missing_is_unknown(self):
        assert categorize_provider("some-new-vcs") == PROVIDER_CATEGORY_OTHER
        assert categorize_provider(None) == PROVIDER_CATEGORY_UNKNOWN


class TestMatcherTaxonomy:
    def test_recognized_values(self):
        assert categorize_matcher("path") == MATCHER_CATEGORY_PATH
        assert categorize_matcher("codeowners") == MATCHER_CATEGORY_CODEOWNERS

    def test_tag_prefix(self):
        assert categorize_matcher("tags.environment") == MATCHER_CATEGORY_TAG

    def test_missing_is_unknown(self):
        assert categorize_matcher(None) == MATCHER_CATEGORY_UNKNOWN


class TestAutoAssignmentTaxonomy:
    def test_recognized_values(self):
        assert categorize_auto_assignment("Auto Assign to Suspect Commits") == AUTO_ASSIGNMENT_SUSPECT_COMMITS
        assert categorize_auto_assignment("Turn off Auto-Assignment") == AUTO_ASSIGNMENT_OFF

    def test_missing_is_unknown(self):
        assert categorize_auto_assignment(None) == AUTO_ASSIGNMENT_UNKNOWN
