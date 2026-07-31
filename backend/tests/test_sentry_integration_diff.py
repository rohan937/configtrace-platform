"""Sentry organization integration / repository / code-mapping /
ownership-rule diff/risk-classification tests (Sentry message 4 of 8).

Uses the REAL ``compute_diff()`` and ``classify_sentry_change()`` — never
hand-built Change objects standing in for the diff pipeline — to verify
integration disabled/removed, repository detached, code mapping removed/
root-cleared, ownership rule removed/owner-changed/invalid, provider
metadata, and reordered-input stability.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules.sentry import classify_sentry_change

_ORG_ID = "id:999"


def _snap(records: list[dict]) -> NS:
    return NS(state=records)


def _integration(iid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_organization_integration",
        "record_id": f"{_ORG_ID}/organization_integration/{iid}",
        "provider_resource_id": f"integrations/{iid}",
        "organization_id": _ORG_ID,
        "integration_id": iid,
        "name": "my-org",
        "provider_category": "github",
        "status_category": "active",
        "external_id": "1",
        "feature_categories": ["commits"],
        "out_of_date": False,
    }
    base.update(overrides)
    return base


def _repo(rid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_repository",
        "record_id": f"{_ORG_ID}/repository/{rid}",
        "provider_resource_id": f"repos/{rid}",
        "organization_id": _ORG_ID,
        "repository_id": rid,
        "name": "my-org/my-repo",
        "provider_category": "github",
        "status_category": "active",
        "integration_id": "i1",
        "external_id": "1",
        "date_created": "2020-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def _code_mapping(cid: str, **overrides) -> dict:
    base = {
        "record_type": "sentry_code_mapping",
        "record_id": f"{_ORG_ID}/code_mapping/{cid}",
        "provider_resource_id": f"code-mappings/{cid}",
        "organization_id": _ORG_ID,
        "mapping_id": cid,
        "project_id": "p1",
        "repository_id": "r1",
        "integration_id": "i1",
        "stack_root_configured": True,
        "source_root_configured": True,
        "default_branch_configured": True,
        "automatically_generated": False,
    }
    base.update(overrides)
    return base


def _ownership_rule(pid: str, rule_index: int, owner_index: int, **overrides) -> dict:
    base = {
        "record_type": "sentry_ownership_rule",
        "record_id": f"{_ORG_ID}/ownership_rule/{pid}/{rule_index}/{owner_index}",
        "provider_resource_id": f"ownership/{pid}/{rule_index}/{owner_index}",
        "organization_id": _ORG_ID,
        "project_id": pid,
        "rule_index": rule_index,
        "owner_index": owner_index,
        "matcher_category": "path",
        "owner_type_category": "team",
        "owner_id": "55",
        "is_active": True,
        "fallthrough": True,
        "auto_assignment_category": "off",
    }
    base.update(overrides)
    return base


def _diff(prev: list[dict], new: list[dict]):
    return compute_diff(_snap(prev), _snap(new))


def _find(changes, *, field_path=None, change_type=None):
    for c in changes:
        if change_type is not None and c["change_type"] != change_type:
            continue
        if field_path is not None and c.get("field_path") != field_path:
            continue
        return c
    raise AssertionError(f"no change matched field_path={field_path!r} change_type={change_type!r} in {changes}")


# ════════════════════════════════════════════════════════════════════════════
# Organization integration
# ════════════════════════════════════════════════════════════════════════════


class TestOrganizationIntegrationDiff:
    def test_added_is_low(self):
        changes = _diff([], [_integration("i1")])
        c = _find(changes, change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_removed_is_medium(self):
        changes = _diff([_integration("i1")], [])
        c = _find(changes, change_type="removed")
        assert classify_sentry_change(c)[0] == "medium"

    def test_disabled_is_medium(self):
        changes = _diff(
            [_integration("i1", status_category="active")],
            [_integration("i1", status_category="disabled")],
        )
        c = _find(changes, field_path="status_category")
        assert classify_sentry_change(c)[0] == "medium"

    def test_reenabled_is_low(self):
        changes = _diff(
            [_integration("i1", status_category="disabled")],
            [_integration("i1", status_category="active")],
        )
        c = _find(changes, field_path="status_category")
        assert classify_sentry_change(c)[0] == "low"

    def test_provider_change_is_medium(self):
        changes = _diff(
            [_integration("i1", provider_category="github")],
            [_integration("i1", provider_category="gitlab")],
        )
        c = _find(changes, field_path="provider_category")
        assert classify_sentry_change(c)[0] == "medium"

    def test_feature_categories_not_tracked(self):
        changes = _diff(
            [_integration("i1", feature_categories=["commits"])],
            [_integration("i1", feature_categories=["commits", "issue-basic"])],
        )
        assert changes == []

    def test_out_of_date_not_tracked(self):
        changes = _diff(
            [_integration("i1", out_of_date=False)],
            [_integration("i1", out_of_date=True)],
        )
        assert changes == []

    def test_provider_metadata_carries_context(self):
        changes = _diff([], [_integration("i1")])
        c = _find(changes, change_type="added")
        assert c["provider_metadata"]["integration_id"] == "i1"
        assert c["provider_metadata"]["provider_category"] == "github"


# ════════════════════════════════════════════════════════════════════════════
# Repository
# ════════════════════════════════════════════════════════════════════════════


class TestRepositoryDiff:
    def test_added_is_low(self):
        changes = _diff([], [_repo("r1")])
        c = _find(changes, change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_removed_is_low(self):
        changes = _diff([_repo("r1")], [])
        c = _find(changes, change_type="removed")
        assert classify_sentry_change(c)[0] == "low"

    def test_rename_is_low(self):
        changes = _diff(
            [_repo("r1", name="old/name")],
            [_repo("r1", name="new/name")],
        )
        c = _find(changes, field_path="name")
        assert classify_sentry_change(c)[0] == "low"

    def test_detached_from_integration_is_medium(self):
        changes = _diff(
            [_repo("r1", integration_id="i1")],
            [_repo("r1", integration_id="i2")],
        )
        c = _find(changes, field_path="integration_id")
        assert classify_sentry_change(c)[0] == "medium"

    def test_disabled_is_medium(self):
        changes = _diff(
            [_repo("r1", status_category="active")],
            [_repo("r1", status_category="disabled")],
        )
        c = _find(changes, field_path="status_category")
        assert classify_sentry_change(c)[0] == "medium"


# ════════════════════════════════════════════════════════════════════════════
# Code mapping
# ════════════════════════════════════════════════════════════════════════════


class TestCodeMappingDiff:
    def test_added_is_low(self):
        changes = _diff([], [_code_mapping("cm1")])
        c = _find(changes, change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_removed_is_medium(self):
        changes = _diff([_code_mapping("cm1")], [])
        c = _find(changes, change_type="removed")
        assert classify_sentry_change(c)[0] == "medium"

    def test_repository_target_changed_is_medium(self):
        changes = _diff(
            [_code_mapping("cm1", repository_id="r1")],
            [_code_mapping("cm1", repository_id="r2")],
        )
        c = _find(changes, field_path="repository_id")
        assert classify_sentry_change(c)[0] == "medium"

    def test_stack_root_cleared_is_medium(self):
        changes = _diff(
            [_code_mapping("cm1", stack_root_configured=True)],
            [_code_mapping("cm1", stack_root_configured=False)],
        )
        c = _find(changes, field_path="stack_root_configured")
        assert classify_sentry_change(c)[0] == "medium"

    def test_stack_root_set_is_low(self):
        changes = _diff(
            [_code_mapping("cm1", stack_root_configured=False)],
            [_code_mapping("cm1", stack_root_configured=True)],
        )
        c = _find(changes, field_path="stack_root_configured")
        assert classify_sentry_change(c)[0] == "low"


# ════════════════════════════════════════════════════════════════════════════
# Ownership rule
# ════════════════════════════════════════════════════════════════════════════


class TestOwnershipRuleDiff:
    def test_added_is_low(self):
        changes = _diff([], [_ownership_rule("p1", 0, 0)])
        c = _find(changes, change_type="added")
        assert classify_sentry_change(c)[0] == "low"

    def test_removed_is_medium(self):
        changes = _diff([_ownership_rule("p1", 0, 0)], [])
        c = _find(changes, change_type="removed")
        severity, msg = classify_sentry_change(c)
        assert severity == "medium"
        assert "does not by itself prove" in msg

    def test_owner_changed_is_medium(self):
        changes = _diff(
            [_ownership_rule("p1", 0, 0, owner_id="55")],
            [_ownership_rule("p1", 0, 0, owner_id="66")],
        )
        c = _find(changes, field_path="owner_id")
        assert classify_sentry_change(c)[0] == "medium"

    def test_matcher_change_is_low(self):
        changes = _diff(
            [_ownership_rule("p1", 0, 0, matcher_category="path")],
            [_ownership_rule("p1", 0, 0, matcher_category="url")],
        )
        c = _find(changes, field_path="matcher_category")
        assert classify_sentry_change(c)[0] == "low"

    def test_config_deactivated_is_medium(self):
        changes = _diff(
            [_ownership_rule("p1", 0, 0, is_active=True)],
            [_ownership_rule("p1", 0, 0, is_active=False)],
        )
        c = _find(changes, field_path="is_active")
        assert classify_sentry_change(c)[0] == "medium"

    def test_config_activated_is_low(self):
        changes = _diff(
            [_ownership_rule("p1", 0, 0, is_active=False)],
            [_ownership_rule("p1", 0, 0, is_active=True)],
        )
        c = _find(changes, field_path="is_active")
        assert classify_sentry_change(c)[0] == "low"

    def test_provider_metadata_carries_context(self):
        changes = _diff([], [_ownership_rule("p1", 0, 0)])
        c = _find(changes, change_type="added")
        assert c["provider_metadata"]["project_id"] == "p1"
        assert c["provider_metadata"]["owner_type_category"] == "team"

    def test_reordered_rules_produce_no_diff(self):
        prev = [_ownership_rule("p1", 0, 0), _ownership_rule("p1", 1, 0)]
        new = [_ownership_rule("p1", 1, 0), _ownership_rule("p1", 0, 0)]
        assert _diff(prev, new) == []
