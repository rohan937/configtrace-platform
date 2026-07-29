"""Snowflake security-policy Change-classification tests (Snowflake message
4 of 8).

Uses the REAL ``compute_diff()`` -> ``classify_snowflake_change()`` pipeline
(via ``risk_service.classify_change()``) for every case — no hand-built
Change dicts standing in for the real diff pipeline.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.services.diff_service import compute_diff
from app.services.risk_service import classify_change

_ACCOUNT_ID = "id:acme-prod"


def _diff(prev_records: list[dict], new_records: list[dict]):
    prev = SimpleNamespace(state=prev_records)
    new = SimpleNamespace(state=new_records)
    return compute_diff(prev, new)


def _only_change(changes):
    assert len(changes) == 1, f"expected exactly 1 change, got {len(changes)}: {changes}"
    return changes[0]


def _network_policy(name="OPEN", **overrides):
    record = {
        "record_type": "snowflake_network_policy",
        "record_id": f"{_ACCOUNT_ID}/network_policy/{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "policy_name": name,
        "owner": "SECURITYADMIN",
        "allowed_ipv4_count": 1,
        "blocked_ipv4_count": 0,
        "allowed_network_rule_count": 0,
        "blocked_network_rule_count": 0,
        "has_allowlist": True,
        "has_blocklist": False,
        "allows_anywhere_ipv4": "false",
        "allows_anywhere_ipv6": "false",
        "detail_collection_status": "complete",
    }
    record.update(overrides)
    return record


def _network_rule(name="MY_RULE", **overrides):
    record = {
        "record_type": "snowflake_network_rule",
        "record_id": f"{_ACCOUNT_ID}/network_rule/{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "rule_name": name,
        "owner": "SYSADMIN",
        "rule_type": "HOST_PORT",
        "rule_mode": "EGRESS",
        "value_count": 3,
    }
    record.update(overrides)
    return record


def _auth_policy(name="STRICT", **overrides):
    record = {
        "record_type": "snowflake_authentication_policy",
        "record_id": f"{_ACCOUNT_ID}/authentication_policy/{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "policy_name": name,
        "owner": "SECURITYADMIN",
        "set_on": "ACCOUNT",
        "authentication_methods": ["password", "saml"],
        "mfa_enrollment": "required",
        "client_types": "all",
        "detail_collection_status": "complete",
    }
    record.update(overrides)
    return record


def _security_integration(name="MY_SAML", integration_type="saml2", **overrides):
    record = {
        "record_type": "snowflake_security_integration",
        "record_id": f"{_ACCOUNT_ID}/security_integration/{name.lower()}/{integration_type}",
        "account_id": _ACCOUNT_ID,
        "integration_name": name,
        "integration_type": integration_type,
        "enabled": "true",
        "owner": "SECURITYADMIN",
        "detail_collection_status": "complete",
    }
    record.update(overrides)
    return record


def _storage_integration(name="MY_S3", **overrides):
    record = {
        "record_type": "snowflake_storage_integration",
        "record_id": f"{_ACCOUNT_ID}/storage_integration/{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "integration_name": name,
        "enabled": "true",
        "storage_provider": "s3",
        "allowed_location_count": 2,
        "blocked_location_count": 0,
        "cloud_identity_configured": "true",
        "detail_collection_status": "complete",
    }
    record.update(overrides)
    return record


def _external_access_integration(name="MY_EAI", **overrides):
    record = {
        "record_type": "snowflake_external_access_integration",
        "record_id": f"{_ACCOUNT_ID}/external_access_integration/{name.lower()}",
        "account_id": _ACCOUNT_ID,
        "integration_name": name,
        "enabled": "true",
        "allowed_network_rule_count": 1,
        "allowed_secret_count": 0,
        "allowed_api_authentication_integration_count": 0,
        "detail_collection_status": "complete",
    }
    record.update(overrides)
    return record


# ── Network policies ──────────────────────────────────────────────────────────


class TestNetworkPolicyChangeClassification:
    def test_added_ordinary_is_low(self):
        changes = _diff([], [_network_policy()])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_added_with_broad_access_is_high(self):
        changes = _diff([], [_network_policy(allows_anywhere_ipv4="true")])
        level, reason = classify_change(_only_change(changes))
        assert level == "high"
        assert "anywhere" in reason.lower()

    def test_removed_is_medium(self):
        changes = _diff([_network_policy()], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_broad_access_introduced_is_high(self):
        changes = _diff(
            [_network_policy(allows_anywhere_ipv4="false")],
            [_network_policy(allows_anywhere_ipv4="true")],
        )
        level, reason = classify_change(_only_change(changes))
        assert level == "high"
        assert "broad" in reason.lower() or "anywhere" in reason.lower()

    def test_broad_access_removed_is_low(self):
        changes = _diff(
            [_network_policy(allows_anywhere_ipv4="true")],
            [_network_policy(allows_anywhere_ipv4="false")],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_unknown_broad_access_never_treated_as_broad(self):
        """A network policy whose broad-access state is unknown (detail
        collection failed) must never be classified as if it were True."""
        changes = _diff([], [_network_policy(allows_anywhere_ipv4="unknown", detail_collection_status="unavailable")])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_allowed_range_added_is_medium(self):
        changes = _diff(
            [_network_policy(allowed_ipv4_count=1)],
            [_network_policy(allowed_ipv4_count=3)],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_allowed_range_removed_is_low(self):
        changes = _diff(
            [_network_policy(allowed_ipv4_count=3)],
            [_network_policy(allowed_ipv4_count=1)],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_owner_change_is_medium(self):
        changes = _diff(
            [_network_policy(owner="SECURITYADMIN")],
            [_network_policy(owner="SYSADMIN")],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"


# ── Network rules ─────────────────────────────────────────────────────────────


class TestNetworkRuleChangeClassification:
    def test_added_is_low(self):
        changes = _diff([], [_network_rule()])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_removed_is_low(self):
        changes = _diff([_network_rule()], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"


# ── Authentication policies ───────────────────────────────────────────────────


class TestAuthenticationPolicyChangeClassification:
    def test_added_is_low(self):
        changes = _diff([], [_auth_policy()])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_removed_is_medium(self):
        changes = _diff([_auth_policy()], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_mfa_required_to_optional_is_high(self):
        changes = _diff(
            [_auth_policy(mfa_enrollment="required")],
            [_auth_policy(mfa_enrollment="optional")],
        )
        level, reason = classify_change(_only_change(changes))
        assert level == "high"
        assert "weakened" in reason.lower()

    def test_mfa_optional_to_required_is_low(self):
        changes = _diff(
            [_auth_policy(mfa_enrollment="optional")],
            [_auth_policy(mfa_enrollment="required")],
        )
        level, reason = classify_change(_only_change(changes))
        assert level == "low"
        assert "strengthened" in reason.lower()

    def test_auth_methods_broadened_is_medium(self):
        changes = _diff(
            [_auth_policy(authentication_methods=["saml"])],
            [_auth_policy(authentication_methods=["saml", "password"])],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_auth_methods_narrowed_is_low(self):
        changes = _diff(
            [_auth_policy(authentication_methods=["saml", "password"])],
            [_auth_policy(authentication_methods=["saml"])],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_owner_change_is_medium(self):
        changes = _diff(
            [_auth_policy(owner="SECURITYADMIN")],
            [_auth_policy(owner="SYSADMIN")],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"


# ── Security integrations ─────────────────────────────────────────────────────


class TestSecurityIntegrationChangeClassification:
    def test_saml_added_enabled_is_medium(self):
        changes = _diff([], [_security_integration(enabled="true")])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_saml_added_disabled_is_low(self):
        changes = _diff([], [_security_integration(enabled="false")])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_oauth_enabled_is_medium(self):
        changes = _diff(
            [_security_integration(integration_type="oauth_snowflake", enabled="false")],
            [_security_integration(integration_type="oauth_snowflake", enabled="true")],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_oauth_disabled_is_low(self):
        changes = _diff(
            [_security_integration(integration_type="oauth_snowflake", enabled="true")],
            [_security_integration(integration_type="oauth_snowflake", enabled="false")],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_scim_run_as_role_change_is_medium(self):
        changes = _diff(
            [_security_integration(integration_type="scim", scim_run_as_role="OLD_ROLE")],
            [_security_integration(integration_type="scim", scim_run_as_role="NEW_ROLE")],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_removed_enabled_integration_is_medium(self):
        changes = _diff([_security_integration(enabled="true")], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_removed_disabled_integration_is_low(self):
        changes = _diff([_security_integration(enabled="false")], [])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"


# ── Storage integrations ──────────────────────────────────────────────────────


class TestStorageIntegrationChangeClassification:
    def test_added_is_low(self):
        changes = _diff([], [_storage_integration()])
        level, _ = classify_change(_only_change(changes))
        assert level == "low"

    def test_enabled_true_is_medium(self):
        changes = _diff(
            [_storage_integration(enabled="false")],
            [_storage_integration(enabled="true")],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_allowed_locations_broadened_is_medium(self):
        changes = _diff(
            [_storage_integration(allowed_location_count=2)],
            [_storage_integration(allowed_location_count=5)],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_blocked_locations_reduced_is_medium(self):
        changes = _diff(
            [_storage_integration(blocked_location_count=3)],
            [_storage_integration(blocked_location_count=1)],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"


# ── External access integrations ──────────────────────────────────────────────


class TestExternalAccessChangeClassification:
    def test_added_is_medium(self):
        changes = _diff([], [_external_access_integration()])
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_enabled_true_is_medium(self):
        changes = _diff(
            [_external_access_integration(enabled="false")],
            [_external_access_integration(enabled="true")],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_allowed_network_rules_increased_is_medium(self):
        changes = _diff(
            [_external_access_integration(allowed_network_rule_count=1)],
            [_external_access_integration(allowed_network_rule_count=3)],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_allowed_secret_count_increased_is_medium(self):
        changes = _diff(
            [_external_access_integration(allowed_secret_count=0)],
            [_external_access_integration(allowed_secret_count=2)],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "medium"

    def test_disabled_is_low(self):
        changes = _diff(
            [_external_access_integration(enabled="true")],
            [_external_access_integration(enabled="false")],
        )
        level, _ = classify_change(_only_change(changes))
        assert level == "low"


# ── Provider metadata / diff hygiene ─────────────────────────────────────────


class TestProviderMetadataHygiene:
    def test_network_policy_metadata_context(self):
        changes = _diff(
            [_network_policy(allows_anywhere_ipv4="false")],
            [_network_policy(allows_anywhere_ipv4="true")],
        )
        pm = _only_change(changes)["provider_metadata"]
        assert pm.get("policy_name") == "OPEN"
        assert pm.get("allows_anywhere_ipv4") == "true"

    def test_auth_policy_metadata_context(self):
        changes = _diff(
            [_auth_policy(mfa_enrollment="optional")],
            [_auth_policy(mfa_enrollment="required")],
        )
        pm = _only_change(changes)["provider_metadata"]
        assert pm.get("mfa_enrollment") == "required"

    def test_security_integration_metadata_excludes_secrets(self):
        changes = _diff([], [_security_integration()])
        pm = _only_change(changes)["provider_metadata"]
        assert pm["record_type"] == "snowflake_security_integration"
        for forbidden in ("saml2_certificate", "client_secret", "oauth_secret"):
            assert forbidden not in pm

    def test_storage_integration_broadened_metadata(self):
        changes = _diff(
            [_storage_integration(allowed_location_count=2)],
            [_storage_integration(allowed_location_count=10)],
        )
        pm = _only_change(changes)["provider_metadata"]
        assert pm.get("storage_provider") == "s3"

    def test_external_access_broadened_metadata(self):
        changes = _diff(
            [_external_access_integration(allowed_network_rule_count=1)],
            [_external_access_integration(allowed_network_rule_count=5)],
        )
        pm = _only_change(changes)["provider_metadata"]
        assert pm.get("allowed_network_rule_count") == 5

    def test_ignored_safe_field_produces_no_diff(self):
        base = _network_policy()
        drifted = dict(base)
        drifted["_not_a_tracked_field"] = "irrelevant-value"
        changes = _diff([base], [drifted])
        assert changes == []

    def test_reordered_records_produce_no_diff(self):
        p1, p2 = _network_policy(name="P1"), _network_policy(name="P2")
        changes = _diff([p1, p2], [p2, p1])
        assert changes == []

    def test_unknown_record_type_fails_safe(self):
        from app.services.risk_rules.snowflake import classify_snowflake_change

        change = {
            "change_type": "modified",
            "provider_metadata": {"record_type": "snowflake_future_thing"},
        }
        level, _reason = classify_snowflake_change(change)
        assert level == "low"
