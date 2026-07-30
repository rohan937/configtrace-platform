"""Snowflake Security Finding predicate tests (Snowflake message 6 of 8).

For every implemented rule: a positive-trigger case and at least one
adjacent non-trigger case (unknown/missing/gated-condition/etc. that must
never fire). Uses ``evaluate()`` directly against hand-built normalized
records — connector-shape reachability is covered separately in
``test_snowflake_security_findings_reachability.py``.
"""

from __future__ import annotations

from app.services.security_rules.snowflake import evaluate

_ACCOUNT = "id:acme-prod"


def _keys(record: dict) -> set[str]:
    return {f.rule_key for f in evaluate(record)}


def _privileged_user(**overrides) -> dict:
    base = {
        "record_type": "snowflake_privileged_user",
        "record_id": f"{_ACCOUNT}/privileged_user/alice",
        "account_id": _ACCOUNT,
        "user_name": "ALICE",
        "user_type": "person",
        "disabled": "enabled",
        "highest_known_privilege_tier": "medium",
        "has_unknown_privilege": False,
        "has_accountadmin": False,
        "has_securityadmin": False,
        "has_sysadmin": False,
        "has_useradmin": False,
        "has_manage_grants": False,
        "high_risk_future_grant_count": 0,
        "privilege_completeness": "complete",
    }
    base.update(overrides)
    return base


def _privileged_role(**overrides) -> dict:
    base = {
        "record_type": "snowflake_privileged_role",
        "record_id": f"{_ACCOUNT}/privileged_role/account_role/custom_admin",
        "account_id": _ACCOUNT,
        "role_name": "CUSTOM_ADMIN",
        "role_type": "account_role",
        "role_category": "custom",
        "database_name": None,
        "highest_known_privilege_tier": "medium",
        "has_manage_grants": False,
        "global_privilege_categories": [],
        "owns_database_count": 0,
        "owns_schema_count": 0,
        "owns_managed_access_schema_count": 0,
        "owns_warehouse_count": 0,
        "owns_security_integration_count": 0,
        "owns_storage_integration_count": 0,
        "owns_external_access_integration_count": 0,
        "owns_network_policy_count": 0,
        "owns_authentication_policy_count": 0,
        "future_ownership_count": 0,
        "privilege_completeness": "complete",
    }
    base.update(overrides)
    return base


def _public_exposure(**overrides) -> dict:
    base = {
        "record_type": "snowflake_public_exposure",
        "record_id": f"{_ACCOUNT}/public_exposure",
        "account_id": _ACCOUNT,
        "exposure_category": "account_wide_user_access",
        "scope": "account",
        "current_public_exposure_count": None,
        "current_public_exposure_data_available": False,
        "future_public_exposure_count": 0,
        "future_public_ownership_count": 0,
        "future_public_write_count": 0,
        "future_public_read_count": 0,
        "privilege_completeness": "partial",
    }
    base.update(overrides)
    return base


def _network_policy(**overrides) -> dict:
    base = {
        "record_type": "snowflake_network_policy",
        "record_id": f"{_ACCOUNT}/network_policy/open",
        "account_id": _ACCOUNT,
        "policy_name": "OPEN",
        "allows_anywhere_ipv4": "false",
        "allows_anywhere_ipv6": "false",
    }
    base.update(overrides)
    return base


def _authentication_policy(**overrides) -> dict:
    base = {
        "record_type": "snowflake_authentication_policy",
        "record_id": f"{_ACCOUNT}/authentication_policy/strict",
        "account_id": _ACCOUNT,
        "policy_name": "STRICT",
        "set_on": "ACCOUNT",
        "mfa_enrollment": "required",
        "authentication_methods": ["saml", "password"],
    }
    base.update(overrides)
    return base


def _security_integration(**overrides) -> dict:
    base = {
        "record_type": "snowflake_security_integration",
        "record_id": f"{_ACCOUNT}/security_integration/my_scim/scim",
        "account_id": _ACCOUNT,
        "integration_name": "MY_SCIM",
        "integration_type": "scim",
        "enabled": "true",
        "scim_run_as_role": "OKTA_PROVISIONER",
        "scim_run_as_role_tier": "medium",
        "scim_run_as_role_has_manage_grants": False,
    }
    base.update(overrides)
    return base


# ── Privileged users ──────────────────────────────────────────────────────────


class TestUserAccountadmin:
    def test_person_accountadmin_fires(self):
        rec = _privileged_user(has_accountadmin=True, highest_known_privilege_tier="critical")
        assert "snowflake_user_accountadmin" in _keys(rec)

    def test_service_accountadmin_fires_service_rule_not_generic(self):
        rec = _privileged_user(has_accountadmin=True, highest_known_privilege_tier="critical", user_type="service")
        keys = _keys(rec)
        assert "snowflake_service_user_accountadmin" in keys
        assert "snowflake_user_accountadmin" not in keys

    def test_service_agent_accountadmin_fires_service_rule(self):
        rec = _privileged_user(has_accountadmin=True, highest_known_privilege_tier="critical", user_type="service_agent")
        assert "snowflake_service_user_accountadmin" in _keys(rec)

    def test_unknown_accountadmin_never_fires(self):
        rec = _privileged_user(has_accountadmin=None, highest_known_privilege_tier="unknown")
        keys = _keys(rec)
        assert "snowflake_user_accountadmin" not in keys
        assert "snowflake_service_user_accountadmin" not in keys

    def test_false_accountadmin_never_fires(self):
        rec = _privileged_user(has_accountadmin=False)
        assert "snowflake_user_accountadmin" not in _keys(rec)


class TestUserSecurityadminAndManageGrants:
    def test_securityadmin_fires(self):
        rec = _privileged_user(has_securityadmin=True, highest_known_privilege_tier="high")
        assert "snowflake_user_securityadmin" in _keys(rec)

    def test_securityadmin_suppressed_when_accountadmin_present(self):
        rec = _privileged_user(has_accountadmin=True, has_securityadmin=True, highest_known_privilege_tier="critical")
        keys = _keys(rec)
        assert "snowflake_user_accountadmin" in keys
        assert "snowflake_user_securityadmin" not in keys

    def test_manage_grants_fires(self):
        rec = _privileged_user(has_manage_grants=True, highest_known_privilege_tier="high")
        assert "snowflake_user_can_manage_grants" in _keys(rec)

    def test_manage_grants_suppressed_when_securityadmin_present(self):
        rec = _privileged_user(has_securityadmin=True, has_manage_grants=True, highest_known_privilege_tier="high")
        keys = _keys(rec)
        assert "snowflake_user_securityadmin" in keys
        assert "snowflake_user_can_manage_grants" not in keys

    def test_unknown_manage_grants_never_fires(self):
        rec = _privileged_user(has_manage_grants=None)
        assert "snowflake_user_can_manage_grants" not in _keys(rec)


class TestUserSysadminUseradmin:
    def test_sysadmin_medium_tier_fires(self):
        rec = _privileged_user(has_sysadmin=True, highest_known_privilege_tier="medium")
        assert "snowflake_user_sysadmin_or_useradmin" in _keys(rec)

    def test_useradmin_medium_tier_fires(self):
        rec = _privileged_user(has_useradmin=True, highest_known_privilege_tier="medium")
        assert "snowflake_user_sysadmin_or_useradmin" in _keys(rec)

    def test_ordinary_user_no_finding(self):
        rec = _privileged_user()
        assert _keys(rec) == set()

    def test_sysadmin_non_medium_tier_does_not_fire_this_rule(self):
        """If tier isn't exactly medium (e.g. it's actually high from
        another signal), the medium-specific rule doesn't double-fire."""
        rec = _privileged_user(has_sysadmin=True, highest_known_privilege_tier="high", has_securityadmin=True)
        keys = _keys(rec)
        assert "snowflake_user_sysadmin_or_useradmin" not in keys
        assert "snowflake_user_securityadmin" in keys


class TestDisabledPrivilegedUser:
    def test_disabled_critical_fires(self):
        rec = _privileged_user(disabled="disabled", highest_known_privilege_tier="critical", has_accountadmin=True)
        assert "snowflake_disabled_privileged_user" in _keys(rec)

    def test_disabled_high_fires(self):
        rec = _privileged_user(disabled="disabled", highest_known_privilege_tier="high", has_securityadmin=True)
        assert "snowflake_disabled_privileged_user" in _keys(rec)

    def test_disabled_medium_does_not_fire(self):
        rec = _privileged_user(disabled="disabled", highest_known_privilege_tier="medium", has_sysadmin=True)
        assert "snowflake_disabled_privileged_user" not in _keys(rec)

    def test_enabled_critical_does_not_fire_disabled_rule(self):
        rec = _privileged_user(disabled="enabled", highest_known_privilege_tier="critical", has_accountadmin=True)
        assert "snowflake_disabled_privileged_user" not in _keys(rec)

    def test_unknown_disabled_state_never_fires(self):
        rec = _privileged_user(disabled="unknown", highest_known_privilege_tier="critical", has_accountadmin=True)
        assert "snowflake_disabled_privileged_user" not in _keys(rec)


class TestLegacyServiceUser:
    def test_legacy_service_ordinary_tier_fires_generic_rule(self):
        rec = _privileged_user(user_type="legacy_service", has_manage_grants=False, highest_known_privilege_tier="low")
        keys = _keys(rec)
        assert "snowflake_legacy_service_user" in keys
        assert "snowflake_legacy_service_user_privileged" not in keys

    def test_legacy_service_high_tier_fires_composite_rule(self):
        rec = _privileged_user(user_type="legacy_service", has_securityadmin=True, highest_known_privilege_tier="high")
        keys = _keys(rec)
        assert "snowflake_legacy_service_user_privileged" in keys
        assert "snowflake_legacy_service_user" not in keys

    def test_ordinary_service_type_never_fires_legacy_rules(self):
        rec = _privileged_user(user_type="service")
        keys = _keys(rec)
        assert "snowflake_legacy_service_user" not in keys
        assert "snowflake_legacy_service_user_privileged" not in keys


class TestUserHighRiskFutureGrant:
    def test_fires_when_no_stronger_rule_present(self):
        rec = _privileged_user(high_risk_future_grant_count=2, highest_known_privilege_tier="low")
        assert "snowflake_user_high_risk_future_grant" in _keys(rec)

    def test_suppressed_when_accountadmin_present(self):
        rec = _privileged_user(high_risk_future_grant_count=2, has_accountadmin=True, highest_known_privilege_tier="critical")
        assert "snowflake_user_high_risk_future_grant" not in _keys(rec)

    def test_zero_count_never_fires(self):
        rec = _privileged_user(high_risk_future_grant_count=0)
        assert "snowflake_user_high_risk_future_grant" not in _keys(rec)

    def test_none_count_never_fires(self):
        rec = _privileged_user(high_risk_future_grant_count=None)
        assert "snowflake_user_high_risk_future_grant" not in _keys(rec)


# ── Privileged roles ──────────────────────────────────────────────────────────


class TestCustomRoleManageGrants:
    def test_manage_grants_alone_fires(self):
        rec = _privileged_role(has_manage_grants=True, highest_known_privilege_tier="high")
        assert "snowflake_custom_role_manage_grants" in _keys(rec)

    def test_manage_grants_plus_identity_admin_fires_composite_only(self):
        rec = _privileged_role(
            has_manage_grants=True, highest_known_privilege_tier="critical",
            global_privilege_categories=["identity_administration"],
        )
        keys = _keys(rec)
        assert "snowflake_custom_role_manage_grants_identity_admin" in keys
        assert "snowflake_custom_role_manage_grants" not in keys

    def test_built_in_role_category_never_fires_custom_rules(self):
        rec = _privileged_role(role_category="securityadmin", has_manage_grants=True, highest_known_privilege_tier="high")
        assert "snowflake_custom_role_manage_grants" not in _keys(rec)

    def test_unknown_manage_grants_never_fires(self):
        rec = _privileged_role(has_manage_grants=None)
        assert "snowflake_custom_role_manage_grants" not in _keys(rec)


class TestCustomRoleHighPrivilege:
    def test_high_tier_custom_role_fires(self):
        rec = _privileged_role(highest_known_privilege_tier="high")
        assert "snowflake_custom_role_high_privilege" in _keys(rec)

    def test_medium_tier_does_not_fire(self):
        rec = _privileged_role(highest_known_privilege_tier="medium")
        assert "snowflake_custom_role_high_privilege" not in _keys(rec)

    def test_high_tier_with_manage_grants_fires_manage_grants_rule_instead(self):
        rec = _privileged_role(highest_known_privilege_tier="high", has_manage_grants=True)
        keys = _keys(rec)
        assert "snowflake_custom_role_manage_grants" in keys
        assert "snowflake_custom_role_high_privilege" not in keys


class TestRoleOwnershipComposites:
    def test_managed_access_schema_custom_role_fires(self):
        rec = _privileged_role(owns_managed_access_schema_count=1)
        assert "snowflake_role_controls_managed_access_schema" in _keys(rec)

    def test_managed_access_schema_zero_never_fires(self):
        rec = _privileged_role(owns_managed_access_schema_count=0)
        assert "snowflake_role_controls_managed_access_schema" not in _keys(rec)

    def test_security_integration_ownership_requires_high_tier(self):
        low_tier = _privileged_role(owns_security_integration_count=1, highest_known_privilege_tier="medium")
        assert "snowflake_role_owns_security_integration_high_privilege" not in _keys(low_tier)
        high_tier = _privileged_role(owns_security_integration_count=1, highest_known_privilege_tier="high")
        assert "snowflake_role_owns_security_integration_high_privilege" in _keys(high_tier)

    def test_storage_integration_ownership_composite(self):
        rec = _privileged_role(owns_storage_integration_count=1, highest_known_privilege_tier="critical")
        assert "snowflake_role_owns_storage_integration_high_privilege" in _keys(rec)

    def test_external_access_integration_ownership_composite(self):
        rec = _privileged_role(owns_external_access_integration_count=1, highest_known_privilege_tier="high")
        assert "snowflake_role_owns_external_access_integration_high_privilege" in _keys(rec)

    def test_authentication_policy_ownership_composite(self):
        rec = _privileged_role(owns_authentication_policy_count=1, highest_known_privilege_tier="high")
        assert "snowflake_role_owns_authentication_policy_high_privilege" in _keys(rec)

    def test_network_policy_ownership_composite(self):
        rec = _privileged_role(owns_network_policy_count=1, highest_known_privilege_tier="critical")
        assert "snowflake_role_owns_network_policy_high_privilege" in _keys(rec)

    def test_database_ownership_composite(self):
        rec = _privileged_role(owns_database_count=1, highest_known_privilege_tier="high")
        assert "snowflake_high_privilege_role_owns_database" in _keys(rec)

    def test_ordinary_database_owner_not_flagged(self):
        """Routine database ownership by a role at low/medium tier is not
        flagged — only the high-privilege composite is."""
        rec = _privileged_role(owns_database_count=1, highest_known_privilege_tier="low")
        assert "snowflake_high_privilege_role_owns_database" not in _keys(rec)

    def test_built_in_role_never_fires_ownership_composites(self):
        rec = _privileged_role(
            role_category="sysadmin", owns_database_count=1, owns_security_integration_count=1,
            highest_known_privilege_tier="critical",
        )
        keys = _keys(rec)
        assert "snowflake_high_privilege_role_owns_database" not in keys
        assert "snowflake_role_owns_security_integration_high_privilege" not in keys


class TestFutureOwnershipGrant:
    def test_fires_on_any_role_type(self):
        rec = _privileged_role(future_ownership_count=1)
        assert "snowflake_future_ownership_grant" in _keys(rec)

    def test_zero_never_fires(self):
        rec = _privileged_role(future_ownership_count=0)
        assert "snowflake_future_ownership_grant" not in _keys(rec)

    def test_none_never_fires(self):
        rec = _privileged_role(future_ownership_count=None)
        assert "snowflake_future_ownership_grant" not in _keys(rec)


# ── PUBLIC exposure ───────────────────────────────────────────────────────────


class TestPublicExposureFindings:
    def test_future_ownership_critical(self):
        rec = _public_exposure(future_public_ownership_count=1, future_public_exposure_count=1)
        assert "snowflake_public_future_ownership_grant" in _keys(rec)

    def test_future_write_high(self):
        rec = _public_exposure(future_public_write_count=1, future_public_exposure_count=1)
        assert "snowflake_public_future_write_access" in _keys(rec)

    def test_future_read_high(self):
        rec = _public_exposure(future_public_read_count=1, future_public_exposure_count=1)
        assert "snowflake_public_future_data_access" in _keys(rec)

    def test_broad_residual_medium(self):
        rec = _public_exposure(future_public_exposure_count=1)
        assert "snowflake_public_future_broad_privilege" in _keys(rec)

    def test_no_future_grants_no_findings(self):
        rec = _public_exposure()
        assert _keys(rec) == set()

    def test_all_categories_can_coexist(self):
        rec = _public_exposure(
            future_public_ownership_count=1, future_public_write_count=1,
            future_public_read_count=1, future_public_exposure_count=4,
        )
        keys = _keys(rec)
        assert {"snowflake_public_future_ownership_grant", "snowflake_public_future_write_access",
                "snowflake_public_future_data_access", "snowflake_public_future_broad_privilege"} == keys

    def test_wording_never_mentions_internet(self):
        rec = _public_exposure(future_public_ownership_count=1, future_public_exposure_count=1)
        findings = evaluate(rec)
        for f in findings:
            assert "internet" not in f.description.lower()
            assert "internet" not in f.title.lower()


# ── Network policy ───────────────────────────────────────────────────────────


class TestNetworkPolicyAnywhere:
    def test_ipv4_anywhere_fires(self):
        rec = _network_policy(allows_anywhere_ipv4="true")
        assert "snowflake_network_policy_allows_anywhere" in _keys(rec)

    def test_ipv6_anywhere_fires(self):
        rec = _network_policy(allows_anywhere_ipv6="true")
        assert "snowflake_network_policy_allows_anywhere" in _keys(rec)

    def test_restricted_policy_no_finding(self):
        rec = _network_policy()
        assert _keys(rec) == set()

    def test_unknown_broad_access_never_fires(self):
        rec = _network_policy(allows_anywhere_ipv4="unknown", allows_anywhere_ipv6="unknown")
        assert "snowflake_network_policy_allows_anywhere" not in _keys(rec)


# ── Authentication policy ─────────────────────────────────────────────────────


class TestAuthenticationPolicyMfa:
    def test_optional_with_password_fires_composite(self):
        rec = _authentication_policy(mfa_enrollment="optional", authentication_methods=["password"])
        keys = _keys(rec)
        assert "snowflake_mfa_optional_with_password" in keys
        assert "snowflake_mfa_optional_for_person_auth" not in keys

    def test_optional_without_explicit_password_fires_generic(self):
        rec = _authentication_policy(mfa_enrollment="optional", authentication_methods=["saml"])
        keys = _keys(rec)
        assert "snowflake_mfa_optional_for_person_auth" in keys
        assert "snowflake_mfa_optional_with_password" not in keys

    def test_required_no_finding(self):
        rec = _authentication_policy(mfa_enrollment="required")
        assert _keys(rec) == set()

    def test_required_password_only_fires_scope_gap(self):
        rec = _authentication_policy(mfa_enrollment="required_password_only")
        assert "snowflake_mfa_password_only_scope" in _keys(rec)

    def test_unknown_mfa_never_fires(self):
        rec = _authentication_policy(mfa_enrollment="unknown")
        assert _keys(rec) == set()

    def test_service_scoped_policy_never_treated_as_person_mfa_weakness(self):
        """A policy set on a specific (non-ACCOUNT) principal is never
        assumed to affect person users."""
        rec = _authentication_policy(set_on="SVC_ETL", mfa_enrollment="optional")
        assert _keys(rec) == set()


# ── Security integration (SCIM / SAML) ───────────────────────────────────────


class TestScimRunAsPrivilege:
    def test_critical_run_as_fires(self):
        rec = _security_integration(scim_run_as_role_tier="critical", scim_run_as_role_has_manage_grants=True)
        assert "snowflake_scim_critical_privilege_run_as" in _keys(rec)

    def test_high_run_as_fires(self):
        rec = _security_integration(scim_run_as_role_tier="high")
        assert "snowflake_scim_high_privilege_run_as" in _keys(rec)

    def test_ordinary_run_as_no_finding(self):
        rec = _security_integration(scim_run_as_role_tier="medium")
        assert _keys(rec) == set()

    def test_unresolved_role_no_finding(self):
        rec = _security_integration(scim_run_as_role_tier="unknown", scim_run_as_role_has_manage_grants=None)
        assert _keys(rec) == set()

    def test_non_scim_integration_never_fires_scim_rules(self):
        rec = _security_integration(integration_type="oauth_snowflake", scim_run_as_role_tier="critical")
        keys = _keys(rec)
        assert "snowflake_scim_critical_privilege_run_as" not in keys
        assert "snowflake_scim_high_privilege_run_as" not in keys


class TestSamlIncompleteConfig:
    def test_missing_certificate_fires(self):
        rec = _security_integration(
            integration_type="saml2", enabled="true",
            saml2_issuer_configured="true", saml2_sso_url_configured="true", saml2_certificate_configured="false",
        )
        assert "snowflake_saml_integration_incomplete_config" in _keys(rec)

    def test_complete_config_no_finding(self):
        rec = _security_integration(
            integration_type="saml2", enabled="true",
            saml2_issuer_configured="true", saml2_sso_url_configured="true", saml2_certificate_configured="true",
        )
        assert _keys(rec) == set()

    def test_disabled_saml_never_fires(self):
        rec = _security_integration(
            integration_type="saml2", enabled="false",
            saml2_issuer_configured="false", saml2_sso_url_configured="false", saml2_certificate_configured="false",
        )
        assert "snowflake_saml_integration_incomplete_config" not in _keys(rec)


class TestUnknownRecordType:
    def test_unrecognized_record_type_returns_empty(self):
        assert evaluate({"record_type": "snowflake_database"}) == []

    def test_non_dict_returns_empty(self):
        assert evaluate(None) == []  # type: ignore[arg-type]
