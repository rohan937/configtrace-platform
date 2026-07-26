"""Okta Security Finding connector-shape reachability tests (Okta message 6 of 8).

For at least one representative rule from every category, proves the full
path: a real Okta API-shaped raw dict -> the connector's actual
normalize/derive function -> a real normalized record -> evaluate_record()
-> a Finding with the expected rule key. This is not testing hand-fabricated
Finding dictionaries — it exercises the same normalization/derivation code
the live connector (app/connectors/okta.py) uses.
"""

from __future__ import annotations

from app.connectors.okta import OktaConnector
from app.services.security_finding_evaluator import evaluate_record

_TENANT = "id:t1"


def _rule_keys(record):
    return {f.rule_key for f in evaluate_record(record, "okta")}


def _user(**overrides):
    base = {"id": "u1", "status": "ACTIVE", "profile": {"login": "alice@example.com"}}
    base.update(overrides)
    return OktaConnector._normalize_user(_TENANT, base)


class TestPrivilegedIdentityReachability:
    """Real role-assignment parse -> derived okta_privileged_identity -> Finding."""

    def test_super_admin_reachable_via_real_derivation(self):
        user_record = _user()
        raw_assignment = {"id": "ra1", "label": "Super Administrator", "type": "SUPER_ADMIN", "status": "ACTIVE"}
        parsed = OktaConnector._parse_role_assignment(raw_assignment)
        admin_role = OktaConnector._normalize_builtin_admin_role(_TENANT, parsed["role_type"], parsed.get("label"))
        assignment = OktaConnector._normalize_user_admin_role_assignment(_TENANT, user_record, parsed, admin_role)

        identities = OktaConnector._derive_privileged_identities(
            _TENANT, {user_record["user_id"]: user_record}, [assignment], [], [],
        )
        assert len(identities) == 1
        assert "okta_super_admin_assigned" in _rule_keys(identities[0])

    def test_deprovisioned_super_admin_reachable(self):
        user_record = _user(status="DEPROVISIONED")
        raw_assignment = {"id": "ra1", "label": "Super Administrator", "type": "SUPER_ADMIN", "status": "ACTIVE"}
        parsed = OktaConnector._parse_role_assignment(raw_assignment)
        admin_role = OktaConnector._normalize_builtin_admin_role(_TENANT, parsed["role_type"], parsed.get("label"))
        assignment = OktaConnector._normalize_user_admin_role_assignment(_TENANT, user_record, parsed, admin_role)

        identities = OktaConnector._derive_privileged_identities(
            _TENANT, {user_record["user_id"]: user_record}, [assignment], [], [],
        )
        keys = _rule_keys(identities[0])
        assert "okta_deprovisioned_identity_retains_admin_privilege" in keys
        assert "okta_super_admin_assigned" in keys

    def test_high_tier_admin_reachable(self):
        user_record = _user()
        raw_assignment = {"id": "ra1", "label": "Org Administrator", "type": "ORG_ADMIN", "status": "ACTIVE"}
        parsed = OktaConnector._parse_role_assignment(raw_assignment)
        admin_role = OktaConnector._normalize_builtin_admin_role(_TENANT, parsed["role_type"], parsed.get("label"))
        assignment = OktaConnector._normalize_user_admin_role_assignment(_TENANT, user_record, parsed, admin_role)

        identities = OktaConnector._derive_privileged_identities(
            _TENANT, {user_record["user_id"]: user_record}, [assignment], [], [],
        )
        assert "okta_high_tier_admin_assigned" in _rule_keys(identities[0])

    def test_custom_admin_role_high_risk_reachable(self):
        raw_role = {"id": "cr1", "label": "Tenant Admin Manager"}
        role_record = OktaConnector._normalize_custom_admin_role(_TENANT, raw_role, ["okta.roles.manage"])
        assert "okta_custom_admin_role_high_risk" in _rule_keys(role_record)

    def test_group_grants_super_admin_reachable(self):
        raw_group = {"id": "g1", "type": "OKTA_GROUP", "profile": {"name": "Admins"}}
        group_record = OktaConnector._normalize_group(_TENANT, raw_group, membership_count=5)
        raw_assignment = {"id": "ra1", "label": "Super Administrator", "type": "SUPER_ADMIN", "status": "ACTIVE"}
        parsed = OktaConnector._parse_role_assignment(raw_assignment)
        admin_role = OktaConnector._normalize_builtin_admin_role(_TENANT, parsed["role_type"], parsed.get("label"))
        group_assignment = OktaConnector._normalize_group_admin_role_assignment(_TENANT, group_record, parsed, admin_role)

        privileged_groups = OktaConnector._derive_privileged_groups(
            _TENANT, {"g1": group_record}, [group_assignment], [], {},
        )
        assert len(privileged_groups) == 1
        assert "okta_privileged_group_grants_super_admin" in _rule_keys(privileged_groups[0])

    def test_unscoped_admin_role_assignment_reachable(self):
        user_record = _user()
        raw_assignment = {"id": "ra1", "label": "App Administrator", "type": "APP_ADMIN", "status": "ACTIVE", "_links": {"self": {"href": "x"}}}
        parsed = OktaConnector._parse_role_assignment(raw_assignment)
        admin_role = OktaConnector._normalize_builtin_admin_role(_TENANT, parsed["role_type"], parsed.get("label"))
        assignment = OktaConnector._normalize_user_admin_role_assignment(_TENANT, user_record, parsed, admin_role)
        assert "okta_unscoped_admin_role_assignment" in _rule_keys(assignment)


class TestAuthenticationReachability:
    """Real _normalize_policy_rule -> Finding."""

    def test_mfa_not_required_reachable(self):
        policy_record = OktaConnector._normalize_policy(_TENANT, {"id": "p1", "name": "Sign-On", "type": "OKTA_SIGN_ON", "status": "ACTIVE", "priority": 1}, rule_count=0)
        raw_rule = {
            "id": "r1", "name": "Catch-all", "status": "ACTIVE", "priority": 1,
            "conditions": {"people": {"groups": {"include": []}}},
            "actions": {"signon": {"access": "ALLOW", "requireFactor": False}},
        }
        rule_record = OktaConnector._normalize_policy_rule(_TENANT, policy_record, raw_rule)
        assert "okta_broad_allow_rule_without_mfa" in _rule_keys(rule_record)

    def test_mfa_optional_reachable(self):
        policy_record = OktaConnector._normalize_policy(_TENANT, {"id": "p1", "name": "Sign-On", "type": "OKTA_SIGN_ON", "status": "ACTIVE", "priority": 1}, rule_count=0)
        raw_rule = {
            "id": "r1", "name": "Rule", "status": "ACTIVE", "priority": 1,
            "conditions": {"people": {"groups": {"include": ["g1"]}}},
            "actions": {"appSignOn": {"access": "ALLOW", "verificationMethod": {"factorMode": "1FA"}}},
        }
        rule_record = OktaConnector._normalize_policy_rule(_TENANT, policy_record, raw_rule)
        # 1FA maps to mfa_requirement=none via the modern shape too, scoped
        # to a specific group (not all_users) so the generic rule fires.
        assert "okta_signon_mfa_not_required" in _rule_keys(rule_record)

    def test_phishing_resistant_not_required_reachable(self):
        policy_record = OktaConnector._normalize_policy(_TENANT, {"id": "p1", "name": "Access", "type": "ACCESS_POLICY", "status": "ACTIVE", "priority": 1}, rule_count=0)
        raw_rule = {
            "id": "r1", "name": "Rule", "status": "ACTIVE", "priority": 1,
            "conditions": {"people": {"groups": {"include": ["g1"]}}},
            "actions": {"appSignOn": {"access": "ALLOW", "verificationMethod": {
                "factorMode": "2FA", "constraints": [{"possession": {"phishingResistant": "DISALLOWED"}}],
            }}},
        }
        rule_record = OktaConnector._normalize_policy_rule(_TENANT, policy_record, raw_rule)
        assert "okta_phishing_resistant_not_required" in _rule_keys(rule_record)

    def test_weak_authenticator_reachable(self):
        auth_record = OktaConnector._normalize_authenticator(_TENANT, {"id": "a1", "key": "phone_number", "type": "phone", "name": "Phone", "status": "ACTIVE"})
        assert "okta_weak_authenticator_enabled" in _rule_keys(auth_record)


class TestPasswordReachability:
    def test_weak_min_length_reachable(self):
        raw_policy = {
            "id": "pw1", "name": "Password Policy", "type": "PASSWORD", "status": "ACTIVE", "priority": 1,
            "settings": {"password": {
                "complexity": {"minLength": 6, "minLowerCase": 0, "minUpperCase": 0, "minNumber": 0, "minSymbol": 0},
                "age": {"maxAgeDays": 0, "minAgeMinutes": 0, "historyCount": 0},
                "lockout": {"maxAttempts": 0},
            }},
        }
        policy_record = OktaConnector._normalize_policy(_TENANT, raw_policy, rule_count=0)
        keys = _rule_keys(policy_record)
        assert "okta_password_policy_weak_min_length" in keys
        assert "okta_password_policy_no_lockout" in keys
        assert "okta_password_policy_no_history" in keys
        assert "okta_password_policy_no_complexity" in keys


class TestApplicationReachability:
    def test_wildcard_redirect_reachable(self):
        raw_app = {
            "id": "app1", "label": "My App", "status": "ACTIVE", "signOnMode": "OPENID_CONNECT",
            "settings": {"oauthClient": {"redirect_uris": ["https://*.example.com/cb"], "application_type": "web"}},
        }
        app_record = OktaConnector._normalize_application(_TENANT, raw_app, user_assignment_count=0, group_assignment_count=0)
        assert "okta_oidc_wildcard_redirect" in _rule_keys(app_record)

    def test_http_redirect_reachable(self):
        raw_app = {
            "id": "app1", "label": "My App", "status": "ACTIVE", "signOnMode": "OPENID_CONNECT",
            "settings": {"oauthClient": {"redirect_uris": ["http://example.com/cb"], "application_type": "web"}},
        }
        app_record = OktaConnector._normalize_application(_TENANT, raw_app, user_assignment_count=0, group_assignment_count=0)
        assert "okta_oidc_http_redirect" in _rule_keys(app_record)

    def test_saml_signing_disabled_reachable(self):
        raw_app = {
            "id": "app1", "label": "SAML App", "status": "ACTIVE", "signOnMode": "SAML_2_0",
            "settings": {"signOn": {"responseSigned": False, "assertionSigned": False}},
        }
        app_record = OktaConnector._normalize_application(_TENANT, raw_app, user_assignment_count=0, group_assignment_count=0)
        keys = _rule_keys(app_record)
        assert "okta_saml_response_signing_disabled" in keys
        assert "okta_saml_assertion_signing_disabled" in keys

    def test_everyone_group_assignment_reachable(self):
        raw_group = {"id": "g1", "type": "BUILT_IN", "profile": {"name": "Everyone"}}
        group_record = OktaConnector._normalize_group(_TENANT, raw_group, membership_count=100)
        app_record = OktaConnector._normalize_application(
            _TENANT, {"id": "app1", "label": "App", "status": "ACTIVE", "signOnMode": "SAML_2_0", "settings": {}},
            user_assignment_count=0, group_assignment_count=1,
        )
        raw_assignment = {"id": "g1"}
        group_assignment = OktaConnector._normalize_app_group_assignment(_TENANT, app_record, group_record, raw_assignment)
        assert "okta_app_assigned_to_everyone_group" in _rule_keys(group_assignment)


class TestIdentityLifecycleReachability:
    def test_deprovisioned_user_retains_app_assignment_reachable(self):
        user_record = _user(status="DEPROVISIONED")
        app_record = OktaConnector._normalize_application(
            _TENANT, {"id": "app1", "label": "App", "status": "ACTIVE", "signOnMode": "SAML_2_0", "settings": {}},
            user_assignment_count=1, group_assignment_count=0,
        )
        raw_assignment = {"id": "u1", "status": "ACTIVE", "scope": "USER"}
        assignment = OktaConnector._normalize_app_user_assignment(_TENANT, app_record, user_record, raw_assignment)
        assert "okta_deprovisioned_user_retains_app_assignment" in _rule_keys(assignment)
