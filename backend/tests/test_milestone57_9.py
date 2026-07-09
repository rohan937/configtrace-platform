"""Tests for M57.9 — Provider Depth III: Stripe + GitHub + Vercel + Shopify.

Surfaces added
--------------
  stripe_billing_portal_config   — GET /v1/billing_portal/configurations
  github_environment_protection  — GET /repos/{owner}/{repo}/environments
  vercel_deploy_hook_metadata    — extracted from GET /v9/projects/{id}
  shopify_app_scope_summary      — GET /admin/oauth/access_scopes.json

Coverage strategy
-----------------
Each surface gets:
  - schema constants / frozenset membership
  - normalisation / field correctness
  - data-minimisation assertions (no customer/payment/secret data)
  - fail-soft / error path
  - diff tracked fields
  - risk rule directionality (key branches)

Forbidden pattern coverage:
  - Stripe: no customer/invoice/subscription data
  - GitHub: no secret values, no reviewer identities
  - Vercel: no env var values, no hook URLs (auth tokens)
  - Shopify: no orders/customers/payment records
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# 1. Schema constants & frozensets
# ─────────────────────────────────────────────────────────────────────────────


class TestStripeSchemaM579:
    def test_billing_portal_config_constant(self):
        from app.connectors.stripe_schema import STRIPE_BILLING_PORTAL_CONFIG
        assert STRIPE_BILLING_PORTAL_CONFIG == "stripe_billing_portal_config"

    def test_billing_portal_config_in_frozenset(self):
        from app.connectors.stripe_schema import STRIPE_RECORD_TYPES
        assert "stripe_billing_portal_config" in STRIPE_RECORD_TYPES

    def test_frozenset_has_expected_types(self):
        # M59.10 + M59.11 expanded STRIPE_RECORD_TYPES from 5 → 17 by adding
        # the catalog/checkout/tax surfaces (Part 1) and the fraud/keys/
        # billing/payouts/coupons surfaces (Part 2).  The original five must
        # still be present; the new twelve are additive.
        from app.connectors.stripe_schema import STRIPE_RECORD_TYPES
        assert len(STRIPE_RECORD_TYPES) == 17
        for legacy in (
            "stripe_account_settings",
            "stripe_webhook_endpoint",
            "stripe_payment_method_configuration",
            "stripe_payment_method_domain",
            "stripe_billing_portal_config",
        ):
            assert legacy in STRIPE_RECORD_TYPES


class TestGitHubSchemaM579:
    def test_environment_protection_constant(self):
        from app.connectors.github_schema import GITHUB_ENVIRONMENT_PROTECTION
        assert GITHUB_ENVIRONMENT_PROTECTION == "github_environment_protection"

    def test_environment_protection_in_frozenset(self):
        from app.connectors.github_schema import GITHUB_RECORD_TYPES
        assert "github_environment_protection" in GITHUB_RECORD_TYPES

    def test_frozenset_has_expected_types(self):
        # M59.6 expanded GITHUB_RECORD_TYPES from 8 → 15 by adding the
        # extras surfaces (ruleset, codeowners, workflow_file, oidc_trust,
        # collaborator, app_installation, security_features).  The original
        # eight must still be present; the new seven are additive.
        # Count updated to 16: includes github_automation_permissions added in M69.5B
        # Count updated to 17: includes github_pages (GitHub Pages configuration)
        from app.connectors.github_schema import GITHUB_RECORD_TYPES
        assert len(GITHUB_RECORD_TYPES) == 17
        for legacy in (
            "github_repo_settings",
            "github_branch_protection",
            "github_actions_secret",
            "github_actions_variable",
            "github_webhook",
            "github_actions_permissions",
            "github_deploy_key",
            "github_environment_protection",
        ):
            assert legacy in GITHUB_RECORD_TYPES


class TestVercelSchemaM579:
    def test_deploy_hook_constant(self):
        from app.connectors.vercel_schema import VERCEL_DEPLOY_HOOK_METADATA
        assert VERCEL_DEPLOY_HOOK_METADATA == "vercel_deploy_hook_metadata"

    def test_deploy_hook_in_frozenset(self):
        from app.connectors.vercel_schema import VERCEL_RECORD_TYPES
        assert "vercel_deploy_hook_metadata" in VERCEL_RECORD_TYPES

    def test_frozenset_has_expected_types(self):
        # M59.12 expanded VERCEL_RECORD_TYPES from 4 → 12 by adding the
        # deployment / team / Edge Config / cron / deployment-protection /
        # integration / function-runtime / firewall surfaces.  The original
        # four legacy types must still be present; the new eight are
        # additive.
        from app.connectors.vercel_schema import VERCEL_RECORD_TYPES
        assert len(VERCEL_RECORD_TYPES) == 12
        for legacy in (
            "vercel_project",
            "vercel_env_var",
            "vercel_domain",
            "vercel_deploy_hook_metadata",
        ):
            assert legacy in VERCEL_RECORD_TYPES


class TestShopifySchemaM579:
    def test_app_scope_summary_constant(self):
        from app.connectors.shopify_schema import SHOPIFY_APP_SCOPE_SUMMARY
        assert SHOPIFY_APP_SCOPE_SUMMARY == "shopify_app_scope_summary"

    def test_app_scope_summary_in_frozenset(self):
        from app.connectors.shopify_schema import SHOPIFY_RECORD_TYPES
        assert "shopify_app_scope_summary" in SHOPIFY_RECORD_TYPES

    def test_frozenset_has_four_types(self):
        from app.connectors.shopify_schema import SHOPIFY_RECORD_TYPES
        # shopify_domain added in M74A
        assert len(SHOPIFY_RECORD_TYPES) == 5


# ─────────────────────────────────────────────────────────────────────────────
# 2. Stripe billing portal connector
# ─────────────────────────────────────────────────────────────────────────────


def _make_portal_config(**kwargs):
    """Minimal Stripe billing portal configuration object."""
    base = {
        "id": "bpc_test123",
        "active": True,
        "is_default": True,
        "default_return_url": "https://example.com/billing",
        "login_page": {"enabled": True},
        "features": {
            "customer_update": {"enabled": True, "allowed_updates": ["email", "address"]},
            "invoice_history": {"enabled": True},
            "payment_method_update": {"enabled": True},
            "subscription_cancel": {
                "enabled": True,
                "mode": "at_period_end",
                "cancellation_reason": {"enabled": False, "options": []},
            },
            "subscription_update": {
                "enabled": False,
                "default_allowed_updates": [],
            },
            "subscription_pause": {"enabled": False},
        },
        "business_profile": {
            "privacy_policy_url": "https://example.com/privacy",
            "terms_of_service_url": "https://example.com/terms",
        },
    }
    base.update(kwargs)
    return base


class TestStripeBillingPortalConnector:
    def _connector(self):
        from app.connectors.stripe import StripeConnector
        return StripeConnector()

    def test_normalises_basic_fields(self):
        conn = self._connector()
        raw_list = [_make_portal_config()]
        with patch.object(conn, "_get_list", return_value=raw_list):
            records = conn._fetch_billing_portal_configs({"stripe_api_key": "sk_test"})
        assert len(records) == 1
        r = records[0]
        assert r["record_type"] == "stripe_billing_portal_config"
        assert r["config_id"] == "bpc_test123"
        assert r["active"] is True
        assert r["is_default"] is True

    def test_login_page_enabled(self):
        conn = self._connector()
        cfg = _make_portal_config()
        cfg["login_page"] = {"enabled": True}
        with patch.object(conn, "_get_list", return_value=[cfg]):
            records = conn._fetch_billing_portal_configs({"stripe_api_key": "sk_test"})
        assert records[0]["login_page_enabled"] is True

    def test_return_url_domain_only(self):
        conn = self._connector()
        cfg = _make_portal_config()
        cfg["default_return_url"] = "https://billing.example.com/portal/return?token=secret"
        with patch.object(conn, "_get_list", return_value=[cfg]):
            records = conn._fetch_billing_portal_configs({"stripe_api_key": "sk_test"})
        r = records[0]
        # Only domain stored — full URL (with path/token) must NOT be stored
        assert r["return_url_domain"] == "billing.example.com"
        record_str = str(r)
        assert "portal/return" not in record_str
        assert "token=secret" not in record_str

    def test_customer_update_fields(self):
        conn = self._connector()
        with patch.object(conn, "_get_list", return_value=[_make_portal_config()]):
            records = conn._fetch_billing_portal_configs({"stripe_api_key": "sk_test"})
        r = records[0]
        assert r["customer_update_enabled"] is True
        assert r["customer_update_allowed_updates"] == ["address", "email"]

    def test_subscription_cancel_fields(self):
        conn = self._connector()
        with patch.object(conn, "_get_list", return_value=[_make_portal_config()]):
            records = conn._fetch_billing_portal_configs({"stripe_api_key": "sk_test"})
        r = records[0]
        assert r["subscription_cancel_enabled"] is True
        assert r["subscription_cancel_mode"] == "at_period_end"
        assert r["subscription_cancel_reason_enabled"] is False

    def test_no_customer_data_stored(self):
        """No customer PII, customer IDs, subscription IDs, or invoice IDs."""
        conn = self._connector()
        with patch.object(conn, "_get_list", return_value=[_make_portal_config()]):
            records = conn._fetch_billing_portal_configs({"stripe_api_key": "sk_test"})
        record_str = str(records)
        # Should never reference customer/invoice/subscription objects
        for forbidden in ("cus_", "/v1/customers", "/v1/invoices", "/v1/subscriptions"):
            assert forbidden not in record_str

    def test_returns_empty_on_403(self):
        from app.connectors.exceptions import ConnectorError
        conn = self._connector()
        with patch.object(conn, "_get_list", side_effect=ConnectorError("403", status_code=403)):
            records = conn._fetch_billing_portal_configs({"stripe_api_key": "sk_test"})
        assert records == []

    def test_returns_empty_on_any_connector_error(self):
        from app.connectors.exceptions import ConnectorError
        conn = self._connector()
        with patch.object(conn, "_get_list", side_effect=ConnectorError("error", status_code=404)):
            records = conn._fetch_billing_portal_configs({"stripe_api_key": "sk_test"})
        assert records == []

    def test_multiple_configs(self):
        conn = self._connector()
        cfg2 = _make_portal_config()
        cfg2["id"] = "bpc_second"
        cfg2["is_default"] = False
        with patch.object(conn, "_get_list", return_value=[_make_portal_config(), cfg2]):
            records = conn._fetch_billing_portal_configs({"stripe_api_key": "sk_test"})
        assert len(records) == 2
        assert records[1]["config_id"] == "bpc_second"

    def test_business_profile_urls_not_stored(self):
        """Privacy/ToS URLs from business_profile must not be stored."""
        conn = self._connector()
        cfg = _make_portal_config()
        cfg["business_profile"] = {
            "privacy_policy_url": "https://secret-internal.example.com/privacy",
            "terms_of_service_url": "https://secret-internal.example.com/tos",
        }
        with patch.object(conn, "_get_list", return_value=[cfg]):
            records = conn._fetch_billing_portal_configs({"stripe_api_key": "sk_test"})
        record_str = str(records)
        assert "secret-internal.example.com" not in record_str


# ─────────────────────────────────────────────────────────────────────────────
# 3. GitHub environment protection connector
# ─────────────────────────────────────────────────────────────────────────────


def _make_env_response(environments=None):
    """Minimal GitHub environments API response."""
    if environments is None:
        environments = [
            {
                "id": 1,
                "name": "production",
                "protection_rules": [
                    {
                        "id": 10,
                        "type": "required_reviewers",
                        "reviewers": [
                            {"type": "User", "reviewer": {"login": "alice"}},
                            {"type": "User", "reviewer": {"login": "bob"}},
                        ],
                        "prevent_self_review": True,
                    },
                    {"id": 11, "type": "wait_timer", "wait_timer": 30},
                ],
                "deployment_branch_policy": {
                    "protected_branches": True,
                    "custom_branch_policies": False,
                },
            }
        ]
    return {"total_count": len(environments), "environments": environments}


class TestGitHubEnvironmentConnector:
    def _connector(self):
        from app.connectors.github import GitHubConnector
        return GitHubConnector()

    def _mock_resp(self, body):
        resp = MagicMock()
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = body
        return resp

    def test_normalises_environment_name(self):
        conn = self._connector()
        with patch.object(conn, "_get", return_value=self._mock_resp(_make_env_response())):
            records = conn._fetch_environments(MagicMock(), {}, "acme", "repo", "acme/repo")
        assert len(records) == 1
        assert records[0]["environment_name"] == "production"
        assert records[0]["record_type"] == "github_environment_protection"

    def test_wait_timer_extracted(self):
        conn = self._connector()
        with patch.object(conn, "_get", return_value=self._mock_resp(_make_env_response())):
            records = conn._fetch_environments(MagicMock(), {}, "acme", "repo", "acme/repo")
        assert records[0]["wait_timer"] == 30

    def test_reviewers_count_no_identity(self):
        conn = self._connector()
        with patch.object(conn, "_get", return_value=self._mock_resp(_make_env_response())):
            records = conn._fetch_environments(MagicMock(), {}, "acme", "repo", "acme/repo")
        r = records[0]
        # Count present
        assert r["reviewers_count"] == 2
        # Reviewer identities (login names) MUST NOT be stored
        record_str = str(r)
        assert "alice" not in record_str
        assert "bob" not in record_str

    def test_prevent_self_review(self):
        conn = self._connector()
        with patch.object(conn, "_get", return_value=self._mock_resp(_make_env_response())):
            records = conn._fetch_environments(MagicMock(), {}, "acme", "repo", "acme/repo")
        assert records[0]["prevent_self_review"] is True

    def test_branch_policy_extracted(self):
        conn = self._connector()
        with patch.object(conn, "_get", return_value=self._mock_resp(_make_env_response())):
            records = conn._fetch_environments(MagicMock(), {}, "acme", "repo", "acme/repo")
        r = records[0]
        assert r["protected_branches"] is True
        assert r["custom_branch_policies"] is False

    def test_no_branch_policy_gives_none(self):
        conn = self._connector()
        env = {"id": 2, "name": "staging", "protection_rules": [], "deployment_branch_policy": None}
        resp = {"total_count": 1, "environments": [env]}
        with patch.object(conn, "_get", return_value=self._mock_resp(resp)):
            records = conn._fetch_environments(MagicMock(), {}, "acme", "repo", "acme/repo")
        r = records[0]
        assert r["protected_branches"] is None
        assert r["custom_branch_policies"] is None

    def test_multiple_environments(self):
        conn = self._connector()
        envs = [
            {"id": 1, "name": "production", "protection_rules": [], "deployment_branch_policy": None},
            {"id": 2, "name": "staging", "protection_rules": [], "deployment_branch_policy": None},
        ]
        with patch.object(conn, "_get", return_value=self._mock_resp({"total_count": 2, "environments": envs})):
            records = conn._fetch_environments(MagicMock(), {}, "acme", "repo", "acme/repo")
        assert len(records) == 2
        names = {r["environment_name"] for r in records}
        assert names == {"production", "staging"}

    def test_returns_empty_on_404(self):
        from app.connectors.exceptions import ConnectorError
        conn = self._connector()
        with patch.object(conn, "_get", side_effect=ConnectorError("not found", status_code=404)):
            records = conn._fetch_environments(MagicMock(), {}, "acme", "repo", "acme/repo")
        assert records == []

    def test_returns_empty_on_403(self):
        from app.connectors.exceptions import AuthenticationError
        conn = self._connector()
        with patch.object(conn, "_get", side_effect=AuthenticationError("forbidden")):
            records = conn._fetch_environments(MagicMock(), {}, "acme", "repo", "acme/repo")
        assert records == []

    def test_record_id_format(self):
        conn = self._connector()
        with patch.object(conn, "_get", return_value=self._mock_resp(_make_env_response())):
            records = conn._fetch_environments(MagicMock(), {}, "acme", "repo", "acme/repo")
        assert records[0]["record_id"] == "acme/repo#environment#production"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Vercel deploy hook connector
# ─────────────────────────────────────────────────────────────────────────────


class TestVercelDeployHookConnector:
    def test_extracts_hooks_from_project_response(self):
        from app.connectors.vercel import _extract_deploy_hooks
        raw = {
            "id": "prj_abc",
            "deployHooks": [
                {"id": "hook1", "name": "Nightly CI", "ref": "main",
                 "url": "https://api.vercel.com/v1/integrations/deploy/prj_abc/SECRET_TOKEN"},
            ],
        }
        records = _extract_deploy_hooks(raw, "prj_abc")
        assert len(records) == 1
        r = records[0]
        assert r["record_type"] == "vercel_deploy_hook_metadata"
        assert r["hook_id"] == "hook1"
        assert r["hook_name"] == "Nightly CI"
        assert r["hook_ref"] == "main"

    def test_hook_url_never_stored(self):
        """Hook URLs act as auth tokens and must NEVER be stored."""
        from app.connectors.vercel import _extract_deploy_hooks
        raw = {
            "deployHooks": [
                {"id": "hook1", "name": "CI", "ref": "main",
                 "url": "https://api.vercel.com/v1/integrations/deploy/prj_abc/VERY_SECRET_TOKEN"},
            ],
        }
        records = _extract_deploy_hooks(raw, "prj_abc")
        record_str = str(records)
        assert "SECRET_TOKEN" not in record_str
        assert "VERY_SECRET_TOKEN" not in record_str
        assert "integrations/deploy" not in record_str

    def test_no_hooks_returns_empty(self):
        from app.connectors.vercel import _extract_deploy_hooks
        assert _extract_deploy_hooks({}, "prj_abc") == []
        assert _extract_deploy_hooks({"deployHooks": []}, "prj_abc") == []

    def test_missing_hooks_key_returns_empty(self):
        from app.connectors.vercel import _extract_deploy_hooks
        assert _extract_deploy_hooks({"name": "project"}, "prj_abc") == []

    def test_record_id_format(self):
        from app.connectors.vercel import _extract_deploy_hooks
        raw = {"deployHooks": [{"id": "hookX", "name": "X", "ref": "main",
                                "url": "https://api.vercel.com/v1/SECRET"}]}
        records = _extract_deploy_hooks(raw, "prj_123")
        assert records[0]["record_id"] == "prj_123#deploy_hook#hookX"

    def test_multiple_hooks(self):
        from app.connectors.vercel import _extract_deploy_hooks
        raw = {
            "deployHooks": [
                {"id": "h1", "name": "Hook A", "ref": "main", "url": "https://vercel/SECRET_A"},
                {"id": "h2", "name": "Hook B", "ref": "develop", "url": "https://vercel/SECRET_B"},
            ],
        }
        records = _extract_deploy_hooks(raw, "prj_xyz")
        assert len(records) == 2
        assert records[0]["hook_ref"] == "main"
        assert records[1]["hook_ref"] == "develop"
        record_str = str(records)
        assert "SECRET_A" not in record_str
        assert "SECRET_B" not in record_str

    def test_hook_without_ref(self):
        from app.connectors.vercel import _extract_deploy_hooks
        raw = {"deployHooks": [{"id": "h1", "name": "No-ref hook", "url": "https://vercel/S"}]}
        records = _extract_deploy_hooks(raw, "prj_abc")
        assert records[0]["hook_ref"] is None


# ─────────────────────────────────────────────────────────────────────────────
# 5. Shopify access scope connector
# ─────────────────────────────────────────────────────────────────────────────


class TestShopifyAccessScopeConnector:
    def _connector(self):
        from app.connectors.shopify import ShopifyConnector
        return ShopifyConnector()

    def _creds(self):
        return {
            "shopify_access_token": "shpat_test",
            "shop_domain": "testshop.myshopify.com",
        }

    def _mock_scope_response(self, scopes):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.is_success = True
        mock_resp.json.return_value = {
            "access_scopes": [{"handle": s} for s in scopes]
        }
        return mock_resp

    def test_scope_count(self):
        conn = self._connector()
        with patch("app.connectors.shopify.httpx") as mock_httpx:
            mock_httpx.get.return_value = self._mock_scope_response(
                ["read_products", "write_products", "read_orders"]
            )
            record = conn._fetch_access_scopes(self._creds())
        assert record is not None
        assert record["scope_count"] == 3

    def test_scope_hash_present(self):
        conn = self._connector()
        with patch("app.connectors.shopify.httpx") as mock_httpx:
            mock_httpx.get.return_value = self._mock_scope_response(
                ["read_products", "write_products"]
            )
            record = conn._fetch_access_scopes(self._creds())
        assert record is not None
        assert len(record["scope_hash"]) == 16

    def test_write_scope_count(self):
        conn = self._connector()
        with patch("app.connectors.shopify.httpx") as mock_httpx:
            mock_httpx.get.return_value = self._mock_scope_response(
                ["read_products", "write_products", "write_inventory", "read_orders"]
            )
            record = conn._fetch_access_scopes(self._creds())
        assert record["write_scope_count"] == 2

    def test_sensitive_scope_count(self):
        conn = self._connector()
        with patch("app.connectors.shopify.httpx") as mock_httpx:
            mock_httpx.get.return_value = self._mock_scope_response(
                ["read_products", "read_orders", "read_customers"]
            )
            record = conn._fetch_access_scopes(self._creds())
        # read_orders + read_customers are both in SENSITIVE_SHOPIFY_SCOPES
        assert record["sensitive_scope_count"] == 2

    def test_customer_scope_present_flag(self):
        conn = self._connector()
        with patch("app.connectors.shopify.httpx") as mock_httpx:
            mock_httpx.get.return_value = self._mock_scope_response(
                ["read_customers", "write_products"]
            )
            record = conn._fetch_access_scopes(self._creds())
        assert record["customer_scope_present"] is True
        assert record["order_scope_present"] is False

    def test_order_scope_present_flag(self):
        conn = self._connector()
        with patch("app.connectors.shopify.httpx") as mock_httpx:
            mock_httpx.get.return_value = self._mock_scope_response(
                ["read_orders", "write_products"]
            )
            record = conn._fetch_access_scopes(self._creds())
        assert record["order_scope_present"] is True

    def test_payment_scope_present_flag(self):
        conn = self._connector()
        with patch("app.connectors.shopify.httpx") as mock_httpx:
            mock_httpx.get.return_value = self._mock_scope_response(
                ["read_shopify_payments_payouts", "read_products"]
            )
            record = conn._fetch_access_scopes(self._creds())
        assert record["payment_scope_present"] is True

    def test_scope_names_sorted(self):
        conn = self._connector()
        with patch("app.connectors.shopify.httpx") as mock_httpx:
            mock_httpx.get.return_value = self._mock_scope_response(
                ["write_products", "read_inventory", "read_products"]
            )
            record = conn._fetch_access_scopes(self._creds())
        assert record["scope_names"] == sorted(record["scope_names"])

    def test_no_customer_pii_in_record(self):
        """Scope names are labels — no customer data should appear."""
        conn = self._connector()
        with patch("app.connectors.shopify.httpx") as mock_httpx:
            mock_httpx.get.return_value = self._mock_scope_response(
                ["read_orders", "read_customers"]
            )
            record = conn._fetch_access_scopes(self._creds())
        record_str = str(record)
        # No actual order/customer objects — only scope label strings
        for forbidden in ("customer@", "order_id", "email", "phone"):
            assert forbidden not in record_str

    def test_returns_none_on_403(self):
        conn = self._connector()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.is_success = False
        with patch("app.connectors.shopify.httpx") as mock_httpx:
            mock_httpx.get.return_value = mock_resp
            record = conn._fetch_access_scopes(self._creds())
        assert record is None

    def test_returns_none_on_network_error(self):
        import httpx
        conn = self._connector()
        with patch("app.connectors.shopify.httpx") as mock_httpx:
            mock_httpx.get.side_effect = httpx.RequestError("network error")
            record = conn._fetch_access_scopes(self._creds())
        assert record is None

    def test_record_type_and_id(self):
        conn = self._connector()
        with patch("app.connectors.shopify.httpx") as mock_httpx:
            mock_httpx.get.return_value = self._mock_scope_response(["read_products"])
            record = conn._fetch_access_scopes(self._creds())
        assert record["record_type"] == "shopify_app_scope_summary"
        assert record["record_id"] == "testshop.myshopify.com:app_scopes"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Diff tracked fields
# ─────────────────────────────────────────────────────────────────────────────


class TestDiffTrackedFieldsM579:
    def _tracked(self, rt: str) -> tuple:
        from app.services.diff_service import _tracked_fields_for
        return _tracked_fields_for({"record_type": rt})

    def test_stripe_billing_portal_config_registered(self):
        fields = self._tracked("stripe_billing_portal_config")
        assert "active" in fields
        assert "payment_method_update_enabled" in fields
        assert "subscription_cancel_enabled" in fields
        assert "subscription_cancel_mode" in fields
        assert "customer_update_allowed_updates" in fields

    def test_github_environment_protection_registered(self):
        fields = self._tracked("github_environment_protection")
        assert "wait_timer" in fields
        assert "reviewers_count" in fields
        assert "prevent_self_review" in fields
        assert "protected_branches" in fields

    def test_vercel_deploy_hook_metadata_registered(self):
        fields = self._tracked("vercel_deploy_hook_metadata")
        assert "hook_name" in fields
        assert "hook_ref" in fields

    def test_shopify_app_scope_summary_registered(self):
        fields = self._tracked("shopify_app_scope_summary")
        assert "scope_count" in fields
        assert "scope_hash" in fields
        assert "sensitive_scope_count" in fields
        assert "customer_scope_present" in fields

    def test_existing_stripe_types_unchanged(self):
        fields = self._tracked("stripe_webhook_endpoint")
        assert "url" in fields
        assert "status" in fields

    def test_existing_github_types_unchanged(self):
        fields = self._tracked("github_branch_protection")
        assert "protection_enabled" in fields
        assert "required_approving_review_count" in fields


# ─────────────────────────────────────────────────────────────────────────────
# 7. Stripe billing portal risk rules
# ─────────────────────────────────────────────────────────────────────────────


def _make_stripe_change(record_type, change_type, field_path=None, old_value=None, new_value=None):
    return {
        "change_type": change_type,
        "field_path": field_path or "",
        "prev_value": old_value,
        "new_value": new_value,
        "provider_metadata": {"record_type": record_type},
    }


class TestStripeBillingPortalRisk:
    def _classify(self, **kwargs):
        from app.services.risk_rules.stripe import _classify_billing_portal_config_change
        return _classify_billing_portal_config_change(_make_stripe_change("stripe_billing_portal_config", **kwargs))

    def test_removed_is_high(self):
        level, _ = self._classify(change_type="removed")
        assert level == "high"

    def test_added_is_low(self):
        level, _ = self._classify(change_type="added")
        assert level == "low"

    def test_active_disabled_is_medium(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="active",
            old_value={"active": True},
            new_value={"active": False},
        )
        assert level == "medium"

    def test_payment_method_update_disabled_is_medium(self):
        level, _ = self._classify(
            change_type="modified",
            old_value={"payment_method_update_enabled": True},
            new_value={"payment_method_update_enabled": False},
        )
        assert level == "medium"

    def test_subscription_cancel_changed_is_medium(self):
        level, _ = self._classify(
            change_type="modified",
            old_value={"subscription_cancel_enabled": False},
            new_value={"subscription_cancel_enabled": True},
        )
        assert level == "medium"

    def test_customer_update_allowed_changed_is_medium(self):
        level, _ = self._classify(
            change_type="modified",
            old_value={"customer_update_allowed_updates": ["email"]},
            new_value={"customer_update_allowed_updates": ["email", "address"]},
        )
        assert level == "medium"

    def test_subscription_cancel_mode_changed_is_low(self):
        level, _ = self._classify(
            change_type="modified",
            old_value={"subscription_cancel_mode": "at_period_end"},
            new_value={"subscription_cancel_mode": "immediately"},
        )
        assert level == "low"

    def test_invoice_history_changed_is_low(self):
        level, _ = self._classify(
            change_type="modified",
            old_value={"invoice_history_enabled": True},
            new_value={"invoice_history_enabled": False},
        )
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 8. GitHub environment protection risk rules
# ─────────────────────────────────────────────────────────────────────────────


def _make_github_env_change(change_type, field_path=None, prev_value=None, new_value=None):
    return {
        "change_type": change_type,
        "field_path": field_path or "",
        "prev_value": prev_value,
        "new_value": new_value,
        "provider_metadata": {"record_type": "github_environment_protection", "record_name": "production"},
    }


class TestGitHubEnvironmentProtectionRisk:
    def _classify(self, **kwargs):
        from app.services.risk_rules.github import _classify_environment_protection
        c = _make_github_env_change(**kwargs)
        from app.services.risk_rules.github import _get
        return _classify_environment_protection(
            c["change_type"],
            c["field_path"],
            c["prev_value"],
            c["new_value"],
            c["provider_metadata"].get("record_name", ""),
        )

    def test_removed_is_high(self):
        level, _ = self._classify(change_type="removed")
        assert level == "high"

    def test_added_is_low(self):
        level, _ = self._classify(change_type="added")
        assert level == "low"

    def test_reviewers_count_decreased_is_high(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="reviewers_count",
            prev_value=2,
            new_value=0,
        )
        assert level == "high"

    def test_reviewers_count_increased_is_low(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="reviewers_count",
            prev_value=1,
            new_value=3,
        )
        assert level == "low"

    def test_prevent_self_review_disabled_is_medium(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="prevent_self_review",
            prev_value=True,
            new_value=False,
        )
        assert level == "medium"

    def test_prevent_self_review_enabled_is_low(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="prevent_self_review",
            prev_value=False,
            new_value=True,
        )
        assert level == "low"

    def test_wait_timer_decreased_is_medium(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="wait_timer",
            prev_value=60,
            new_value=0,
        )
        assert level == "medium"

    def test_wait_timer_increased_is_low(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="wait_timer",
            prev_value=0,
            new_value=30,
        )
        assert level == "low"

    def test_protected_branches_false_is_high(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="protected_branches",
            prev_value=True,
            new_value=False,
        )
        assert level == "high"

    def test_custom_branch_policies_changed_is_medium(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="custom_branch_policies",
            prev_value=False,
            new_value=True,
        )
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Vercel deploy hook risk rules
# ─────────────────────────────────────────────────────────────────────────────


def _make_vercel_hook_change(change_type, field_path=None, prev_value=None, new_value=None):
    return {
        "change_type": change_type,
        "field_path": field_path or "",
        "prev_value": prev_value,
        "new_value": new_value,
        "provider_metadata": {"record_type": "vercel_deploy_hook_metadata", "record_name": "nightly-ci"},
    }


class TestVercelDeployHookRisk:
    def _classify(self, **kwargs):
        from app.services.risk_rules.vercel import _classify_deploy_hook_metadata
        c = _make_vercel_hook_change(**kwargs)
        return _classify_deploy_hook_metadata(
            c["change_type"],
            c["field_path"],
            c["prev_value"],
            c["new_value"],
            c["provider_metadata"].get("record_name", ""),
        )

    def test_removed_is_medium(self):
        level, _ = self._classify(change_type="removed")
        assert level == "medium"

    def test_added_is_medium(self):
        level, _ = self._classify(change_type="added")
        assert level == "medium"

    def test_hook_ref_changed_is_high(self):
        # Policy update (Vercel audit): changing a deploy hook's target ref
        # redirects what gets deployed whenever any external CI/CD system
        # calls the hook URL — that's a high-impact change, not cosmetic.
        level, _ = self._classify(
            change_type="modified",
            field_path="hook_ref",
            prev_value="main",
            new_value="develop",
        )
        assert level == "high"

    def test_hook_name_changed_is_low(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="hook_name",
            prev_value="old name",
            new_value="new name",
        )
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 10. Shopify app scope risk rules
# ─────────────────────────────────────────────────────────────────────────────


def _make_shopify_scope_change(change_type, field_path=None, prev_value=None, new_value=None):
    return {
        "change_type": change_type,
        "field_path": field_path or "",
        "prev_value": prev_value,
        "new_value": new_value,
        "provider_metadata": {"record_type": "shopify_app_scope_summary"},
    }


class TestShopifyAppScopeRisk:
    def _classify(self, **kwargs):
        from app.services.risk_rules.shopify import _classify_app_scope_summary_change
        return _classify_app_scope_summary_change(_make_shopify_scope_change(**kwargs))

    def test_removed_is_high(self):
        level, _ = self._classify(change_type="removed")
        assert level == "high"

    def test_added_is_low(self):
        level, _ = self._classify(change_type="added")
        assert level == "low"

    def test_sensitive_scope_increased_is_high(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="sensitive_scope_count",
            prev_value=1,
            new_value=3,
        )
        assert level == "high"

    def test_write_scope_increased_is_high(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="write_scope_count",
            prev_value=0,
            new_value=2,
        )
        assert level == "high"

    def test_customer_scope_newly_present_is_high(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="customer_scope_present",
            prev_value=False,
            new_value=True,
        )
        assert level == "high"

    def test_order_scope_newly_present_is_high(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="order_scope_present",
            prev_value=False,
            new_value=True,
        )
        assert level == "high"

    def test_payment_scope_newly_present_is_critical(self):
        # Policy update (audit): payment scopes give an app the ability to
        # read or act on payment-method / charge data — a newly granted
        # payment scope is a top-severity event. customer/order scopes
        # remain "high".
        level, _ = self._classify(
            change_type="modified",
            field_path="payment_scope_present",
            prev_value=False,
            new_value=True,
        )
        assert level == "critical"

    def test_scope_count_increased_is_medium(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="scope_count",
            prev_value=3,
            new_value=5,
        )
        assert level == "medium"

    def test_scope_count_decreased_is_medium(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="scope_count",
            prev_value=5,
            new_value=3,
        )
        assert level == "medium"

    def test_scope_hash_changed_is_medium(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="scope_hash",
            prev_value="abc123",
            new_value="def456",
        )
        assert level == "medium"

    def test_scope_names_changed_is_medium(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="scope_names",
            prev_value=["read_products"],
            new_value=["read_products", "write_products"],
        )
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# 11. Risk service dispatch
# ─────────────────────────────────────────────────────────────────────────────


class TestRiskDispatchM579:
    def _make_change(self, record_type, change_type="removed"):
        return {
            "change_type": change_type,
            "field_path": "",
            "prev_value": None,
            "new_value": None,
            "provider_metadata": {"record_type": record_type},
        }

    def test_stripe_billing_portal_dispatched(self):
        from app.services.risk_service import classify_change
        level, _ = classify_change(self._make_change("stripe_billing_portal_config"))
        assert level == "high"

    def test_github_environment_dispatched(self):
        from app.services.risk_service import classify_change
        level, _ = classify_change(self._make_change("github_environment_protection"))
        assert level == "high"

    def test_vercel_deploy_hook_dispatched(self):
        from app.services.risk_service import classify_change
        level, _ = classify_change(self._make_change("vercel_deploy_hook_metadata"))
        assert level == "medium"

    def test_shopify_app_scope_dispatched(self):
        from app.services.risk_service import classify_change
        level, _ = classify_change(self._make_change("shopify_app_scope_summary"))
        assert level == "high"
