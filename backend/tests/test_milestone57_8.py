"""Tests for M57.8 — Firebase + Supabase App Security depth.

Covers:
  1.  Firebase schema: FIREBASE_REMOTE_CONFIG_TEMPLATE and FIREBASE_APP_CHECK_CONFIG constants
  2.  Firebase schema: FIREBASE_RECORD_TYPES frozenset includes both new types
  3.  Firebase connector: _fetch_remote_config normalisation (counts, hashes)
  4.  Firebase connector: _fetch_remote_config — parameter VALUES never stored
  5.  Firebase connector: _fetch_remote_config — condition expressions never stored
  6.  Firebase connector: _fetch_remote_config — updateUser info never stored
  7.  Firebase connector: _fetch_remote_config fail-soft on 403 / 404 / unexpected
  8.  Firebase connector: _fetch_app_check normalisation (enforcement counts, service names)
  9.  Firebase connector: _fetch_app_check — debug tokens never accessed
  10. Firebase connector: _fetch_app_check fail-soft on 403 / 404 / unexpected
  11. Firebase diff tracked fields: both new types registered
  12. Firebase risk rules: remote config — removed → high, added → low
  13. Firebase risk rules: remote config — parameter_count decrease → medium
  14. Firebase risk rules: remote config — condition_count decrease → medium
  15. Firebase risk rules: remote config — parameter_keys_hash changed → medium
  16. Firebase risk rules: remote config — update_type FORCED_UPDATE → medium
  17. Firebase risk rules: remote config — version_number → low
  18. Firebase risk rules: app check — removed → high, added → low
  19. Firebase risk rules: app check — enforced_service_count decreases → high
  20. Firebase risk rules: app check — unenforced_service_count increases → high
  21. Firebase risk rules: app check — service_count change → medium
  22. Firebase risk service dispatch: new types route through classify_firebase_change
  23. Supabase connector: _fetch_auth_config includes M57.8 security fields
  24. Supabase connector: raw redirect URLs never stored (count only)
  25. Supabase diff tracked fields: new auth security fields present
  26. Supabase risk rules: leaked_password_protection_enabled disabled → high
  27. Supabase risk rules: captcha_enabled disabled → medium
  28. Supabase risk rules: refresh_token_rotation_enabled disabled → medium
  29. Supabase risk rules: jwt_exp increased → medium
  30. Supabase risk rules: additional_redirect_urls_count increased → medium
  31. Supabase risk rules: require_reauthentication disabled → medium
"""

from __future__ import annotations

import hashlib
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_firebase_change(
    record_type: str,
    change_type: str,
    field_path: str = "",
    old_value: Any = None,
    new_value: Any = None,
) -> dict:
    return {
        "change_type": change_type,
        "field_path":  field_path,
        "old_value":   old_value,
        "new_value":   new_value,
        "provider_metadata": {"record_type": record_type},
    }


def _make_supabase_change(
    record_type: str,
    change_type: str,
    field_path: str = "",
    old_value: Any = None,
    new_value: Any = None,
) -> dict:
    return {
        "change_type": change_type,
        "field_path":  field_path,
        "old_value":   old_value,
        "new_value":   new_value,
        # Supabase risk rules read prev_value not old_value for some fields
        "prev_value":  old_value,
        "provider_metadata": {"record_type": record_type},
    }


def _sha256p(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# 1–2. Firebase schema constants
# ─────────────────────────────────────────────────────────────────────────────

class TestFirebaseSchemaM578:
    def test_remote_config_constant(self):
        from app.connectors.firebase_schema import FIREBASE_REMOTE_CONFIG_TEMPLATE
        assert FIREBASE_REMOTE_CONFIG_TEMPLATE == "firebase_remote_config_template"

    def test_app_check_constant(self):
        from app.connectors.firebase_schema import FIREBASE_APP_CHECK_CONFIG
        assert FIREBASE_APP_CHECK_CONFIG == "firebase_app_check_config"

    def test_both_in_record_types_frozenset(self):
        from app.connectors.firebase_schema import (
            FIREBASE_APP_CHECK_CONFIG,
            FIREBASE_RECORD_TYPES,
            FIREBASE_REMOTE_CONFIG_TEMPLATE,
        )
        assert FIREBASE_REMOTE_CONFIG_TEMPLATE in FIREBASE_RECORD_TYPES
        assert FIREBASE_APP_CHECK_CONFIG in FIREBASE_RECORD_TYPES

    def test_existing_types_still_in_frozenset(self):
        """Regression: existing record types must not have been removed."""
        from app.connectors.firebase_schema import FIREBASE_RECORD_TYPES
        for rt in (
            "firebase_project", "firebase_auth_config", "firebase_auth_provider",
            "firebase_firestore_ruleset", "firebase_storage_bucket",
            "firebase_hosting_site", "firebase_function_metadata",
        ):
            assert rt in FIREBASE_RECORD_TYPES, f"{rt!r} missing from FIREBASE_RECORD_TYPES"


# ─────────────────────────────────────────────────────────────────────────────
# 3–7. Firebase connector — Remote Config
# ─────────────────────────────────────────────────────────────────────────────

class TestFirebaseRemoteConfig:
    """Unit-tests for FirebaseConnector._fetch_remote_config."""

    def _connector(self):
        from app.connectors.firebase import FirebaseConnector
        return FirebaseConnector()

    def _raw_response(
        self,
        parameters: dict | None = None,
        conditions: list | None = None,
        parameter_groups: dict | None = None,
        version: dict | None = None,
    ) -> dict:
        """Build a minimal Raw Remote Config API response."""
        return {
            "parameters": parameters if parameters is not None else {
                "feature_x": {"defaultValue": {"value": "SECRET_VAL"}},
                "feature_y": {"defaultValue": {"value": "ANOTHER_SECRET"}},
            },
            "conditions": conditions if conditions is not None else [
                {"name": "ios_users", "expression": "SENSITIVE_EXPR"},
                {"name": "beta_group", "expression": "ANOTHER_EXPR"},
            ],
            "parameterGroups": parameter_groups if parameter_groups is not None else {
                "group_a": {"description": "SENSITIVE_DESC"},
            },
            "version": version if version is not None else {
                "versionNumber": "7",
                "updateOrigin": "CONSOLE",
                "updateType": "INCREMENTAL_UPDATE",
                "updateUser": {"email": "admin@example.com"},  # MUST NOT be stored
                "description": "Config release note",           # MUST NOT be stored
            },
        }

    def test_basic_normalisation(self):
        conn = self._connector()
        warnings: list = []
        raw = self._raw_response()
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_remote_config("tok", "proj-123", warnings)
        assert len(records) == 1
        r = records[0]
        assert r["record_type"] == "firebase_remote_config_template"
        assert r["project_id"]  == "proj-123"
        assert r["record_id"]   == "proj-123/remote_config"

    def test_parameter_count(self):
        conn = self._connector()
        raw = self._raw_response()  # 2 parameters
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_remote_config("tok", "p", [])
        assert records[0]["parameter_count"] == 2

    def test_condition_count(self):
        conn = self._connector()
        raw = self._raw_response()  # 2 conditions
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_remote_config("tok", "p", [])
        assert records[0]["condition_count"] == 2

    def test_parameter_group_count(self):
        conn = self._connector()
        raw = self._raw_response()  # 1 group
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_remote_config("tok", "p", [])
        assert records[0]["parameter_group_count"] == 1

    def test_parameter_keys_hash_deterministic(self):
        conn = self._connector()
        raw = self._raw_response(parameters={"alpha": {}, "beta": {}, "gamma": {}})
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_remote_config("tok", "p", [])
        expected = _sha256p("alpha,beta,gamma")
        assert records[0]["parameter_keys_hash"] == expected

    def test_condition_names_hash_deterministic(self):
        conn = self._connector()
        raw = self._raw_response(conditions=[
            {"name": "z_cond"}, {"name": "a_cond"},
        ])
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_remote_config("tok", "p", [])
        expected = _sha256p("a_cond,z_cond")  # sorted
        assert records[0]["condition_names_hash"] == expected

    def test_version_metadata_extracted(self):
        conn = self._connector()
        raw = self._raw_response()
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_remote_config("tok", "p", [])
        r = records[0]
        assert r["version_number"] == "7"
        assert r["update_origin"]  == "CONSOLE"
        assert r["update_type"]    == "INCREMENTAL_UPDATE"

    # ── Data minimisation tests ───────────────────────────────────────────────

    def test_parameter_values_not_stored(self):
        """Parameter default/conditional values must NEVER appear in the record."""
        conn = self._connector()
        raw = self._raw_response()
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_remote_config("tok", "p", [])
        record_str = str(records[0])
        assert "SECRET_VAL" not in record_str
        assert "ANOTHER_SECRET" not in record_str

    def test_condition_expressions_not_stored(self):
        """Condition expressions must NEVER appear in the record."""
        conn = self._connector()
        raw = self._raw_response()
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_remote_config("tok", "p", [])
        record_str = str(records[0])
        assert "SENSITIVE_EXPR" not in record_str
        assert "ANOTHER_EXPR" not in record_str

    def test_update_user_not_stored(self):
        """updateUser email must NEVER appear in the record."""
        conn = self._connector()
        raw = self._raw_response()
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_remote_config("tok", "p", [])
        record_str = str(records[0])
        assert "admin@example.com" not in record_str

    def test_description_not_stored(self):
        """updateUser description/release notes must NEVER appear in the record."""
        conn = self._connector()
        raw = self._raw_response()
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_remote_config("tok", "p", [])
        record_str = str(records[0])
        assert "Config release note" not in record_str

    def test_group_descriptions_not_stored(self):
        """Parameter group descriptions must NEVER appear in the record."""
        conn = self._connector()
        raw = self._raw_response()
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_remote_config("tok", "p", [])
        record_str = str(records[0])
        assert "SENSITIVE_DESC" not in record_str

    # ── Fail-soft tests ───────────────────────────────────────────────────────

    def test_403_returns_empty_and_adds_warning(self):
        from app.connectors.exceptions import ConnectorError
        conn = self._connector()
        warnings: list = []
        exc = ConnectorError("forbidden", status_code=403)
        with patch.object(conn, "_get", side_effect=exc):
            records = conn._fetch_remote_config("tok", "p", warnings)
        assert records == []
        assert any("403" in w or "permission" in w.lower() for w in warnings)

    def test_404_returns_empty_silently(self):
        from app.connectors.exceptions import ConnectorError
        conn = self._connector()
        warnings: list = []
        exc = ConnectorError("not found", status_code=404)
        with patch.object(conn, "_get", side_effect=exc):
            records = conn._fetch_remote_config("tok", "p", warnings)
        assert records == []

    def test_unexpected_exception_returns_empty(self):
        conn = self._connector()
        warnings: list = []
        with patch.object(conn, "_get", side_effect=RuntimeError("boom")):
            records = conn._fetch_remote_config("tok", "p", warnings)
        assert records == []
        assert any("Remote Config" in w or "remote_config" in w.lower() or w for w in warnings)

    def test_empty_template_returns_zero_counts(self):
        conn = self._connector()
        raw = self._raw_response(parameters={}, conditions=[], parameter_groups={})
        raw["version"] = {}
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_remote_config("tok", "p", [])
        r = records[0]
        assert r["parameter_count"]       == 0
        assert r["condition_count"]       == 0
        assert r["parameter_group_count"] == 0
        assert r["parameter_keys_hash"]   is None
        assert r["condition_names_hash"]  is None


# ─────────────────────────────────────────────────────────────────────────────
# 8–10. Firebase connector — App Check
# ─────────────────────────────────────────────────────────────────────────────

class TestFirebaseAppCheck:
    """Unit-tests for FirebaseConnector._fetch_app_check."""

    def _connector(self):
        from app.connectors.firebase import FirebaseConnector
        return FirebaseConnector()

    def _raw_response(self, services: list | None = None) -> dict:
        if services is None:
            services = [
                {
                    "name": "projects/123/services/firestore.googleapis.com",
                    "enforcementMode": "ENFORCED",
                },
                {
                    "name": "projects/123/services/storage.googleapis.com",
                    "enforcementMode": "UNENFORCED",
                },
                {
                    "name": "projects/123/services/firebasedatabase.googleapis.com",
                    "enforcementMode": "ENFORCEMENT_MODE_UNSPECIFIED",
                },
            ]
        return {"services": services}

    def test_basic_normalisation(self):
        conn = self._connector()
        raw = self._raw_response()
        with patch.object(conn, "_get", return_value=raw):
            records = conn._fetch_app_check("tok", "proj-123", [])
        assert len(records) == 1
        r = records[0]
        assert r["record_type"] == "firebase_app_check_config"
        assert r["project_id"]  == "proj-123"
        assert r["record_id"]   == "proj-123/app_check"

    def test_service_count(self):
        conn = self._connector()
        with patch.object(conn, "_get", return_value=self._raw_response()):
            records = conn._fetch_app_check("tok", "p", [])
        assert records[0]["service_count"] == 3

    def test_enforced_count(self):
        conn = self._connector()
        with patch.object(conn, "_get", return_value=self._raw_response()):
            records = conn._fetch_app_check("tok", "p", [])
        assert records[0]["enforced_service_count"] == 1
        assert records[0]["unenforced_service_count"] == 2

    def test_enforced_service_names_are_short_api_names(self):
        conn = self._connector()
        with patch.object(conn, "_get", return_value=self._raw_response()):
            records = conn._fetch_app_check("tok", "p", [])
        enforced = records[0]["enforced_service_names"]
        assert isinstance(enforced, list)
        assert "firestore.googleapis.com" in enforced
        # Full resource name must not appear
        assert not any("projects/123/services" in s for s in enforced)

    def test_unenforced_not_in_enforced_names(self):
        conn = self._connector()
        with patch.object(conn, "_get", return_value=self._raw_response()):
            records = conn._fetch_app_check("tok", "p", [])
        enforced = records[0]["enforced_service_names"] or []
        assert "storage.googleapis.com" not in enforced

    def test_no_services_returns_zero_counts(self):
        conn = self._connector()
        with patch.object(conn, "_get", return_value={"services": []}):
            records = conn._fetch_app_check("tok", "p", [])
        r = records[0]
        assert r["service_count"] == 0
        assert r["enforced_service_count"] == 0
        assert r["unenforced_service_count"] == 0
        assert r["enforced_service_names"] is None

    # ── Data minimisation ──────────────────────────────────────────────────────

    def test_no_debug_token_in_record(self):
        """Debug tokens must never be stored — they would not appear in the
        services list, but verify no 'token' key exists in the record."""
        conn = self._connector()
        with patch.object(conn, "_get", return_value=self._raw_response()):
            records = conn._fetch_app_check("tok", "p", [])
        r = records[0]
        assert "debug_token" not in r
        assert "attestation" not in str(r)

    # ── Fail-soft ──────────────────────────────────────────────────────────────

    def test_403_returns_empty_and_adds_warning(self):
        from app.connectors.exceptions import ConnectorError
        conn = self._connector()
        warnings: list = []
        exc = ConnectorError("forbidden", status_code=403)
        with patch.object(conn, "_get", side_effect=exc):
            records = conn._fetch_app_check("tok", "p", warnings)
        assert records == []
        assert any("403" in w or "App Check" in w for w in warnings)

    def test_404_returns_empty_silently(self):
        from app.connectors.exceptions import ConnectorError
        conn = self._connector()
        warnings: list = []
        exc = ConnectorError("not found", status_code=404)
        with patch.object(conn, "_get", side_effect=exc):
            records = conn._fetch_app_check("tok", "p", warnings)
        assert records == []

    def test_unexpected_exception_returns_empty(self):
        conn = self._connector()
        warnings: list = []
        with patch.object(conn, "_get", side_effect=RuntimeError("boom")):
            records = conn._fetch_app_check("tok", "p", warnings)
        assert records == []


# ─────────────────────────────────────────────────────────────────────────────
# 11. Firebase diff tracked fields
# ─────────────────────────────────────────────────────────────────────────────

class TestFirebaseDiffTrackedFieldsM578:
    def _tracked(self, rt: str) -> tuple:
        from app.services.diff_service import _tracked_fields_for
        return _tracked_fields_for({"record_type": rt})

    def test_remote_config_template_tracked(self):
        fields = self._tracked("firebase_remote_config_template")
        expected = {
            "version_number", "update_origin", "update_type",
            "parameter_count", "condition_count", "parameter_group_count",
            "parameter_keys_hash", "condition_names_hash",
        }
        assert expected.issubset(set(fields))

    def test_app_check_config_tracked(self):
        fields = self._tracked("firebase_app_check_config")
        expected = {
            "service_count", "enforced_service_count", "unenforced_service_count",
            "enforced_service_names",
        }
        assert expected.issubset(set(fields))

    def test_existing_firebase_types_still_tracked(self):
        """Regression: existing Firebase types must still return non-empty tuples."""
        for rt in (
            "firebase_project", "firebase_auth_config",
            "firebase_firestore_ruleset", "firebase_storage_bucket",
        ):
            assert len(self._tracked(rt)) > 0, f"{rt!r} tracked fields are empty"


# ─────────────────────────────────────────────────────────────────────────────
# 12–21. Firebase risk rules
# ─────────────────────────────────────────────────────────────────────────────

class TestFirebaseRemoteConfigRisk:
    def _classify(self, **kw) -> tuple[str, str]:
        from app.services.risk_rules.firebase import _classify_remote_config_change
        return _classify_remote_config_change(_make_firebase_change(
            "firebase_remote_config_template", **kw
        ))

    def test_removed_is_high(self):
        level, _ = self._classify(change_type="removed")
        assert level == "high"

    def test_added_is_low(self):
        level, _ = self._classify(change_type="added")
        assert level == "low"

    def test_parameter_count_decrease_is_medium(self):
        level, reason = self._classify(
            change_type="modified", field_path="parameter_count",
            old_value=5, new_value=3,
        )
        assert level == "medium"
        assert "parameter" in reason.lower()

    def test_parameter_count_increase_is_low(self):
        level, _ = self._classify(
            change_type="modified", field_path="parameter_count",
            old_value=3, new_value=7,
        )
        assert level == "low"

    def test_condition_count_decrease_is_medium(self):
        level, _ = self._classify(
            change_type="modified", field_path="condition_count",
            old_value=4, new_value=1,
        )
        assert level == "medium"

    def test_parameter_keys_hash_change_is_medium(self):
        level, _ = self._classify(
            change_type="modified", field_path="parameter_keys_hash",
            old_value="abc", new_value="xyz",
        )
        assert level == "medium"

    def test_condition_names_hash_change_is_medium(self):
        level, _ = self._classify(
            change_type="modified", field_path="condition_names_hash",
            old_value="abc", new_value="xyz",
        )
        assert level == "medium"

    def test_forced_update_is_medium(self):
        level, _ = self._classify(
            change_type="modified", field_path="update_type",
            old_value="INCREMENTAL_UPDATE", new_value="FORCED_UPDATE",
        )
        assert level == "medium"

    def test_rollback_is_medium(self):
        level, _ = self._classify(
            change_type="modified", field_path="update_type",
            new_value="ROLLBACK",
        )
        assert level == "medium"

    def test_version_number_is_low(self):
        level, _ = self._classify(
            change_type="modified", field_path="version_number",
            old_value="6", new_value="7",
        )
        assert level == "low"

    def test_update_origin_is_low(self):
        level, _ = self._classify(
            change_type="modified", field_path="update_origin",
            old_value="CONSOLE", new_value="REST_API",
        )
        assert level == "low"


class TestFirebaseAppCheckRisk:
    def _classify(self, **kw) -> tuple[str, str]:
        from app.services.risk_rules.firebase import _classify_app_check_change
        return _classify_app_check_change(_make_firebase_change(
            "firebase_app_check_config", **kw
        ))

    def test_removed_is_high(self):
        level, _ = self._classify(change_type="removed")
        assert level == "high"

    def test_added_is_low(self):
        level, _ = self._classify(change_type="added")
        assert level == "low"

    def test_enforced_count_decrease_is_high(self):
        level, reason = self._classify(
            change_type="modified", field_path="enforced_service_count",
            old_value=3, new_value=1,
        )
        assert level == "high"
        assert "enforc" in reason.lower()

    def test_enforced_count_increase_is_low(self):
        level, _ = self._classify(
            change_type="modified", field_path="enforced_service_count",
            old_value=1, new_value=3,
        )
        assert level == "low"

    def test_unenforced_count_increase_is_high(self):
        level, reason = self._classify(
            change_type="modified", field_path="unenforced_service_count",
            old_value=1, new_value=3,
        )
        assert level == "high"

    def test_unenforced_count_decrease_is_low(self):
        level, _ = self._classify(
            change_type="modified", field_path="unenforced_service_count",
            old_value=3, new_value=1,
        )
        assert level == "low"

    def test_service_count_decrease_is_medium(self):
        level, _ = self._classify(
            change_type="modified", field_path="service_count",
            old_value=5, new_value=3,
        )
        assert level == "medium"

    def test_service_count_increase_is_medium(self):
        level, _ = self._classify(
            change_type="modified", field_path="service_count",
            old_value=3, new_value=5,
        )
        assert level == "medium"

    def test_enforced_service_names_change_is_medium(self):
        level, _ = self._classify(
            change_type="modified", field_path="enforced_service_names",
            old_value=["firestore.googleapis.com"],
            new_value=["firestore.googleapis.com", "storage.googleapis.com"],
        )
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# 22. Firebase risk service dispatch for new types
# ─────────────────────────────────────────────────────────────────────────────

class TestFirebaseRiskDispatchM578:
    def test_remote_config_dispatched(self):
        from app.services.risk_service import classify_change
        change = _make_firebase_change("firebase_remote_config_template", "removed")
        level, _ = classify_change(change)
        assert level == "high"

    def test_app_check_dispatched(self):
        from app.services.risk_service import classify_change
        change = _make_firebase_change("firebase_app_check_config", "removed")
        level, _ = classify_change(change)
        assert level == "high"


# ─────────────────────────────────────────────────────────────────────────────
# 23–24. Supabase connector — auth security depth
# ─────────────────────────────────────────────────────────────────────────────

class TestSupabaseAuthSecurityDepth:
    """Verify _fetch_auth_config captures M57.8 security fields."""

    def _connector(self):
        from app.connectors.supabase import SupabaseConnector
        return SupabaseConnector()

    def _raw_auth_data(
        self,
        password_hibp_enabled: bool = True,
        security_captcha_enabled: bool = True,
        security_update_password_require_reauthentication: bool = True,
        refresh_token_rotation_enabled: bool = True,
        jwt_exp: int = 3600,
        additional_redirect_urls: list | None = None,
    ) -> dict:
        return {
            "email_enabled": True,
            "phone_enabled": False,
            "anonymous_enabled": False,
            "mfa_totp_enabled": True,
            "session_timebox": None,
            "session_inactivity_timeout": None,
            "password_min_length": 8,
            "site_url": "https://example.com",
            "rate_limit_anonymous_users": None,
            "external": {},
            # M57.8 fields
            "password_hibp_enabled": password_hibp_enabled,
            "security_captcha_enabled": security_captcha_enabled,
            "security_update_password_require_reauthentication": security_update_password_require_reauthentication,
            "refresh_token_rotation_enabled": refresh_token_rotation_enabled,
            "jwt_exp": jwt_exp,
            "additional_redirect_urls": additional_redirect_urls if additional_redirect_urls is not None else ["https://app.example.com/callback"],
        }

    def test_leaked_password_protection_present(self):
        conn = self._connector()
        raw = self._raw_auth_data(password_hibp_enabled=True)
        with patch.object(conn, "_get", return_value=raw):
            auth_record, _ = conn._fetch_auth_config("tok", "ref123")
        assert auth_record["leaked_password_protection_enabled"] is True

    def test_leaked_password_protection_false(self):
        conn = self._connector()
        raw = self._raw_auth_data(password_hibp_enabled=False)
        with patch.object(conn, "_get", return_value=raw):
            auth_record, _ = conn._fetch_auth_config("tok", "ref123")
        assert auth_record["leaked_password_protection_enabled"] is False

    def test_captcha_enabled_present(self):
        conn = self._connector()
        raw = self._raw_auth_data(security_captcha_enabled=True)
        with patch.object(conn, "_get", return_value=raw):
            auth_record, _ = conn._fetch_auth_config("tok", "ref123")
        assert auth_record["captcha_enabled"] is True

    def test_refresh_token_rotation_present(self):
        conn = self._connector()
        raw = self._raw_auth_data(refresh_token_rotation_enabled=True)
        with patch.object(conn, "_get", return_value=raw):
            auth_record, _ = conn._fetch_auth_config("tok", "ref123")
        assert auth_record["refresh_token_rotation_enabled"] is True

    def test_jwt_exp_present(self):
        conn = self._connector()
        raw = self._raw_auth_data(jwt_exp=7200)
        with patch.object(conn, "_get", return_value=raw):
            auth_record, _ = conn._fetch_auth_config("tok", "ref123")
        assert auth_record["jwt_exp"] == 7200

    def test_require_reauthentication_present(self):
        conn = self._connector()
        raw = self._raw_auth_data(security_update_password_require_reauthentication=True)
        with patch.object(conn, "_get", return_value=raw):
            auth_record, _ = conn._fetch_auth_config("tok", "ref123")
        assert auth_record["require_reauthentication_for_password_update"] is True

    def test_additional_redirect_urls_count_not_raw_urls(self):
        """Raw redirect URLs must NEVER be stored — only the count."""
        conn = self._connector()
        raw = self._raw_auth_data(additional_redirect_urls=[
            "https://secret-app.internal/callback",
            "https://other.example.com/auth",
        ])
        with patch.object(conn, "_get", return_value=raw):
            auth_record, _ = conn._fetch_auth_config("tok", "ref123")
        # Only count stored
        assert auth_record["additional_redirect_urls_count"] == 2
        # Raw URLs never in record
        record_str = str(auth_record)
        assert "secret-app.internal" not in record_str
        assert "other.example.com" not in record_str

    def test_empty_redirect_urls_count_is_zero(self):
        conn = self._connector()
        raw = self._raw_auth_data(additional_redirect_urls=[])
        with patch.object(conn, "_get", return_value=raw):
            auth_record, _ = conn._fetch_auth_config("tok", "ref123")
        assert auth_record["additional_redirect_urls_count"] == 0

    def test_missing_m578_fields_default_to_false(self):
        """When M57.8 fields are absent from the API response, defaults apply."""
        conn = self._connector()
        raw = {
            "email_enabled": True,
            "phone_enabled": False,
            "anonymous_enabled": False,
            "mfa_totp_enabled": False,
            "external": {},
        }
        with patch.object(conn, "_get", return_value=raw):
            auth_record, _ = conn._fetch_auth_config("tok", "ref123")
        assert auth_record["leaked_password_protection_enabled"] is False
        assert auth_record["captcha_enabled"] is False
        assert auth_record["refresh_token_rotation_enabled"] is False
        assert auth_record["require_reauthentication_for_password_update"] is False
        assert auth_record["additional_redirect_urls_count"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# 25. Supabase diff tracked fields
# ─────────────────────────────────────────────────────────────────────────────

class TestSupabaseDiffTrackedFieldsM578:
    def _tracked(self, rt: str) -> tuple:
        from app.services.diff_service import _tracked_fields_for
        return _tracked_fields_for({"record_type": rt})

    def test_auth_config_has_m578_fields(self):
        fields = self._tracked("supabase_auth_config")
        expected = {
            "leaked_password_protection_enabled",
            "captcha_enabled",
            "require_reauthentication_for_password_update",
            "refresh_token_rotation_enabled",
            "jwt_exp",
            "additional_redirect_urls_count",
        }
        assert expected.issubset(set(fields)), (
            f"Missing M57.8 fields: {expected - set(fields)}"
        )

    def test_auth_config_existing_fields_still_tracked(self):
        """Regression: existing fields must not be dropped."""
        fields = self._tracked("supabase_auth_config")
        for f in ("email_enabled", "mfa_totp_enabled", "anonymous_enabled", "password_min_length"):
            assert f in fields, f"{f!r} missing from supabase_auth_config tracked fields"


# ─────────────────────────────────────────────────────────────────────────────
# 26–31. Supabase risk rules for M57.8 fields
# ─────────────────────────────────────────────────────────────────────────────

class TestSupabaseAuthSecurityRiskM578:
    def _classify(self, **kw) -> tuple[str, str]:
        from app.services.risk_rules.supabase import _classify_auth_config_change
        return _classify_auth_config_change(_make_supabase_change(
            "supabase_auth_config", **kw
        ))

    def test_leaked_password_protection_disabled_is_high(self):
        level, reason = self._classify(
            change_type="modified",
            field_path="leaked_password_protection_enabled",
            new_value=False,
        )
        assert level == "high"
        assert "password" in reason.lower() or "leak" in reason.lower() or "hibp" in reason.lower()

    def test_leaked_password_protection_enabled_is_low(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="leaked_password_protection_enabled",
            new_value=True,
        )
        assert level == "low"

    def test_captcha_disabled_is_medium(self):
        level, reason = self._classify(
            change_type="modified",
            field_path="captcha_enabled",
            new_value=False,
        )
        assert level == "medium"
        assert "captcha" in reason.lower() or "bot" in reason.lower()

    def test_captcha_enabled_is_low(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="captcha_enabled",
            new_value=True,
        )
        assert level == "low"

    def test_refresh_token_rotation_disabled_is_high(self):
        # Policy update (audit): without rotation, a stolen refresh token
        # can be reused indefinitely without detection → high.
        level, reason = self._classify(
            change_type="modified",
            field_path="refresh_token_rotation_enabled",
            new_value=False,
        )
        assert level == "high"
        assert "token" in reason.lower() or "refresh" in reason.lower()

    def test_refresh_token_rotation_enabled_is_low(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="refresh_token_rotation_enabled",
            new_value=True,
        )
        assert level == "low"

    def test_jwt_exp_significant_increase_is_high(self):
        # Policy update (audit): a ≥2× extension of JWT lifetime materially
        # widens the exposure window for a stolen token. 3600s → 86400s is
        # 24× so this case is now high (was medium).
        level, reason = self._classify(
            change_type="modified",
            field_path="jwt_exp",
            old_value=3600,
            new_value=86400,
        )
        assert level == "high"
        assert "jwt" in reason.lower() or "expiry" in reason.lower() or "expir" in reason.lower()

    def test_jwt_exp_decrease_is_low(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="jwt_exp",
            old_value=86400,
            new_value=3600,
        )
        assert level == "low"

    def test_redirect_urls_count_increase_is_medium(self):
        level, reason = self._classify(
            change_type="modified",
            field_path="additional_redirect_urls_count",
            old_value=1,
            new_value=4,
        )
        assert level == "medium"
        assert "redirect" in reason.lower()

    def test_redirect_urls_count_decrease_is_low(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="additional_redirect_urls_count",
            old_value=4,
            new_value=1,
        )
        assert level == "low"

    def test_require_reauthentication_disabled_is_medium(self):
        level, reason = self._classify(
            change_type="modified",
            field_path="require_reauthentication_for_password_update",
            new_value=False,
        )
        assert level == "medium"
        assert "reauth" in reason.lower() or "password" in reason.lower()

    def test_require_reauthentication_enabled_is_low(self):
        level, _ = self._classify(
            change_type="modified",
            field_path="require_reauthentication_for_password_update",
            new_value=True,
        )
        assert level == "low"
