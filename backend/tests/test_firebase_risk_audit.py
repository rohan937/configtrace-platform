"""Firebase risk accuracy audit — local-only regression tests.

Builds the scenario matrix from the verification brief and asserts the
expected severity for each scenario. Documents ConfigTrace's Firebase
risk policy so any future regression that mis-rates one of these
scenarios fails loudly here.

Pure-mock; no DB, no network, no Firebase / GCP API.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _change(
    *,
    record_type: str,
    field_path: str | None = None,
    change_type: str = "modified",
    new_value: Any = None,
    prev_value: Any = None,
    extra_metadata: dict[str, Any] | None = None,
) -> MagicMock:
    pm: dict[str, Any] = {"record_type": record_type}
    if extra_metadata:
        pm.update(extra_metadata)
    c = MagicMock(name="Change")
    c.field_path        = field_path
    c.change_type       = change_type
    c.new_value         = new_value
    c.prev_value        = prev_value
    c.old_value         = prev_value          # M57.8 helpers read old_value
    c.provider_metadata = pm
    return c


def _classify(change):
    from app.services.risk_rules.firebase import classify_firebase_change
    return classify_firebase_change(change)


# ─────────────────────────────────────────────────────────────────────────────
# A. Firestore / Realtime Database security rules
# ─────────────────────────────────────────────────────────────────────────────

class TestFirestoreRuleset:
    def test_A1_public_write_detected_is_critical(self):
        c = _change(
            record_type="firebase_firestore_ruleset",
            field_path="public_write_detected",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_A2_public_read_detected_is_high(self):
        c = _change(
            record_type="firebase_firestore_ruleset",
            field_path="public_read_detected",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A3_rules_no_longer_public_write_is_low(self):
        c = _change(
            record_type="firebase_firestore_ruleset",
            field_path="public_write_detected",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_A4_authenticated_only_false_is_medium(self):
        c = _change(
            record_type="firebase_firestore_ruleset",
            field_path="authenticated_only_detected",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_A5_rules_hash_changed_is_medium(self):
        c = _change(
            record_type="firebase_firestore_ruleset",
            field_path="rules_hash",
            new_value="abc123",
            prev_value="def456",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_A6_ruleset_removed_is_high(self):
        # Per brief: "rules removed/emptied" is critical/high. Without
        # knowing whether the rules are truly empty vs the connector lost
        # access, we treat it as high.
        c = _change(
            record_type="firebase_firestore_ruleset",
            change_type="removed",
        )
        level, _ = _classify(c)
        assert level == "high"


# ─────────────────────────────────────────────────────────────────────────────
# B. Firebase Storage
# ─────────────────────────────────────────────────────────────────────────────

class TestStorage:
    def test_B1_storage_public_write_is_critical(self):
        c = _change(
            record_type="firebase_storage_ruleset",
            field_path="public_write_detected",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_B2_storage_public_read_is_high(self):
        c = _change(
            record_type="firebase_storage_ruleset",
            field_path="public_read_detected",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B3_storage_ruleset_removed_is_high(self):
        c = _change(
            record_type="firebase_storage_ruleset",
            change_type="removed",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B4_uniform_bucket_level_access_disabled_is_high(self):
        c = _change(
            record_type="firebase_storage_bucket",
            field_path="uniform_bucket_level_access",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B5_public_access_prevention_unenforced_is_high(self):
        c = _change(
            record_type="firebase_storage_bucket",
            field_path="public_access_prevention",
            new_value="inherited",
            prev_value="enforced",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B6_uniform_bucket_level_access_enabled_is_low(self):
        c = _change(
            record_type="firebase_storage_bucket",
            field_path="uniform_bucket_level_access",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# C. Firebase Auth
# ─────────────────────────────────────────────────────────────────────────────

class TestAuth:
    def test_C1_anonymous_enabled_is_high(self):
        c = _change(
            record_type="firebase_auth_config",
            field_path="anonymous_enabled",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C2_anonymous_disabled_is_low(self):
        c = _change(
            record_type="firebase_auth_config",
            field_path="anonymous_enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_C3_mfa_disabled_is_high(self):
        c = _change(
            record_type="firebase_auth_config",
            field_path="mfa_enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C4_email_disabled_is_medium(self):
        c = _change(
            record_type="firebase_auth_config",
            field_path="sign_in_email_enabled",
            new_value=False,
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_C5_custom_authorized_domain_added_is_high(self):
        c = _change(
            record_type="firebase_authorized_domain",
            change_type="added",
            extra_metadata={
                "domain": "evil.example.com",
                "is_default_firebase_domain": False,
                "is_localhost": False,
            },
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C6_default_firebase_domain_added_is_low(self):
        c = _change(
            record_type="firebase_authorized_domain",
            change_type="added",
            extra_metadata={
                "domain": "my-project.firebaseapp.com",
                "is_default_firebase_domain": True,
                "is_localhost": False,
            },
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_C7_localhost_authorized_domain_added_is_low(self):
        c = _change(
            record_type="firebase_authorized_domain",
            change_type="added",
            extra_metadata={
                "domain": "localhost",
                "is_default_firebase_domain": False,
                "is_localhost": True,
            },
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_C8_custom_authorized_domain_removed_is_medium(self):
        c = _change(
            record_type="firebase_authorized_domain",
            change_type="removed",
            extra_metadata={
                "domain": "old.example.com",
                "is_default_firebase_domain": False,
                "is_localhost": False,
            },
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_C9_auth_provider_added_is_medium(self):
        c = _change(
            record_type="firebase_auth_provider",
            change_type="added",
            extra_metadata={"provider_id": "google.com"},
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_C10_auth_provider_removed_is_medium(self):
        # Per brief: "OAuth provider added/removed is Medium unless risky
        # details exist." High was too high — bumped to medium.
        c = _change(
            record_type="firebase_auth_provider",
            change_type="removed",
            extra_metadata={"provider_id": "google.com"},
        )
        level, _ = _classify(c)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# D. Firebase Hosting
# ─────────────────────────────────────────────────────────────────────────────

class TestHosting:
    def test_D1_hosting_site_removed_is_high(self):
        c = _change(
            record_type="firebase_hosting_site",
            change_type="removed",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_D2_custom_domain_count_decreased_is_high(self):
        c = _change(
            record_type="firebase_hosting_site",
            field_path="custom_domain_count",
            new_value=1,
            prev_value=2,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_D3_custom_domain_removed_is_high(self):
        c = _change(
            record_type="firebase_hosting_domain",
            change_type="removed",
            extra_metadata={
                "domain": "www.example.com",
                "domain_type": "CUSTOM",
            },
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_D4_custom_domain_added_is_medium(self):
        c = _change(
            record_type="firebase_hosting_domain",
            change_type="added",
            extra_metadata={
                "domain": "www.example.com",
                "domain_type": "CUSTOM",
            },
        )
        level, _ = _classify(c)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# E. Cloud Functions
# ─────────────────────────────────────────────────────────────────────────────

class TestFunctions:
    def test_E1_function_removed_is_medium(self):
        c = _change(
            record_type="firebase_function_metadata",
            change_type="removed",
            extra_metadata={"function_name": "process-payment"},
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_E2_function_runtime_changed_is_medium(self):
        c = _change(
            record_type="firebase_function_metadata",
            field_path="runtime",
            new_value="nodejs20",
            extra_metadata={"function_name": "process-payment"},
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_E3_function_status_failed_is_medium(self):
        c = _change(
            record_type="firebase_function_metadata",
            field_path="status",
            new_value="FAILED",
            extra_metadata={"function_name": "process-payment"},
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_E4_function_env_var_count_changed_is_medium(self):
        c = _change(
            record_type="firebase_function_metadata",
            field_path="env_var_key_count",
            new_value=5,
            prev_value=4,
            extra_metadata={"function_name": "send-receipt"},
        )
        level, _ = _classify(c)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# F. Project metadata
# ─────────────────────────────────────────────────────────────────────────────

class TestProject:
    def test_F1_lifecycle_deleted_is_critical(self):
        c = _change(
            record_type="firebase_project",
            field_path="lifecycle_state",
            new_value="DELETED",
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_F2_display_name_change_is_low(self):
        c = _change(
            record_type="firebase_project",
            field_path="display_name",
            new_value="New Name",
        )
        level, _ = _classify(c)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# G. App Check (security enforcement)
# ─────────────────────────────────────────────────────────────────────────────

class TestAppCheck:
    def test_G1_app_check_removed_is_high(self):
        c = _change(
            record_type="firebase_app_check_config",
            change_type="removed",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_G2_enforced_service_count_decreased_is_high(self):
        c = _change(
            record_type="firebase_app_check_config",
            field_path="enforced_service_count",
            new_value=1,
            prev_value=3,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_G3_unenforced_service_count_increased_is_high(self):
        c = _change(
            record_type="firebase_app_check_config",
            field_path="unenforced_service_count",
            new_value=3,
            prev_value=1,
        )
        level, _ = _classify(c)
        assert level == "high"


# ─────────────────────────────────────────────────────────────────────────────
# H. Unknown subtype safety
# ─────────────────────────────────────────────────────────────────────────────

class TestUnknownSubtype:
    def test_H1_unknown_subtype_falls_back_safely(self):
        c = _change(record_type="firebase_future_feature")
        level, reason = _classify(c)
        assert level == "low"
        assert "firebase" in reason.lower()

    def test_H2_no_crash_on_malformed_metadata(self):
        for bad_pm in (None, "not a dict", 42, []):
            c = MagicMock(name="Change")
            c.field_path        = None
            c.change_type       = "modified"
            c.new_value         = None
            c.prev_value        = None
            c.old_value         = None
            c.provider_metadata = bad_pm
            level, _ = _classify(c)
            assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# I. Safety — no secrets / API keys / service-account JSON in reasons
# ─────────────────────────────────────────────────────────────────────────────

class TestSafetyInvariants:
    @pytest.mark.parametrize("change_args", [
        dict(record_type="firebase_firestore_ruleset",
             field_path="public_write_detected", new_value=True, prev_value=False),
        dict(record_type="firebase_storage_ruleset",
             field_path="public_write_detected", new_value=True, prev_value=False),
        dict(record_type="firebase_auth_config",
             field_path="anonymous_enabled", new_value=True, prev_value=False),
        dict(record_type="firebase_authorized_domain", change_type="added",
             extra_metadata={"domain": "evil.example.com",
                             "is_default_firebase_domain": False,
                             "is_localhost": False}),
        dict(record_type="firebase_storage_bucket",
             field_path="uniform_bucket_level_access", new_value=False, prev_value=True),
        dict(record_type="firebase_app_check_config",
             field_path="enforced_service_count", new_value=1, prev_value=3),
    ])
    def test_I1_reason_does_not_leak_secrets(self, change_args):
        """Reasons must not contain a Google API-key-shaped string, a
        service-account JSON fragment, or an OAuth client secret prefix."""
        c = _change(**change_args)
        _, reason = _classify(c)
        lower = reason.lower()
        # Google API keys are 39-char strings starting with AIza
        assert "aiza" not in lower, f"reason looks like an API key: {reason!r}"
        # Service-account JSON markers
        for marker in (
            '"private_key"', '"private_key_id"', '"client_secret"',
            "begin private key", "begin rsa private key",
            "client_secret_", "gcp_secret_",
        ):
            assert marker not in lower, f"reason contains secret marker: {reason!r}"

    def test_I2_no_auto_fix_language(self):
        cases = [
            dict(record_type="firebase_firestore_ruleset",
                 field_path="public_write_detected", new_value=True, prev_value=False),
            dict(record_type="firebase_storage_ruleset",
                 field_path="public_write_detected", new_value=True, prev_value=False),
            dict(record_type="firebase_auth_config",
                 field_path="anonymous_enabled", new_value=True),
            dict(record_type="firebase_storage_bucket",
                 field_path="uniform_bucket_level_access", new_value=False),
        ]
        bad = ("auto-fix", "automatically fix", "guaranteed", "auto fix")
        for args in cases:
            _, reason = _classify(_change(**args))
            lower = reason.lower()
            for phrase in bad:
                assert phrase not in lower, f"reason contains {phrase!r}: {reason!r}"
