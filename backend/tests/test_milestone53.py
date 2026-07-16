"""M53 test suite: Firebase Provider MVP.

Tests
-----
 1. Schema constants — all 10 FIREBASE_* constants defined and correct.
 2. REQUIRED_SA_FIELDS — tuple has the 5 expected field names.
 3. _sha256_prefix — returns 16-char hex string, deterministic.
 4. _analyze_rules — empty source returns safe defaults.
 5. _analyze_rules — public write pattern detected (critical).
 6. _analyze_rules — public read pattern detected (high).
 7. _analyze_rules — authenticated-only pattern clears public flags.
 8. _analyze_rules — raw source is NEVER present in returned dict.
 9. FirebaseConnector validate_credentials — missing required field raises ValueError.
10. FirebaseConnector validate_credentials — invalid JSON raises ValueError.
11. FirebaseConnector fetch — get_access_token failure raises AuthenticationError.
12. FirebaseConnector fetch — API returns 403 → raises no exception (fail-soft warning).
13. Risk rules — firebase_project added → low.
14. Risk rules — lifecycle_state → DELETED → critical.
15. Risk rules — firebase_auth_config anonymous_sign_in_enabled True → high.
16. Risk rules — firebase_firestore_ruleset public_write_detected True → critical.
17. Risk rules — firebase_storage_ruleset public_read_detected True → high.
18. Risk rules — firebase_hosting_site custom_domain_count decreases → high.
19. Risk rules — firebase_function_metadata runtime changed → medium.
20. risk_service.classify_change — dispatches on firebase_ prefix.
21. diff_service._tracked_fields_for — firebase_ types return non-empty tuple.
22. diff_service._tracked_fields_for — unknown firebase_ subtype returns empty tuple.
23. failure_classifier — firebase credentials_invalid.
24. failure_classifier — firebase permission_denied (403).
25. failure_classifier — firebase project_unavailable (404).
26. failure_classifier — firebase api_unavailable (500).
27. IntegrationCreateRequest schema — firebase provider accepted.
28. IntegrationCreateRequest schema — firebase without SA JSON raises ValidationError.
29. IntegrationReconnectRequest — has firebase_service_account_json field.
30. integration_service.create_integration — dispatches to firebase branch.
31. integration_service.reconnect_credentials_firebase — invalid JSON raises ValueError.
32. sync_service — 'firebase' present in _SUPPORTED_PROVIDERS.

Scope: no real Firebase APIs called; all network requests are mocked.
Does NOT call external Google/Firebase APIs.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_change(
    record_type: str = "firebase_project",
    field_path: str = "",
    change_type: str = "modified",
    prev_value: Any = None,
    new_value: Any = None,
    provider_metadata: dict | None = None,
) -> dict:
    """Return a plain dict that mimics a Change ORM row for risk-rule testing.

    Uses the same field names as the Change ORM model (prev_value / new_value),
    not old_value.  The risk rules read _get(change, "prev_value") so the key
    name must match.
    """
    return {
        "record_type": record_type,
        "field_path": field_path,
        "change_type": change_type,
        "prev_value": prev_value,
        "new_value": new_value,
        "provider_metadata": provider_metadata or {"record_type": record_type},
    }


def _minimal_sa_json(project_id: str = "test-project") -> str:
    """Return a minimal (but structurally valid) service account JSON string."""
    return json.dumps(
        {
            "type": "service_account",
            "project_id": project_id,
            "private_key_id": "key123",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIFake\n-----END RSA PRIVATE KEY-----\n",
            "client_email": f"sa@{project_id}.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Schema constants
# ═══════════════════════════════════════════════════════════════════════════════


class TestFirebaseSchemaConstants:
    """firebase_schema.py — constant names and values."""

    def test_all_ten_record_type_constants_defined(self):
        from app.connectors.firebase_schema import (
            FIREBASE_AUTH_CONFIG,
            FIREBASE_AUTH_PROVIDER,
            FIREBASE_AUTHORIZED_DOMAIN,
            FIREBASE_FIRESTORE_RULESET,
            FIREBASE_FUNCTION_METADATA,
            FIREBASE_HOSTING_DOMAIN,
            FIREBASE_HOSTING_SITE,
            FIREBASE_PROJECT,
            FIREBASE_STORAGE_BUCKET,
            FIREBASE_STORAGE_RULESET,
        )

        assert FIREBASE_PROJECT == "firebase_project"
        assert FIREBASE_AUTH_CONFIG == "firebase_auth_config"
        assert FIREBASE_AUTH_PROVIDER == "firebase_auth_provider"
        assert FIREBASE_AUTHORIZED_DOMAIN == "firebase_authorized_domain"
        assert FIREBASE_FIRESTORE_RULESET == "firebase_firestore_ruleset"
        assert FIREBASE_STORAGE_BUCKET == "firebase_storage_bucket"
        assert FIREBASE_STORAGE_RULESET == "firebase_storage_ruleset"
        assert FIREBASE_HOSTING_SITE == "firebase_hosting_site"
        assert FIREBASE_HOSTING_DOMAIN == "firebase_hosting_domain"
        assert FIREBASE_FUNCTION_METADATA == "firebase_function_metadata"

    def test_required_sa_fields_has_five_entries(self):
        from app.connectors.firebase_schema import REQUIRED_SA_FIELDS

        assert isinstance(REQUIRED_SA_FIELDS, (tuple, list))
        assert len(REQUIRED_SA_FIELDS) == 5
        for field in ("type", "project_id", "private_key_id", "private_key", "client_email"):
            assert field in REQUIRED_SA_FIELDS


# ═══════════════════════════════════════════════════════════════════════════════
# 2. _sha256_prefix helper
# ═══════════════════════════════════════════════════════════════════════════════


class TestSha256Prefix:
    def test_returns_16_hex_chars(self):
        from app.connectors.firebase import _sha256_prefix

        result = _sha256_prefix("my-firebase-project")
        assert len(result) == 16
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic(self):
        from app.connectors.firebase import _sha256_prefix

        val = "projects/12345678/rulesets/abc"
        assert _sha256_prefix(val) == _sha256_prefix(val)

    def test_different_inputs_produce_different_hashes(self):
        from app.connectors.firebase import _sha256_prefix

        assert _sha256_prefix("project-a") != _sha256_prefix("project-b")

    def test_matches_sha256(self):
        from app.connectors.firebase import _sha256_prefix

        raw = "test-value"
        expected = hashlib.sha256(raw.encode()).hexdigest()[:16]
        assert _sha256_prefix(raw) == expected


# ═══════════════════════════════════════════════════════════════════════════════
# 3. _analyze_rules
# ═══════════════════════════════════════════════════════════════════════════════


class TestAnalyzeRules:
    def test_empty_source_returns_safe_defaults(self):
        """Regression note (Firebase change-classification QA pass): an
        unavailable rules source means the public/private posture is
        UNKNOWN, not a confirmed non-public state — this previously asserted
        False (matching a stale connector default that has since been
        corrected to preserve None)."""
        from app.connectors.firebase import _analyze_rules

        result = _analyze_rules("")
        assert result["public_read_detected"] is None
        assert result["public_write_detected"] is None
        assert result["parser_confidence"] == "low"
        assert result["rules_hash"] is None

    def test_public_write_if_true_detected(self):
        from app.connectors.firebase import _analyze_rules

        source = """
        rules_version = '2';
        service cloud.firestore {
          match /databases/{database}/documents {
            match /{document=**} {
              allow write: if true;
            }
          }
        }
        """
        result = _analyze_rules(source)
        assert result["public_write_detected"] is True

    def test_public_read_if_true_detected(self):
        from app.connectors.firebase import _analyze_rules

        source = """
        rules_version = '2';
        service cloud.firestore {
          match /databases/{database}/documents {
            match /{document=**} {
              allow read: if true;
            }
          }
        }
        """
        result = _analyze_rules(source)
        assert result["public_read_detected"] is True
        # write alone should not be marked
        assert result["public_write_detected"] is False

    def test_auth_check_sets_authenticated_only(self):
        from app.connectors.firebase import _analyze_rules

        source = """
        rules_version = '2';
        service cloud.firestore {
          match /databases/{database}/documents {
            match /{document=**} {
              allow read, write: if request.auth != null;
            }
          }
        }
        """
        result = _analyze_rules(source)
        assert result["authenticated_only_detected"] is True
        assert result["public_write_detected"] is False
        assert result["public_read_detected"] is False

    def test_raw_source_not_in_result(self):
        from app.connectors.firebase import _analyze_rules

        source = "allow read: if true;"
        result = _analyze_rules(source)
        # The raw source string itself must NEVER appear as a value in the dict.
        # (Individual words like "allow" may appear in human-readable reason text.)
        for v in result.values():
            assert v != source, f"Raw source string must not be stored in result; got {v!r}"
            if isinstance(v, str):
                # The full raw source (all 21 chars) must not be embedded in any value
                assert source not in v, (
                    f"Raw source string was embedded in result value: {v!r}"
                )

    def test_rules_hash_is_16_hex_chars(self):
        from app.connectors.firebase import _analyze_rules

        result = _analyze_rules("allow read: if true;")
        h = result.get("rules_hash")
        assert h is not None
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)

    def test_parser_confidence_field_present(self):
        from app.connectors.firebase import _analyze_rules

        result = _analyze_rules("allow read: if true;")
        assert "parser_confidence" in result
        assert result["parser_confidence"] in ("low", "medium", "high")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. FirebaseConnector — credential validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestFirebaseConnectorValidation:
    def test_missing_required_field_raises_value_error(self):
        from app.connectors.firebase import FirebaseConnector

        # Missing 'project_id'
        incomplete_sa = json.dumps(
            {
                "type": "service_account",
                "private_key_id": "k",
                "private_key": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n",
                "client_email": "sa@proj.iam.gserviceaccount.com",
            }
        )
        with pytest.raises((ValueError, Exception)):
            FirebaseConnector().validate_credentials(
                {"service_account_json": incomplete_sa}
            )

    def test_invalid_json_raises_error(self):
        from app.connectors.firebase import FirebaseConnector

        with pytest.raises((ValueError, Exception)):
            FirebaseConnector().validate_credentials(
                {"service_account_json": "not valid json {{{"}
            )

    def test_missing_service_account_json_key_raises_error(self):
        from app.connectors.firebase import FirebaseConnector

        with pytest.raises((ValueError, KeyError, Exception)):
            FirebaseConnector().validate_credentials({})


# ═══════════════════════════════════════════════════════════════════════════════
# 5. FirebaseConnector — fetch fail-soft behaviour
# ═══════════════════════════════════════════════════════════════════════════════


class TestFirebaseConnectorFetch:
    """Fetch + validate_credentials with mocked HTTP."""

    def _connector(self):
        from app.connectors.firebase import FirebaseConnector
        return FirebaseConnector()

    def test_get_access_token_failure_raises_authentication_error(self):
        """If the Google token endpoint returns 401, AuthenticationError is raised."""
        import httpx
        from app.connectors.firebase import FirebaseConnector
        from app.connectors.exceptions import AuthenticationError

        sa_json = _minimal_sa_json()
        creds = {"service_account_json": sa_json}

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 401
        mock_response.json.return_value = {"error": "invalid_grant"}
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401", request=MagicMock(), response=mock_response
        )

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            with pytest.raises((AuthenticationError, Exception)):
                FirebaseConnector()._get_access_token(json.loads(sa_json))

    def test_403_on_surface_produces_warning_not_exception(self):
        """A 403 on a non-critical surface should add a warning but not raise."""
        import httpx
        from app.connectors.firebase import FirebaseConnector

        sa_json = _minimal_sa_json()
        creds = {"service_account_json": sa_json}

        # We'll test _fetch_auth_config directly with a mocked _get that returns 403
        connector = FirebaseConnector()
        warnings: list[str] = []

        # Mock the internal _get to simulate 403
        from app.connectors.exceptions import ConnectorError

        def _fake_get(access_token, url, params=None):
            raise ConnectorError("403 Forbidden", status_code=403)

        connector._get = _fake_get

        # Should not raise, should append to warnings
        result = connector._fetch_auth_config("token", "test-project", warnings)
        assert isinstance(result, list)  # returns records (possibly empty)
        # warnings list may have been populated
        assert isinstance(warnings, list)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Firebase risk rules
# ═══════════════════════════════════════════════════════════════════════════════


class TestFirebaseRiskRules:
    """classify_firebase_change — per-record-type risk classification."""

    def test_project_added_is_low(self):
        from app.services.risk_rules.firebase import classify_firebase_change

        change = _make_change("firebase_project", change_type="added")
        level, reason = classify_firebase_change(change)
        assert level == "low"

    def test_project_lifecycle_deleted_is_critical(self):
        from app.services.risk_rules.firebase import classify_firebase_change

        change = _make_change(
            "firebase_project",
            field_path="lifecycle_state",
            change_type="modified",
            prev_value="ACTIVE",
            new_value="DELETE_REQUESTED",
        )
        level, reason = classify_firebase_change(change)
        assert level == "critical"

    def test_auth_config_anonymous_enabled_is_high(self):
        from app.services.risk_rules.firebase import classify_firebase_change

        change = _make_change(
            "firebase_auth_config",
            field_path="anonymous_enabled",  # field name from the auth_config record
            change_type="modified",
            prev_value=False,
            new_value=True,
        )
        level, reason = classify_firebase_change(change)
        assert level == "high"

    def test_auth_config_anonymous_disabled_is_low(self):
        """Disabling anonymous auth is security-strengthening → low."""
        from app.services.risk_rules.firebase import classify_firebase_change

        change = _make_change(
            "firebase_auth_config",
            field_path="anonymous_enabled",
            change_type="modified",
            prev_value=True,
            new_value=False,
        )
        level, reason = classify_firebase_change(change)
        assert level == "low"

    def test_firestore_ruleset_public_write_is_critical(self):
        from app.services.risk_rules.firebase import classify_firebase_change

        change = _make_change(
            "firebase_firestore_ruleset",
            field_path="public_write_detected",
            change_type="modified",
            prev_value=False,
            new_value=True,
        )
        level, reason = classify_firebase_change(change)
        assert level == "critical"
        assert "write" in reason.lower() or "public" in reason.lower()

    def test_storage_ruleset_public_read_is_high(self):
        from app.services.risk_rules.firebase import classify_firebase_change

        change = _make_change(
            "firebase_storage_ruleset",
            field_path="public_read_detected",
            change_type="modified",
            prev_value=False,
            new_value=True,
        )
        level, reason = classify_firebase_change(change)
        assert level in ("high", "critical")

    def test_storage_bucket_ubla_disabled_is_high(self):
        """Disabling uniform_bucket_level_access is a security downgrade → high."""
        from app.services.risk_rules.firebase import classify_firebase_change

        change = _make_change(
            "firebase_storage_bucket",
            field_path="uniform_bucket_level_access",
            change_type="modified",
            prev_value=True,
            new_value=False,
        )
        level, reason = classify_firebase_change(change)
        assert level == "high"

    def test_storage_bucket_ubla_enabled_is_low(self):
        """Enabling uniform_bucket_level_access is a security improvement → low."""
        from app.services.risk_rules.firebase import classify_firebase_change

        change = _make_change(
            "firebase_storage_bucket",
            field_path="uniform_bucket_level_access",
            change_type="modified",
            prev_value=False,
            new_value=True,
        )
        level, reason = classify_firebase_change(change)
        assert level == "low"

    def test_hosting_site_custom_domain_count_decreased_is_high(self):
        """Decreasing custom_domain_count → high (production domain may have been removed)."""
        from app.services.risk_rules.firebase import classify_firebase_change

        change = _make_change(
            "firebase_hosting_site",
            field_path="custom_domain_count",  # must match risk rule: fp == "custom_domain_count"
            change_type="modified",
            prev_value=3,
            new_value=2,
        )
        level, reason = classify_firebase_change(change)
        assert level == "high", f"Expected high for domain count decrease, got {level!r}"

    def test_function_runtime_changed_is_medium(self):
        from app.services.risk_rules.firebase import classify_firebase_change

        change = _make_change(
            "firebase_function_metadata",
            field_path="runtime",
            change_type="modified",
            prev_value="nodejs16",
            new_value="nodejs20",
        )
        level, reason = classify_firebase_change(change)
        assert level in ("medium", "low")

    def test_unknown_firebase_type_returns_low(self):
        """Unknown firebase_ subtype should degrade gracefully to low or medium."""
        from app.services.risk_rules.firebase import classify_firebase_change

        change = _make_change(
            "firebase_unknown_future_record",
            change_type="modified",
        )
        level, reason = classify_firebase_change(change)
        assert level in ("low", "medium", "high")  # must not crash

    def test_reason_never_asserts_breach(self):
        """Risk reason strings must use may/could language, not assert a breach."""
        from app.services.risk_rules.firebase import classify_firebase_change

        FORBIDDEN = ("was leaked", "was breached", "is compromised", "data exposed")
        record_types = [
            "firebase_project",
            "firebase_auth_config",
            "firebase_firestore_ruleset",
            "firebase_storage_bucket",
        ]
        for rt in record_types:
            change = _make_change(rt, field_path="dummy", change_type="modified")
            _, reason = classify_firebase_change(change)
            reason_lower = reason.lower()
            for bad in FORBIDDEN:
                assert bad not in reason_lower, (
                    f"risk_reason for {rt} contains forbidden phrase {bad!r}: {reason!r}"
                )


# ═══════════════════════════════════════════════════════════════════════════════
# 7. risk_service dispatch
# ═══════════════════════════════════════════════════════════════════════════════


class TestRiskServiceDispatch:
    def test_firebase_prefix_dispatches_to_firebase_rules(self):
        from app.services.risk_service import classify_change

        change = _make_change("firebase_project", change_type="added")
        level, reason = classify_change(change)
        assert isinstance(level, str)
        assert level in ("low", "medium", "high", "critical")
        assert isinstance(reason, str)

    def test_non_firebase_prefix_uses_cloudflare_dns_fallback(self):
        """A plain record type (no provider prefix) uses Cloudflare DNS rules."""
        from app.services.risk_service import classify_change

        change = _make_change(
            "A",
            field_path="content",
            change_type="modified",
            provider_metadata={"record_type": "A"},
        )
        level, _ = classify_change(change)
        assert level in ("low", "medium", "high", "critical")

    def test_firebase_sub_types_all_return_valid_level(self):
        """Every known firebase_ sub-type should classify without crashing."""
        from app.connectors.firebase_schema import (
            FIREBASE_AUTH_CONFIG,
            FIREBASE_AUTH_PROVIDER,
            FIREBASE_AUTHORIZED_DOMAIN,
            FIREBASE_FIRESTORE_RULESET,
            FIREBASE_FUNCTION_METADATA,
            FIREBASE_HOSTING_DOMAIN,
            FIREBASE_HOSTING_SITE,
            FIREBASE_PROJECT,
            FIREBASE_STORAGE_BUCKET,
            FIREBASE_STORAGE_RULESET,
        )
        from app.services.risk_service import classify_change

        valid_levels = {"low", "medium", "high", "critical"}
        for rt in [
            FIREBASE_PROJECT,
            FIREBASE_AUTH_CONFIG,
            FIREBASE_AUTH_PROVIDER,
            FIREBASE_AUTHORIZED_DOMAIN,
            FIREBASE_FIRESTORE_RULESET,
            FIREBASE_STORAGE_BUCKET,
            FIREBASE_STORAGE_RULESET,
            FIREBASE_HOSTING_SITE,
            FIREBASE_HOSTING_DOMAIN,
            FIREBASE_FUNCTION_METADATA,
        ]:
            change = _make_change(rt, change_type="modified")
            level, reason = classify_change(change)
            assert level in valid_levels, f"Invalid level {level!r} for {rt}"
            assert isinstance(reason, str) and len(reason) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# 8. diff_service tracked fields
# ═══════════════════════════════════════════════════════════════════════════════


class TestDiffServiceTrackedFields:
    def test_firebase_project_returns_non_empty_tuple(self):
        from app.services.diff_service import _tracked_fields_for

        result = _tracked_fields_for({"record_type": "firebase_project"})
        assert isinstance(result, tuple)
        assert len(result) > 0

    def test_firebase_firestore_ruleset_includes_public_write_detected(self):
        from app.services.diff_service import _tracked_fields_for

        fields = _tracked_fields_for({"record_type": "firebase_firestore_ruleset"})
        assert "public_write_detected" in fields

    def test_firebase_storage_bucket_includes_uniform_bucket_level_access(self):
        from app.services.diff_service import _tracked_fields_for

        fields = _tracked_fields_for({"record_type": "firebase_storage_bucket"})
        assert "uniform_bucket_level_access" in fields

    def test_firebase_auth_config_includes_anonymous_enabled(self):
        from app.services.diff_service import _tracked_fields_for

        fields = _tracked_fields_for({"record_type": "firebase_auth_config"})
        assert "anonymous_enabled" in fields

    def test_all_ten_firebase_types_tracked(self):
        from app.services.diff_service import _tracked_fields_for

        types = [
            "firebase_project",
            "firebase_auth_config",
            "firebase_auth_provider",
            "firebase_authorized_domain",
            "firebase_firestore_ruleset",
            "firebase_storage_bucket",
            "firebase_storage_ruleset",
            "firebase_hosting_site",
            "firebase_hosting_domain",
            "firebase_function_metadata",
        ]
        for rt in types:
            fields = _tracked_fields_for({"record_type": rt})
            assert isinstance(fields, tuple), f"{rt} returned {type(fields)}"
            assert len(fields) > 0, f"{rt} returned empty tuple"

    def test_unknown_firebase_subtype_returns_empty_tuple(self):
        from app.services.diff_service import _tracked_fields_for

        result = _tracked_fields_for({"record_type": "firebase_does_not_exist"})
        assert isinstance(result, tuple)
        assert len(result) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# 9. failure_classifier
# ═══════════════════════════════════════════════════════════════════════════════


class TestFailureClassifier:
    """failure_classifier handles firebase errors correctly."""

    def test_firebase_credentials_invalid(self):
        from app.connectors.exceptions import AuthenticationError
        from app.core.failure_classifier import classify_failure

        exc = AuthenticationError("Invalid grant: account not found")
        result = classify_failure(exc, provider="firebase")
        assert result is not None
        assert result.error_code == "firebase_credentials_invalid"

    def test_firebase_permission_denied(self):
        from app.connectors.exceptions import ConnectorError
        from app.core.failure_classifier import classify_failure

        exc = ConnectorError("403 Forbidden", status_code=403)
        result = classify_failure(exc, provider="firebase")
        assert result is not None
        assert result.error_code == "firebase_permission_denied"

    def test_firebase_project_unavailable(self):
        from app.connectors.exceptions import ConnectorError
        from app.core.failure_classifier import classify_failure

        exc = ConnectorError("404 Not Found", status_code=404)
        result = classify_failure(exc, provider="firebase")
        assert result is not None
        assert result.error_code == "firebase_project_unavailable"

    def test_firebase_api_unavailable(self):
        from app.connectors.exceptions import ConnectorError
        from app.core.failure_classifier import classify_failure

        exc = ConnectorError("500 Internal Server Error", status_code=500)
        result = classify_failure(exc, provider="firebase")
        assert result is not None
        assert result.error_code == "firebase_api_unavailable"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Schema validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestIntegrationSchemas:
    def test_firebase_provider_accepted_in_create_request(self):
        from app.schemas.integration import IntegrationCreateRequest

        req = IntegrationCreateRequest(
            provider="firebase",
            display_name="My Firebase",
            firebase_service_account_json=_minimal_sa_json(),
        )
        assert req.provider == "firebase"
        assert req.firebase_service_account_json is not None

    def test_firebase_missing_sa_json_raises_validation_error(self):
        from pydantic import ValidationError

        from app.schemas.integration import IntegrationCreateRequest

        with pytest.raises(ValidationError) as exc_info:
            IntegrationCreateRequest(
                provider="firebase",
                display_name="My Firebase",
                # firebase_service_account_json intentionally omitted
            )
        errors_str = str(exc_info.value)
        assert "firebase_service_account_json" in errors_str or "required" in errors_str.lower()

    def test_reconnect_request_has_firebase_sa_json_field(self):
        from app.schemas.integration import IntegrationReconnectRequest

        req = IntegrationReconnectRequest(
            firebase_service_account_json=_minimal_sa_json(),
        )
        assert req.firebase_service_account_json is not None

    def test_provider_literal_includes_firebase(self):
        """provider field accepts 'firebase' as a literal value."""
        from app.schemas.integration import IntegrationCreateRequest
        import typing

        hints = IntegrationCreateRequest.model_fields["provider"]
        # The annotation should include 'firebase'
        # We test this implicitly: constructing with "firebase" must not raise.
        req = IntegrationCreateRequest(
            provider="firebase",
            display_name="Test",
            firebase_service_account_json=_minimal_sa_json(),
        )
        assert req.provider == "firebase"


# ═══════════════════════════════════════════════════════════════════════════════
# 11. integration_service dispatch
# ═══════════════════════════════════════════════════════════════════════════════


class TestIntegrationServiceDispatch:
    """create_integration dispatches to firebase branch."""

    def test_firebase_branch_called(self):
        """create_integration with provider='firebase' calls create_firebase_integration."""
        from app.services import integration_service

        mock_db = MagicMock()
        user_id = uuid.uuid4()
        workspace_id = uuid.uuid4()
        sa_json = _minimal_sa_json("dispatch-test")
        creds = {"service_account_json": sa_json}

        with patch.object(
            integration_service, "create_firebase_integration"
        ) as mock_fn:
            mock_fn.return_value = MagicMock()
            integration_service.create_integration(
                user_id=user_id,
                provider="firebase",
                display_name="Test Firebase",
                credentials=creds,
                workspace_id=workspace_id,
                db=mock_db,
            )
            mock_fn.assert_called_once()

    def test_unsupported_provider_still_raises_value_error(self):
        from app.services import integration_service

        mock_db = MagicMock()
        with pytest.raises(ValueError, match="Unsupported provider"):
            integration_service.create_integration(
                user_id=uuid.uuid4(),
                provider="unknown_provider_xyz",
                display_name="Test",
                credentials={},
                db=mock_db,
            )

    def test_firebase_in_supported_provider_error_message(self):
        """Error message for unsupported providers includes 'firebase'."""
        from app.services import integration_service

        mock_db = MagicMock()
        try:
            integration_service.create_integration(
                user_id=uuid.uuid4(),
                provider="bogus",
                display_name="Test",
                credentials={},
                db=mock_db,
            )
        except ValueError as exc:
            assert "firebase" in str(exc).lower()


# ═══════════════════════════════════════════════════════════════════════════════
# 12. reconnect_credentials_firebase
# ═══════════════════════════════════════════════════════════════════════════════


class TestReconnectFirebase:
    def test_invalid_json_raises_value_error(self):
        from app.services.integration_service import reconnect_credentials_firebase

        mock_db = MagicMock()

        # _get_integration_by_id needs to return something
        with patch(
            "app.services.integration_service.get_integration_by_id"
        ) as mock_get:
            mock_integration = MagicMock()
            mock_integration.status = "error"
            mock_get.return_value = mock_integration

            with pytest.raises(ValueError, match="not valid JSON"):
                reconnect_credentials_firebase(
                    integration_id=uuid.uuid4(),
                    user_id=uuid.uuid4(),
                    new_service_account_json="not{{{valid json",
                    db=mock_db,
                )

    def test_not_found_raises_lookup_error(self):
        from app.services.integration_service import reconnect_credentials_firebase

        mock_db = MagicMock()

        with patch(
            "app.services.integration_service.get_integration_by_id",
            return_value=None,
        ):
            with pytest.raises(LookupError):
                reconnect_credentials_firebase(
                    integration_id=uuid.uuid4(),
                    user_id=uuid.uuid4(),
                    new_service_account_json=_minimal_sa_json(),
                    db=mock_db,
                )


# ═══════════════════════════════════════════════════════════════════════════════
# 13. sync_service supported providers
# ═══════════════════════════════════════════════════════════════════════════════


class TestSyncServiceSupportedProviders:
    def test_firebase_in_supported_providers(self):
        """The scheduling function must include firebase in its provider filter."""
        import inspect

        from app.services import sync_service

        # Read the source of create_scheduled_syncs_for_active_integrations to
        # find the _SUPPORTED_PROVIDERS tuple defined inside the function.
        source = inspect.getsource(
            sync_service.create_scheduled_syncs_for_active_integrations
        )
        assert "firebase" in source, (
            "'firebase' not found in create_scheduled_syncs_for_active_integrations source"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 14. Security invariants
# ═══════════════════════════════════════════════════════════════════════════════


class TestCredentialSecurityInvariants:
    """Prove the private_key is never exposed in errors, logs, or API responses."""

    def test_private_key_not_in_validation_error_message(self):
        """ValueError for a missing field must not echo back any credential values."""
        from app.connectors.firebase import FirebaseConnector

        fake_private_key = "-----BEGIN RSA PRIVATE KEY-----\nTOPSECRETFAKE\n-----END RSA PRIVATE KEY-----\n"
        bad_creds = json.dumps(
            {
                "type": "service_account",
                # private_key_id intentionally missing → should raise ValueError
                "project_id": "test-project",
                "private_key": fake_private_key,
                "client_email": "sa@test.iam.gserviceaccount.com",
            }
        )
        with pytest.raises((ValueError, Exception)) as exc_info:
            FirebaseConnector().validate_credentials({"service_account_json": bad_creds})

        error_str = str(exc_info.value)
        # The private_key content must NEVER appear in the error message.
        assert fake_private_key not in error_str
        assert "TOPSECRETFAKE" not in error_str

    def test_wrong_type_field_error_does_not_expose_private_key(self):
        """Wrong 'type' field error message must not contain the private key."""
        from app.connectors.firebase import FirebaseConnector

        fake_private_key = "-----BEGIN RSA PRIVATE KEY-----\nSECRETKEYDATA\n-----END RSA PRIVATE KEY-----\n"
        bad_creds = json.dumps(
            {
                "type": "user",  # wrong type
                "project_id": "proj",
                "private_key_id": "k1",
                "private_key": fake_private_key,
                "client_email": "sa@proj.iam.gserviceaccount.com",
            }
        )
        with pytest.raises(ValueError) as exc_info:
            FirebaseConnector().validate_credentials({"service_account_json": bad_creds})

        error_str = str(exc_info.value)
        assert fake_private_key not in error_str
        assert "SECRETKEYDATA" not in error_str

    def test_invalid_json_error_does_not_expose_content(self):
        """JSON parse error for malformed SA JSON must not echo back any content."""
        from app.connectors.firebase import FirebaseConnector

        mangled_json = '{"type": "service_account", "private_key": "SECRET_KEY_HERE", invalid}'
        with pytest.raises((ValueError, Exception)) as exc_info:
            FirebaseConnector().validate_credentials({"service_account_json": mangled_json})

        # The raw credential content must not be in the error message.
        error_str = str(exc_info.value)
        assert "SECRET_KEY_HERE" not in error_str


class TestRulesAnalysisSecurityPolicy:
    """Prove the rules parser does not over-classify or under-classify."""

    def test_authenticated_only_firestore_rules_not_public(self):
        """Rules that require request.auth != null must NOT be classified as public."""
        from app.connectors.firebase import _analyze_rules

        source = """
        rules_version = '2';
        service cloud.firestore {
          match /databases/{database}/documents {
            match /{document=**} {
              allow read, write: if request.auth != null;
            }
          }
        }
        """
        result = _analyze_rules(source)
        assert result["public_read_detected"] is False, (
            "Authenticated-only rules must not be classified as public read"
        )
        assert result["public_write_detected"] is False, (
            "Authenticated-only rules must not be classified as public write"
        )
        assert result["authenticated_only_detected"] is True

    def test_authenticated_only_storage_rules_not_public(self):
        """Storage rules that require auth must NOT be classified as public."""
        from app.connectors.firebase import _analyze_rules

        source = """
        rules_version = '2';
        service firebase.storage {
          match /b/{bucket}/o {
            match /{allPaths=**} {
              allow read, write: if request.auth.uid != null;
            }
          }
        }
        """
        result = _analyze_rules(source)
        assert result["public_read_detected"] is False
        assert result["public_write_detected"] is False

    def test_uid_check_rules_not_public(self):
        """request.auth.uid check should mark as authenticated-only, not public."""
        from app.connectors.firebase import _analyze_rules

        source = """
        rules_version = '2';
        service cloud.firestore {
          match /databases/{database}/documents {
            match /users/{userId} {
              allow read, write: if request.auth.uid == userId;
            }
          }
        }
        """
        result = _analyze_rules(source)
        assert result["public_read_detected"] is False
        assert result["public_write_detected"] is False
        assert result["authenticated_only_detected"] is True

    def test_uncertain_rules_do_not_produce_critical(self):
        """Rules that match no known pattern should not produce Critical classification."""
        from app.connectors.firebase import _analyze_rules
        from app.services.risk_rules.firebase import classify_firebase_change

        # Unusual/complex rules that might not match our simple regex patterns.
        source = """
        rules_version = '2';
        service cloud.firestore {
          match /databases/{database}/documents {
            function isAdmin() { return get(/databases/$(database)/documents/admins/$(request.auth.uid)).data.isAdmin == true; }
            match /{document=**} {
              allow read: if isAdmin();
              allow write: if isAdmin();
            }
          }
        }
        """
        result = _analyze_rules(source)
        # Complex rules: should not detect public access
        assert result["public_read_detected"] is False
        assert result["public_write_detected"] is False

        # Create a change with these analysis results and verify not Critical
        change = _make_change(
            "firebase_firestore_ruleset",
            field_path="rules_hash",
            change_type="modified",
            prev_value="abc123",
            new_value="def456",
        )
        level, reason = classify_firebase_change(change)
        assert level != "critical", (
            f"Uncertain rules_hash change must not produce Critical, got {level!r}"
        )

    def test_no_cond_write_semicolon_detected(self):
        """Older Firebase Rules syntax 'allow write;' (no condition) is public write."""
        from app.connectors.firebase import _analyze_rules

        source = """
        service cloud.firestore {
          match /databases/{database}/documents {
            match /{document=**} {
              allow write;
            }
          }
        }
        """
        result = _analyze_rules(source)
        assert result["public_write_detected"] is True

    def test_commented_out_public_rule_not_detected(self):
        """A commented-out 'allow write: if true' must NOT be flagged."""
        from app.connectors.firebase import _analyze_rules

        source = """
        rules_version = '2';
        service cloud.firestore {
          match /databases/{database}/documents {
            match /{document=**} {
              // allow write: if true;   // DANGER: don't uncomment
              allow write: if request.auth != null;
            }
          }
        }
        """
        result = _analyze_rules(source)
        # The commented line must not cause a public write detection.
        assert result["public_write_detected"] is False, (
            "Commented-out public write rule must not be flagged"
        )


class TestFailureClassifierRecommendations:
    """Failure classifier recommendations must ask for read-only metadata roles only."""

    def test_credentials_invalid_recommendation_no_data_access(self):
        """Recommended action for credentials_invalid must not mention data read/write."""
        from app.connectors.exceptions import AuthenticationError
        from app.core.failure_classifier import classify_failure

        exc = AuthenticationError("bad key")
        result = classify_failure(exc, provider="firebase")

        action = result.recommended_action.lower()
        # Must not suggest data read/write permissions
        assert "firestore" not in action or "read" not in action, (
            "Recommended action must not ask for Firestore read access"
        )
        assert "storage.objects" not in action, (
            "Recommended action must not ask for storage object access"
        )
        # Must mention metadata/config roles are sufficient
        assert "metadata" in action or "read-only" in action or "viewer" in action, (
            f"Recommended action should reference metadata/read-only roles: {action!r}"
        )

    def test_permission_denied_recommendation_no_data_access(self):
        """403 recommended action must not ask for data read/write permissions."""
        from app.connectors.exceptions import ConnectorError
        from app.core.failure_classifier import classify_failure

        exc = ConnectorError("403", status_code=403)
        result = classify_failure(exc, provider="firebase")

        action = result.recommended_action.lower()
        assert "storage.objectviewer" not in action, (
            "Recommended action must not suggest storage.objectViewer (grants object reads)"
        )
        assert "metadata" in action or "viewer" in action or "read-only" in action

    def test_firebase_permission_denied_error_code(self):
        from app.connectors.exceptions import ConnectorError
        from app.core.failure_classifier import classify_failure

        result = classify_failure(ConnectorError("403", status_code=403), provider="firebase")
        assert result.error_code == "firebase_permission_denied"

    def test_firebase_project_unavailable_error_code(self):
        from app.connectors.exceptions import ConnectorError
        from app.core.failure_classifier import classify_failure

        result = classify_failure(ConnectorError("404", status_code=404), provider="firebase")
        assert result.error_code == "firebase_project_unavailable"


class TestNoForbiddenApiReferences:
    """Confirm the connector source does not reference forbidden Firebase APIs."""

    def test_connector_does_not_reference_firestore_documents_api(self):
        """Firestore document read/list/query APIs must not appear in the connector."""
        import inspect
        from app.connectors.firebase import FirebaseConnector

        source = inspect.getsource(FirebaseConnector)
        # Firestore documents API
        assert "firestore.googleapis.com" not in source, (
            "Connector must not call firestore.googleapis.com document APIs"
        )
        assert "/documents/" not in source, (
            "Connector must not reference Firestore document paths"
        )

    def test_connector_does_not_reference_storage_objects_api(self):
        """Storage object list/read/download APIs must not appear in the connector."""
        import inspect
        from app.connectors.firebase import FirebaseConnector

        source = inspect.getsource(FirebaseConnector)
        # Storage objects endpoint /b/{bucket}/o is never called
        assert "/b/{" not in source or "/b/{bucket}" not in source or "/o/" not in source, (
            "Connector must not reference Storage object list/read paths"
        )

    def test_connector_does_not_call_auth_user_export(self):
        """The connector must not construct or call Firebase Auth user export URLs.

        The docstrings mention these endpoints as explicitly forbidden — that's fine.
        The actual URL string constructions (f-strings / variable assignments) must
        not include the user export paths.
        """
        import inspect
        from app.connectors.firebase import FirebaseConnector

        source = inspect.getsource(FirebaseConnector)

        # Filter to lines that are code (not comments/docstrings): look for lines
        # that assign a URL string or construct a URL with the forbidden path.
        # We look for f-string or string literal assignments that contain the path.
        import re

        # Actual URL construction lines (non-comment, non-docstring): must not contain
        # accounts:query or accounts:lookup as callable paths
        code_lines = [
            line for line in source.split("\n")
            if "accounts:query" in line or "accounts:lookup" in line
        ]
        for line in code_lines:
            stripped = line.strip()
            # Allow mentions in comments (#...) or docstring continuation lines
            # that start with typical docstring markers
            is_comment = stripped.startswith("#")
            is_doc_line = stripped.startswith(("- ", "* ", "/", '"', "'", "NEVER", "The endpoint"))
            assert is_comment or is_doc_line, (
                f"Connector appears to construct auth user export URL: {line!r}"
            )

    def test_connector_does_not_reference_secret_manager(self):
        """Secret Manager APIs must not appear in the connector."""
        import inspect
        from app.connectors.firebase import FirebaseConnector

        source = inspect.getsource(FirebaseConnector)
        assert "secretmanager" not in source.lower(), (
            "Connector must not reference Secret Manager APIs"
        )
        assert "secretversions" not in source.lower(), (
            "Connector must not reference Secret Manager version API"
        )

    def test_connector_module_does_not_call_data_write_apis(self):
        """The connector must not call Firebase/GCS data write or mutate APIs.

        httpx.post IS present for two legitimate, read-only reasons:
        1. The OAuth2 token exchange (adjacent to ``token_uri``).
        2. Cloud Logging's ``entries:list`` API (M72B activity ingestion) —
           Google's documented convention for this read-only query endpoint
           uses POST because filter expressions can exceed URL length
           limits; it lists/reads log entries, it does not write or mutate
           anything.
        httpx.patch, httpx.put, httpx.delete must not appear (data mutating).

        Regression note: this assertion previously required *exactly* one
        httpx.post call and was already failing before this Firebase
        detection-QA pass, for a reason unrelated to this pass's fixes (the
        assertion was stale relative to the M72B Cloud Logging addition).
        Corrected here rather than left broken.
        """
        import inspect
        import app.connectors.firebase as _fb_module

        full_source = inspect.getsource(_fb_module)

        # Data-mutating HTTP methods must not be present.
        assert "httpx.patch" not in full_source, "Connector must not use httpx.patch"
        assert "httpx.put" not in full_source, "Connector must not use httpx.put"
        assert "httpx.delete" not in full_source, "Connector must not use httpx.delete"

        # httpx.post is allowed only for the OAuth2 token exchange and the
        # read-only Cloud Logging entries:list call — never a data-mutating
        # Firebase/GCS API.
        post_count = full_source.count("httpx.post")
        assert post_count == 2, (
            f"Expected exactly two httpx.post calls (OAuth2 token + Cloud "
            f"Logging entries:list), found {post_count}"
        )
        # The first call must be adjacent to the token_uri variable.
        first_post_idx = full_source.index("httpx.post")
        first_post_context = full_source[first_post_idx : first_post_idx + 200]
        assert "token_uri" in first_post_context, (
            "The first httpx.post call must be for the OAuth2 token endpoint (token_uri)"
        )
        # The second call must be the Cloud Logging entries:list read API.
        second_post_idx = full_source.index("httpx.post", first_post_idx + 1)
        assert "entries:list" in full_source[:second_post_idx][-500:], (
            "The second httpx.post call must be for the read-only Cloud "
            "Logging entries:list endpoint"
        )

        # Firestore document API appears in the module docstring as a "NEVER made" listing.
        # Verify it is NOT referenced as an actual URL construction in non-comment lines.
        for line in full_source.split("\n"):
            stripped = line.strip()
            if "firestore.googleapis.com" in stripped:
                # Allow it only in comments or docstring context lines
                is_comment = stripped.startswith(("#", "-", "*", "/"))
                is_doc_starter = stripped.startswith(('"""', "'''", '"', "'"))
                assert is_comment or is_doc_starter, (
                    f"firestore.googleapis.com must only appear in comments/docstrings: {line!r}"
                )
