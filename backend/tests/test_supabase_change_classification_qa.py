"""Supabase change-classification QA regression coverage (message-2 pass).

This file covers bugs found while auditing classification correctness for
every currently emitted and tracked Supabase field, building on the
detection-QA pass (test_supabase_detection_qa.py):

  1. A coordinated unknown-Boolean problem across the connector and
     classifiers: several connector fields coerced missing/unrecognised API
     values to `False` (or, for redirect-URL/env-var counts, to `0`) via
     `bool(data.get(x, False))`/`.get(x) or []`, while several classifier
     branches used an unconditional `if new_v is False: <risky>; else:
     <assumes restored>` pattern with no explicit `None` case. Fixing only
     one side would have produced an inconsistent half-fix (e.g. making the
     connector preserve `None` while the classifier's `else` branch still
     claimed "restored" for that same `None`Reserve). Both sides are fixed
     together here:
       - `app/connectors/supabase.py` gained `_bool_or_none()` and
         `_count_or_none()` helpers, applied to every Boolean/count field
         that is not guaranteed present on every API response:
         `email_enabled`, `phone_enabled`, `anonymous_enabled`,
         `mfa_totp_enabled`, `leaked_password_protection_enabled`,
         `captcha_enabled`, `require_reauthentication_for_password_update`,
         `refresh_token_rotation_enabled`, `additional_redirect_urls_count`,
         OAuth provider `enabled`, `s3_protocol_enabled`, Edge Function
         `verify_jwt` and `env_var_key_count`, and RLS `rls_enabled`/
         `rls_forced`.
       - `app/services/risk_rules/supabase.py` gained an explicit `None`
         branch for every one of those fields' classifier logic, using
         cautious "could not be determined" copy rather than claiming an
         explicit enabled/disabled/restored state.
  2. `_fetch_network_restrictions()` also conflated "the API response is
     missing the `allowed_ranges` key entirely" (malformed/unexpected
     shape) with "the key is present and explicitly an empty list"
     (Supabase's own documented "no restrictions" signal) — both produced
     an `is_unrestricted=True` record. Fixed to treat a missing key as
     unknown (skip emitting a record) rather than asserting unrestricted.
  3. `_classify_rls_status_change`'s "added" branch checked `if not new_v:`
     against the WHOLE new-record dict (for an "added" Change, `new_value`
     is the full new record) — a populated dict is always truthy, so this
     never actually distinguished a table added WITHOUT RLS from one added
     WITH RLS. Every newly added table was silently misclassified as
     "added with RLS enabled" regardless of its real posture. Fixed to
     inspect `new_value.get("rls_enabled")` directly.
  4. `_classify_network_restriction_change`'s "added" branch checked
     `new_v is True` (again comparing a dict identity against the literal
     `True`, always False) and `fp == "is_unrestricted"` (field_path is
     always empty for whole-record add/remove events) — so the single most
     critical network-restriction scenario (all restrictions removed,
     surfaced as the "unrestricted" sentinel record being newly "added")
     NEVER fired the intended "critical" branch, instead falling through to
     a "low" bucket with backwards copy claiming access was "now limited"
     when it was actually now unrestricted. Fixed to inspect
     `new_value.get("is_unrestricted")` directly.

These tests exercise the REAL compute_diff() -> classify_supabase_change()
pipeline (not hand-built mocks) wherever practical, and the real connector
fetch methods for the normalization fixes.
"""

from __future__ import annotations

from unittest.mock import patch

from app.connectors.exceptions import ConnectorError
from app.connectors.supabase import SupabaseConnector, _bool_or_none, _count_or_none
from app.services.diff_service import compute_diff
from app.services.risk_rules.supabase import classify_supabase_change
from app.services.security_finding_evaluator import evaluate_record


class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]):
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


def _change(**kwargs) -> dict:
    base = {
        "change_type": "modified",
        "field_path": None,
        "prev_value": None,
        "new_value": None,
        "provider_metadata": {},
    }
    base.update(kwargs)
    return base


class TestConnectorHelpers:
    def test_bool_or_none_true(self):
        assert _bool_or_none(True) is True

    def test_bool_or_none_false(self):
        assert _bool_or_none(False) is False

    def test_bool_or_none_missing_stays_unknown(self):
        assert _bool_or_none(None) is None

    def test_bool_or_none_malformed_stays_unknown(self):
        assert _bool_or_none("maybe") is None
        assert _bool_or_none({}) is None
        assert _bool_or_none(42) is None

    def test_count_or_none_real_list(self):
        assert _count_or_none(["a", "b"]) == 2
        assert _count_or_none([]) == 0

    def test_count_or_none_missing_stays_unknown(self):
        assert _count_or_none(None) is None
        assert _count_or_none("not-a-list") is None


class TestConnectorAuthConfigNormalization:
    """Missing/unrecognised Boolean fields from the Management API must
    stay unknown (None), never silently become False, and permission
    failure must not fabricate a False either."""

    def _fetch(self, connector, get_return):
        with patch.object(connector, "_get", return_value=get_return):
            return connector._fetch_auth_config("tok", "proj1")

    def test_explicit_true_stays_true(self):
        connector = SupabaseConnector()
        record, _ = self._fetch(connector, {"anonymous_enabled": True})
        assert record["anonymous_enabled"] is True

    def test_explicit_false_stays_false(self):
        connector = SupabaseConnector()
        record, _ = self._fetch(connector, {"anonymous_enabled": False})
        assert record["anonymous_enabled"] is False

    def test_missing_field_stays_unknown_not_false(self):
        connector = SupabaseConnector()
        record, _ = self._fetch(connector, {})
        assert record["anonymous_enabled"] is None
        assert record["email_enabled"] is None
        assert record["phone_enabled"] is None
        assert record["mfa_totp_enabled"] is None
        assert record["leaked_password_protection_enabled"] is None
        assert record["captcha_enabled"] is None
        assert record["require_reauthentication_for_password_update"] is None
        assert record["refresh_token_rotation_enabled"] is None

    def test_permission_denied_does_not_fabricate_false(self):
        connector = SupabaseConnector()
        with patch.object(
            connector, "_get",
            side_effect=ConnectorError("403", status_code=403),
        ):
            record, oauth_records = connector._fetch_auth_config("tok", "proj1")
        # The 403 branch returns only config_fetch_warnings + record identity
        # — it must not claim any boolean field is explicitly False.
        assert "anonymous_enabled" not in record or record.get("anonymous_enabled") is None
        assert oauth_records == []
        assert record["config_fetch_warnings"]

    def test_missing_redirect_urls_count_stays_unknown_not_zero(self):
        connector = SupabaseConnector()
        record, _ = self._fetch(connector, {})
        assert record["additional_redirect_urls_count"] is None

    def test_explicit_empty_redirect_urls_is_zero_not_unknown(self):
        connector = SupabaseConnector()
        record, _ = self._fetch(connector, {"additional_redirect_urls": []})
        assert record["additional_redirect_urls_count"] == 0

    def test_oauth_provider_enabled_missing_stays_unknown(self):
        connector = SupabaseConnector()
        _, oauth_records = self._fetch(
            connector, {"external": {"google": {"client_id": "abc"}}},
        )
        assert len(oauth_records) == 1
        assert oauth_records[0]["enabled"] is None


class TestConnectorRlsNormalization:
    def test_rls_enabled_missing_stays_unknown(self):
        connector = SupabaseConnector()
        with patch.object(connector, "_get", return_value=[{"name": "orders", "schema": "public"}]):
            records = connector._fetch_rls_status("tok", "proj1")
        assert records[0]["rls_enabled"] is None
        assert records[0]["rls_forced"] is None

    def test_rls_enabled_explicit_false_stays_false(self):
        connector = SupabaseConnector()
        with patch.object(
            connector, "_get",
            return_value=[{"name": "orders", "schema": "public", "rls_enabled": False}],
        ):
            records = connector._fetch_rls_status("tok", "proj1")
        assert records[0]["rls_enabled"] is False

    def test_rls_enabled_explicit_true_stays_true(self):
        connector = SupabaseConnector()
        with patch.object(
            connector, "_get",
            return_value=[{"name": "orders", "schema": "public", "rls_enabled": True}],
        ):
            records = connector._fetch_rls_status("tok", "proj1")
        assert records[0]["rls_enabled"] is True


class TestConnectorNetworkRestrictionNormalization:
    def test_missing_allowed_ranges_key_does_not_fabricate_unrestricted(self):
        connector = SupabaseConnector()
        with patch.object(connector, "_get", return_value={}):
            records = connector._fetch_network_restrictions("tok", "proj1")
        assert records == []

    def test_explicit_empty_allowed_ranges_is_unrestricted(self):
        connector = SupabaseConnector()
        with patch.object(connector, "_get", return_value={"allowed_ranges": []}):
            records = connector._fetch_network_restrictions("tok", "proj1")
        assert len(records) == 1
        assert records[0]["is_unrestricted"] is True

    def test_populated_allowed_ranges_is_restricted(self):
        connector = SupabaseConnector()
        with patch.object(connector, "_get", return_value={"allowed_ranges": ["10.0.0.0/8"]}):
            records = connector._fetch_network_restrictions("tok", "proj1")
        assert len(records) == 1
        assert records[0]["is_unrestricted"] is False
        assert records[0]["cidr"] == "10.0.0.0/8"


class TestConnectorEdgeFunctionNormalization:
    def test_verify_jwt_missing_stays_unknown(self):
        connector = SupabaseConnector()
        with patch.object(connector, "_get", return_value=[{"slug": "fn1", "name": "fn1"}]):
            records = connector._fetch_edge_functions("tok", "proj1")
        assert records[0]["verify_jwt"] is None

    def test_env_var_key_count_missing_stays_unknown_not_zero(self):
        connector = SupabaseConnector()
        with patch.object(connector, "_get", return_value=[{"slug": "fn1", "name": "fn1"}]):
            records = connector._fetch_edge_functions("tok", "proj1")
        assert records[0]["env_var_key_count"] is None

    def test_env_var_key_count_explicit_empty_is_zero(self):
        connector = SupabaseConnector()
        with patch.object(
            connector, "_get",
            return_value=[{"slug": "fn1", "name": "fn1", "envVarKeys": []}],
        ):
            records = connector._fetch_edge_functions("tok", "proj1")
        assert records[0]["env_var_key_count"] == 0


class TestClassifierBooleanUnknownSafety:
    """Every classifier branch fixed this pass must have an explicit
    unknown case that neither claims an explicit state nor crashes."""

    def test_anonymous_enabled_unknown_is_not_critical(self):
        change = _change(
            provider_metadata={"record_type": "supabase_auth_config"},
            field_path="anonymous_enabled", prev_value=False, new_value=None,
        )
        level, reason = classify_supabase_change(change)
        assert level != "critical"
        assert "could not be determined" in reason

    def test_mfa_totp_enabled_unknown_is_not_a_restore_claim(self):
        change = _change(
            provider_metadata={"record_type": "supabase_auth_config"},
            field_path="mfa_totp_enabled", prev_value=True, new_value=None,
        )
        level, reason = classify_supabase_change(change)
        assert "strengthens" not in reason.lower()
        assert "could not be determined" in reason

    def test_email_enabled_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_auth_config"},
            field_path="email_enabled", prev_value=True, new_value=None,
        )
        level, reason = classify_supabase_change(change)
        assert "was enabled" not in reason
        assert "could not be determined" in reason

    def test_phone_enabled_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_auth_config"},
            field_path="phone_enabled", prev_value=True, new_value=None,
        )
        _, reason = classify_supabase_change(change)
        assert "was disabled" not in reason

    def test_leaked_password_protection_unknown_is_not_a_restore_claim(self):
        change = _change(
            provider_metadata={"record_type": "supabase_auth_config"},
            field_path="leaked_password_protection_enabled", prev_value=False, new_value=None,
        )
        _, reason = classify_supabase_change(change)
        assert "will be warned" not in reason.lower()

    def test_captcha_enabled_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_auth_config"},
            field_path="captcha_enabled", prev_value=True, new_value=None,
        )
        _, reason = classify_supabase_change(change)
        assert "was enabled" not in reason

    def test_reauth_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_auth_config"},
            field_path="require_reauthentication_for_password_update",
            prev_value=False, new_value=None,
        )
        _, reason = classify_supabase_change(change)
        assert "now required" not in reason.lower()

    def test_refresh_token_rotation_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_auth_config"},
            field_path="refresh_token_rotation_enabled", prev_value=False, new_value=None,
        )
        _, reason = classify_supabase_change(change)
        assert "was enabled" not in reason

    def test_s3_protocol_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_storage_config"},
            field_path="s3_protocol_enabled", prev_value=True, new_value=None,
        )
        _, reason = classify_supabase_change(change)
        assert "was disabled" not in reason

    def test_verify_jwt_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_edge_function", "function_name": "fn1"},
            field_path="verify_jwt", prev_value=True, new_value=None,
        )
        level, reason = classify_supabase_change(change)
        assert level != "low"
        assert "must now provide" not in reason.lower()

    def test_rls_enabled_unknown_is_not_a_restore_claim(self):
        change = _change(
            provider_metadata={"record_type": "supabase_rls_status", "table_name": "orders", "schema_name": "public"},
            field_path="rls_enabled", prev_value=False, new_value=None,
        )
        level, reason = classify_supabase_change(change)
        assert "security improvement" not in reason.lower()
        assert level != "low"

    def test_rls_forced_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_rls_status", "table_name": "orders", "schema_name": "public"},
            field_path="rls_forced", prev_value=True, new_value=None,
        )
        _, reason = classify_supabase_change(change)
        assert "table owners may now bypass" not in reason.lower()

    def test_is_unrestricted_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_network_restriction"},
            field_path="is_unrestricted", prev_value=False, new_value=None,
        )
        level, reason = classify_supabase_change(change)
        assert level != "critical"
        assert "reinstated" not in reason.lower()

    def test_oauth_provider_enabled_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_oauth_provider", "provider_name": "google"},
            field_path="enabled", prev_value=True, new_value=None,
        )
        _, reason = classify_supabase_change(change)
        assert "was disabled" not in reason

    def test_has_public_select_policy_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_rls_status", "table_name": "orders", "schema_name": "public"},
            field_path="has_public_select_policy", prev_value=True, new_value=None,
        )
        _, reason = classify_supabase_change(change)
        assert "was removed" not in reason.lower()

    def test_has_public_insert_policy_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_rls_status", "table_name": "orders", "schema_name": "public"},
            field_path="has_public_insert_policy", prev_value=True, new_value=None,
        )
        _, reason = classify_supabase_change(change)
        assert "was removed" not in reason.lower()

    def test_exposed_to_anon_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_rls_status", "table_name": "orders", "schema_name": "public"},
            field_path="exposed_to_anon", prev_value=True, new_value=None,
        )
        _, reason = classify_supabase_change(change)
        assert "no longer has any policy" not in reason.lower()

    def test_has_custom_domain_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "supabase_project"},
            field_path="has_custom_domain", prev_value=True, new_value=None,
        )
        _, reason = classify_supabase_change(change)
        assert "was added" not in reason.lower()


class TestAddedRecordInspectionBugs:
    """Regression guards for the two 'added' Changes that were classifying
    based on the wrong data shape entirely."""

    def test_added_table_without_rls_is_medium_not_low(self):
        new_record = {
            "record_type": "supabase_rls_status", "record_id": "r1",
            "table_name": "new_table", "schema_name": "public",
            "rls_enabled": False, "rls_forced": False,
        }
        changes = _real_changes([], [new_record])
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        level, reason = classify_supabase_change(added[0])
        assert level == "medium"
        assert "without row level security" in reason.lower()

    def test_added_table_with_rls_is_still_low(self):
        new_record = {
            "record_type": "supabase_rls_status", "record_id": "r1",
            "table_name": "new_table", "schema_name": "public",
            "rls_enabled": True, "rls_forced": False,
        }
        changes = _real_changes([], [new_record])
        added = [c for c in changes if c["change_type"] == "added"]
        level, reason = classify_supabase_change(added[0])
        assert level == "low"
        assert "with rls enabled" in reason.lower()

    def test_added_table_rls_unknown_is_medium_and_cautious(self):
        new_record = {
            "record_type": "supabase_rls_status", "record_id": "r1",
            "table_name": "new_table", "schema_name": "public",
        }
        changes = _real_changes([], [new_record])
        added = [c for c in changes if c["change_type"] == "added"]
        level, reason = classify_supabase_change(added[0])
        assert level == "medium"
        assert "could not be determined" in reason

    def test_network_unrestricted_added_is_critical_not_low(self):
        """The exact scenario the bug caused: all explicit CIDR restrictions
        removed, leaving only the 'unrestricted' sentinel — previously
        misclassified as 'low' with backwards copy."""
        prev = [{
            "record_type": "supabase_network_restriction", "record_id": "nr1",
            "cidr": "10.0.0.0/8", "is_unrestricted": False,
        }]
        new = [{
            "record_type": "supabase_network_restriction",
            "record_id": "supabase_network_restriction:proj:unrestricted",
            "cidr": "", "is_unrestricted": True,
        }]
        changes = _real_changes(prev, new)
        added = [c for c in changes if c["change_type"] == "added"]
        removed = [c for c in changes if c["change_type"] == "removed"]
        assert len(added) == 1 and len(removed) == 1
        level, reason = classify_supabase_change(added[0])
        assert level == "critical"
        assert "now limited" not in reason.lower()
        assert "removed" in reason.lower()

    def test_network_restricted_added_is_still_low(self):
        new_record = {
            "record_type": "supabase_network_restriction", "record_id": "nr2",
            "cidr": "10.0.0.0/8", "is_unrestricted": False,
        }
        changes = _real_changes([], [new_record])
        added = [c for c in changes if c["change_type"] == "added"]
        level, _ = classify_supabase_change(added[0])
        assert level == "low"


class TestSecurityFindingUnknownSafety:
    """Findings must never fire on the newly-None-preserving fields."""

    def test_anonymous_enabled_unknown_does_not_fire(self):
        record = {"record_type": "supabase_auth_config", "record_id": "a1"}
        findings = evaluate_record(record, "supabase")
        keys = {f.rule_key for f in findings}
        assert "supabase_anonymous_access_enabled" not in keys

    def test_leaked_password_protection_unknown_does_not_fire(self):
        record = {"record_type": "supabase_auth_config", "record_id": "a1"}
        findings = evaluate_record(record, "supabase")
        keys = {f.rule_key for f in findings}
        assert "supabase_auth_protection_missing" not in keys

    def test_captcha_unknown_does_not_fire(self):
        record = {"record_type": "supabase_auth_config", "record_id": "a1"}
        findings = evaluate_record(record, "supabase")
        keys = {f.rule_key for f in findings}
        assert "supabase_captcha_disabled" not in keys

    def test_refresh_token_rotation_unknown_does_not_fire(self):
        record = {"record_type": "supabase_auth_config", "record_id": "a1"}
        findings = evaluate_record(record, "supabase")
        keys = {f.rule_key for f in findings}
        assert "supabase_refresh_token_rotation_disabled" not in keys

    def test_reauth_unknown_does_not_fire(self):
        record = {"record_type": "supabase_auth_config", "record_id": "a1"}
        findings = evaluate_record(record, "supabase")
        keys = {f.rule_key for f in findings}
        assert "supabase_password_update_reauth_disabled" not in keys
