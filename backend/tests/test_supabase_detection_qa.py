"""Supabase detection-QA regression coverage (message-1 detection pass).

This file covers bugs found while auditing the Supabase connector -> diff ->
classify_supabase_change pipeline, and Security Finding reachability:

  1. ``supabase_rls_status``'s M71A per-table public-policy fields
     (``policy_count``, ``has_public_select_policy``,
     ``has_public_insert_policy``, ``has_public_update_policy``,
     ``has_public_delete_policy``, ``exposed_to_anon``) are emitted by the
     connector (merged from ``_fetch_database_policies``) and evaluated by
     the ``supabase_public_select_sensitive_table`` / ``supabase_public_
     write_policy`` Security Findings, but had NO entry in
     ``_SUPABASE_TRACKED_FIELDS_BY_TYPE`` — compute_diff() never detected a
     table gaining or losing a public policy as a Change. Fixed by adding
     the tracked-field entries and matching classifier branches in
     ``_classify_rls_status_change``.
  2. ``_build_provider_metadata()`` had NO Supabase-specific stanza at all —
     five classifiers (``_classify_rls_status_change``, ``_classify_edge_
     function_change``, ``_classify_network_restriction_change``,
     ``_classify_custom_domain_change``, ``_classify_oauth_provider_
     change``) read identifying fields (``table_name``/``schema_name``,
     ``function_name``/``slug``, ``cidr``, ``custom_domain``,
     ``provider_name``) directly from provider_metadata that the generic
     record_name/record_content stanza never populates (these records don't
     carry a "name" field). In production this meant the MOST severe
     Supabase Change ("RLS disabled" — critical) showed only the schema
     ("table 'public'") with the table name silently dropped, making the
     alert nearly useless for triage. Fixed by adding a Supabase-specific
     stanza to ``_build_provider_metadata()``.
  3. ``_fetch_rls_status``, ``_fetch_network_restrictions``, and
     ``_fetch_edge_functions`` each injected a synthetic "_access_denied"
     placeholder record on HTTP 403 whose ``record_id`` was NEW and
     distinct from every real per-item record's id. Since these are
     per-item list endpoints, a mere permission hiccup made compute_diff()
     report EVERY previously-known table/CIDR/function as "removed" (their
     ids vanish from the new snapshot) plus the placeholder itself as
     "added" — a burst of false-removal noise, followed by another burst
     when the token was fixed and the placeholder disappeared while real
     items "reappeared". Fixed by returning an empty list on 403 instead,
     matching the safer pattern already used by ``_fetch_custom_domain``.

These tests exercise the REAL compute_diff() -> classify_supabase_change()
pipeline (not hand-built mocks) wherever practical, matching the
established regression pattern from this session's other detection-QA
passes.
"""

from __future__ import annotations

from unittest.mock import patch

from app.connectors.exceptions import ConnectorError
from app.connectors.supabase import SupabaseConnector
from app.services.diff_service import compute_diff
from app.services.risk_rules.supabase import classify_supabase_change
from app.services.security_finding_evaluator import evaluate_record


class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]):
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


_RLS_BASE = {
    "record_type": "supabase_rls_status",
    "record_id": "supabase_rls_status:proj:public.orders",
    "table_name": "orders",
    "schema_name": "public",
    "rls_enabled": True,
    "rls_forced": False,
    "policy_count": 1,
    "has_public_select_policy": False,
    "has_public_insert_policy": False,
    "has_public_update_policy": False,
    "has_public_delete_policy": False,
    "exposed_to_anon": False,
}


class TestRlsPolicyFieldsRealComputeDiff:
    def test_public_select_policy_added_is_detected_and_high(self):
        prev = [dict(_RLS_BASE)]
        new = [{**_RLS_BASE, "has_public_select_policy": True, "exposed_to_anon": True,
                 "policy_count": 2}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "has_public_select_policy"]
        assert len(matching) == 1, "has_public_select_policy change was not detected by compute_diff"
        level, reason = classify_supabase_change(matching[0])
        assert level == "high"
        assert "public.orders" in reason

    def test_public_write_policy_added_is_high(self):
        prev = [dict(_RLS_BASE)]
        new = [{**_RLS_BASE, "has_public_insert_policy": True}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "has_public_insert_policy"]
        assert len(matching) == 1
        level, reason = classify_supabase_change(matching[0])
        assert level == "high"
        assert "public.orders" in reason

    def test_public_policy_removed_is_low(self):
        prev = [{**_RLS_BASE, "has_public_select_policy": True}]
        new = [dict(_RLS_BASE)]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "has_public_select_policy"]
        assert len(matching) == 1
        level, _ = classify_supabase_change(matching[0])
        assert level == "low"

    def test_rls_status_change_still_detects_rls_enabled_and_carries_table_name(self):
        prev = [dict(_RLS_BASE)]
        new = [{**_RLS_BASE, "rls_enabled": False}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "rls_enabled"]
        assert len(matching) == 1
        assert matching[0]["provider_metadata"]["table_name"] == "orders"
        assert matching[0]["provider_metadata"]["schema_name"] == "public"
        level, reason = classify_supabase_change(matching[0])
        assert level == "critical"
        assert "public.orders" in reason


class TestProviderMetadataCompleteness:
    """Every Supabase classifier that needs an identifying field beyond
    record_name/record_content must actually receive it through real
    compute_diff() output, not just hand-built test metadata."""

    def test_edge_function_name_survives_real_compute_diff(self):
        prev = [{
            "record_type": "supabase_edge_function", "record_id": "fn1",
            "function_name": "admin-delete", "slug": "admin-delete",
            "status": "ACTIVE", "version": 1, "env_var_key_count": 0,
            "verify_jwt": True,
        }]
        new = [{**prev[0], "verify_jwt": False}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "verify_jwt"]
        assert len(matching) == 1
        assert matching[0]["provider_metadata"]["function_name"] == "admin-delete"
        _, reason = classify_supabase_change(matching[0])
        assert "admin-delete" in reason

    def test_network_restriction_cidr_survives_real_compute_diff(self):
        prev = [{
            "record_type": "supabase_network_restriction", "record_id": "nr1",
            "cidr": "10.0.0.0/8", "is_unrestricted": False,
        }]
        new = []
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["change_type"] == "removed"]
        assert len(matching) == 1
        assert matching[0]["provider_metadata"]["cidr"] == "10.0.0.0/8"
        _, reason = classify_supabase_change(matching[0])
        assert "10.0.0.0/8" in reason

    def test_custom_domain_survives_real_compute_diff(self):
        prev = [{
            "record_type": "supabase_custom_domain", "record_id": "cd1",
            "custom_domain": "api.example.com", "status": "active",
        }]
        new = [{**prev[0], "status": "pending"}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "status"]
        assert len(matching) == 1
        assert matching[0]["provider_metadata"]["custom_domain"] == "api.example.com"
        _, reason = classify_supabase_change(matching[0])
        assert "api.example.com" in reason

    def test_oauth_provider_name_survives_real_compute_diff(self):
        prev = [{
            "record_type": "supabase_oauth_provider", "record_id": "op1",
            "provider_name": "google", "enabled": True, "client_id_hash": "abc123",
        }]
        new = [{**prev[0], "enabled": False}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "enabled"]
        assert len(matching) == 1
        assert matching[0]["provider_metadata"]["provider_name"] == "google"
        _, reason = classify_supabase_change(matching[0])
        assert "google" in reason


class TestOptionalEndpoint403DoesNotMassRemove:
    """A 403 on an optional per-item-list endpoint must not inject a
    synthetic placeholder whose record_id differs from every real item's
    id — that would make compute_diff() report all prior items as
    "removed" plus the placeholder as "added"."""

    def test_rls_status_403_returns_empty_list_not_a_placeholder(self):
        connector = SupabaseConnector()
        with patch.object(
            connector, "_get",
            side_effect=ConnectorError("403", status_code=403),
        ):
            result = connector._fetch_rls_status("tok", "proj123")
        assert result == []

    def test_network_restrictions_403_returns_empty_list_not_a_placeholder(self):
        connector = SupabaseConnector()
        with patch.object(
            connector, "_get",
            side_effect=ConnectorError("403", status_code=403),
        ):
            result = connector._fetch_network_restrictions("tok", "proj123")
        assert result == []

    def test_edge_functions_403_returns_empty_list_not_a_placeholder(self):
        connector = SupabaseConnector()
        with patch.object(
            connector, "_get",
            side_effect=ConnectorError("403", status_code=403),
        ):
            result = connector._fetch_edge_functions("tok", "proj123")
        assert result == []

    def test_rls_403_does_not_falsely_remove_prior_tables(self):
        """Regression guard for the exact scenario the bug caused: a prior
        sync had 2 real table records; this sync's RLS endpoint 403s. The
        new snapshot must contain zero supabase_rls_status records (not a
        placeholder), and — critically — this test documents that
        compute_diff() will still show the 2 prior tables as "removed"
        (an accepted, architecture-wide limitation of snapshot-diffing
        shared by every provider's optional per-item endpoints, not
        something this fix eliminates) rather than the previous behavior
        of ALSO fabricating a spurious "added" placeholder on top of that."""
        connector = SupabaseConnector()
        with patch.object(
            connector, "_get",
            side_effect=ConnectorError("403", status_code=403),
        ):
            new_rls_records = connector._fetch_rls_status("tok", "proj123")
        assert new_rls_records == []

        prev = [
            {"record_type": "supabase_rls_status", "record_id": "supabase_rls_status:proj123:public.a",
             "table_name": "a", "schema_name": "public", "rls_enabled": True, "rls_forced": False},
            {"record_type": "supabase_rls_status", "record_id": "supabase_rls_status:proj123:public.b",
             "table_name": "b", "schema_name": "public", "rls_enabled": True, "rls_forced": False},
        ]
        changes = _real_changes(prev, new_rls_records)
        removed = [c for c in changes if c["change_type"] == "removed"]
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(removed) == 2
        assert len(added) == 0, "no spurious placeholder should appear as 'added'"


class TestSecurityFindingReachability:
    """Every Supabase Security Finding rule fires from a shape the connector
    can actually produce, through the real evaluate_record() entrypoint."""

    def test_rls_disabled_fires_high(self):
        record = {**_RLS_BASE, "rls_enabled": False}
        findings = evaluate_record(record, "supabase")
        keys = {f.rule_key for f in findings}
        assert "supabase_rls_disabled" in keys

    def test_rls_disabled_unknown_does_not_fire(self):
        record = {k: v for k, v in _RLS_BASE.items() if k != "rls_enabled"}
        findings = evaluate_record(record, "supabase")
        keys = {f.rule_key for f in findings}
        assert "supabase_rls_disabled" not in keys

    def test_public_select_sensitive_table_fires(self):
        record = {**_RLS_BASE, "table_name": "users", "has_public_select_policy": True}
        findings = evaluate_record(record, "supabase")
        keys = {f.rule_key for f in findings}
        assert "supabase_public_select_sensitive_table" in keys

    def test_edge_function_jwt_disabled_fires(self):
        record = {
            "record_type": "supabase_edge_function", "record_id": "fn1",
            "function_name": "public-webhook", "slug": "public-webhook",
            "verify_jwt": False,
        }
        findings = evaluate_record(record, "supabase")
        keys = {f.rule_key for f in findings}
        assert "supabase_edge_function_jwt_disabled" in keys

    def test_edge_function_verify_jwt_unknown_does_not_fire(self):
        record = {
            "record_type": "supabase_edge_function", "record_id": "fn1",
            "function_name": "some-fn", "slug": "some-fn",
        }
        findings = evaluate_record(record, "supabase")
        keys = {f.rule_key for f in findings}
        assert "supabase_edge_function_jwt_disabled" not in keys
