"""Deterministic contract fingerprint tests (message 7).

Covers stability across repeated calls, detection of every certification-
relevant contract change (record types, Findings, credentials,
capabilities, completeness, reconnect, launch state), order-independence,
exclusion of prose/timestamps, and evidence-note wording policy.
"""

from __future__ import annotations

import dataclasses

from app.provider_certification.models import (
    CompletenessScopeDeclaration,
    ReachabilityExemption,
)
from app.provider_certification import fingerprint, runner


def _base_manifest():
    return runner.get_manifest("sentry")


class TestStability:
    def test_fingerprint_is_stable_across_repeated_calls(self):
        m = _base_manifest()
        first = fingerprint.contract_fingerprint(m)
        second = fingerprint.contract_fingerprint(m)
        assert first == second

    def test_hash_is_stable_across_repeated_calls(self):
        m = _base_manifest()
        assert fingerprint.fingerprint_hash(m) == fingerprint.fingerprint_hash(m)

    def test_identical_manifests_are_fingerprints_equal(self):
        m = _base_manifest()
        assert fingerprint.fingerprints_equal(m, m) is True


class TestRecordTypeChangeDetected:
    def test_added_record_type_changes_fingerprint(self):
        m = _base_manifest()
        changed = dataclasses.replace(
            m, expected_record_types=tuple(m.expected_record_types) + ("brand_new_record_type",)
        )
        assert not fingerprint.fingerprints_equal(m, changed)
        diff = fingerprint.diff_fingerprints(
            fingerprint.contract_fingerprint(m), fingerprint.contract_fingerprint(changed)
        )
        assert "record_types" in diff


class TestFindingChangeDetected:
    def test_added_finding_id_changes_fingerprint(self):
        m = _base_manifest()
        new_rule_id = "sentry_brand_new_finding_rule"
        changed = dataclasses.replace(
            m,
            security_finding_rule_ids=tuple(m.security_finding_rule_ids) + (new_rule_id,),
            reachability_exemptions=tuple(m.reachability_exemptions)
            + (ReachabilityExemption(rule_ids=(new_rule_id,), reason="test fixture exemption"),),
        )
        assert not fingerprint.fingerprints_equal(m, changed)
        diff = fingerprint.diff_fingerprints(
            fingerprint.contract_fingerprint(m), fingerprint.contract_fingerprint(changed)
        )
        assert "finding_ids" in diff


class TestCredentialFieldChangeDetected:
    def test_added_credential_field_changes_fingerprint(self):
        m = _base_manifest()
        changed = dataclasses.replace(
            m, credential_fields=tuple(m.credential_fields) + ("brand_new_credential_field",)
        )
        assert not fingerprint.fingerprints_equal(m, changed)
        diff = fingerprint.diff_fingerprints(
            fingerprint.contract_fingerprint(m), fingerprint.contract_fingerprint(changed)
        )
        assert "credential_fields" in diff

    def test_added_sensitive_credential_field_changes_fingerprint(self):
        m = _base_manifest()
        changed = dataclasses.replace(
            m,
            credential_fields=tuple(m.credential_fields) + ("brand_new_secret_field",),
            sensitive_credential_fields=tuple(m.sensitive_credential_fields) + ("brand_new_secret_field",),
        )
        assert not fingerprint.fingerprints_equal(m, changed)


class TestCapabilityChangeDetected:
    def test_added_supported_capability_changes_fingerprint(self):
        m = _base_manifest()
        changed = dataclasses.replace(
            m, supported_capabilities=tuple(m.supported_capabilities) + ("brand_new_capability",)
        )
        assert not fingerprint.fingerprints_equal(m, changed)
        diff = fingerprint.diff_fingerprints(
            fingerprint.contract_fingerprint(m), fingerprint.contract_fingerprint(changed)
        )
        assert "supported_capabilities" in diff

    def test_added_unsupported_capability_changes_fingerprint(self):
        m = _base_manifest()
        changed = dataclasses.replace(
            m, unsupported_capabilities=tuple(m.unsupported_capabilities) + ("brand_new_gap",)
        )
        assert not fingerprint.fingerprints_equal(m, changed)


class TestCompletenessChangeDetected:
    def test_added_completeness_scope_changes_fingerprint(self):
        m = _base_manifest()
        changed = dataclasses.replace(
            m, completeness_scopes=tuple(m.completeness_scopes) + ("brand_new_scope",)
        )
        assert not fingerprint.fingerprints_equal(m, changed)

    def test_added_completeness_scope_declaration_changes_fingerprint(self):
        m = _base_manifest()
        real_record_type = m.expected_record_types[0]
        new_decl = CompletenessScopeDeclaration(
            scope_id="brand_new_scope_decl",
            granularity="family",
            record_types=(real_record_type,),
        )
        changed = dataclasses.replace(
            m, completeness_scope_declarations=tuple(m.completeness_scope_declarations) + (new_decl,)
        )
        assert not fingerprint.fingerprints_equal(m, changed)
        diff = fingerprint.diff_fingerprints(
            fingerprint.contract_fingerprint(m), fingerprint.contract_fingerprint(changed)
        )
        assert "completeness_scope_declarations" in diff

    def test_added_false_removal_scope_changes_fingerprint(self):
        m = _base_manifest()
        changed = dataclasses.replace(
            m, false_removal_scopes=tuple(m.false_removal_scopes) + ("brand_new_scope",)
        )
        assert not fingerprint.fingerprints_equal(m, changed)


class TestReconnectChangeDetected:
    def test_reconnect_flag_flip_changes_fingerprint(self):
        # google_cloud is public=True/connectable=True/live=False/reconnect=False,
        # so flipping reconnect alone stays a valid manifest (only
        # expected_live=True forces expected_reconnect=True).
        m = runner.get_manifest("google_cloud")
        changed = dataclasses.replace(m, expected_reconnect=not m.expected_reconnect)
        assert not fingerprint.fingerprints_equal(m, changed)
        diff = fingerprint.diff_fingerprints(
            fingerprint.contract_fingerprint(m), fingerprint.contract_fingerprint(changed)
        )
        assert "reconnect" in diff


class TestLaunchStateChangeDetected:
    def test_public_flag_flip_changes_fingerprint(self):
        # google_cloud is public=True/connectable=True/live=False; since
        # expected_connectable=True requires expected_public=True, we flip
        # both down together to stay valid, and still detect the change.
        m = runner.get_manifest("google_cloud")
        changed = dataclasses.replace(m, expected_public=False, expected_connectable=False)
        assert not fingerprint.fingerprints_equal(m, changed)
        diff = fingerprint.diff_fingerprints(
            fingerprint.contract_fingerprint(m), fingerprint.contract_fingerprint(changed)
        )
        assert "public" in diff

    def test_connectable_flag_flip_changes_fingerprint(self):
        # slack starts maturity='planned' (public=False/connectable=False/
        # live=False by construction); enabling connectable requires public
        # and a frontend form too, and 'planned' forbids all three, so we
        # promote maturity to 'partial' in the same replace() to stay valid.
        m = runner.get_manifest("slack")
        changed = dataclasses.replace(
            m,
            maturity="partial",
            expected_public=True,
            expected_connectable=True,
            expected_frontend_form=m.expected_frontend_form or "SlackIntegrationForm",
        )
        assert not fingerprint.fingerprints_equal(m, changed)
        diff = fingerprint.diff_fingerprints(
            fingerprint.contract_fingerprint(m), fingerprint.contract_fingerprint(changed)
        )
        assert "connectable" in diff

    def test_live_flag_flip_changes_fingerprint(self):
        # google_cloud is connectable=True/live=False already, so flipping
        # live to True only additionally requires reconnect=True.
        m = runner.get_manifest("google_cloud")
        changed = dataclasses.replace(m, expected_live=not m.expected_live, expected_reconnect=True)
        assert not fingerprint.fingerprints_equal(m, changed)
        diff = fingerprint.diff_fingerprints(
            fingerprint.contract_fingerprint(m), fingerprint.contract_fingerprint(changed)
        )
        assert "live" in diff

    def test_maturity_change_changes_fingerprint(self):
        # slack is fully non-public/non-connectable/non-live already, so
        # it satisfies the "planned" invariant either way.
        m = runner.get_manifest("slack")
        other_maturity = "planned" if m.maturity != "planned" else "partial"
        changed = dataclasses.replace(m, maturity=other_maturity)
        assert not fingerprint.fingerprints_equal(m, changed)


class TestFrontendFormChangeDetected:
    def test_frontend_form_change_changes_fingerprint(self):
        m = _base_manifest()
        changed = dataclasses.replace(m, expected_frontend_form=(m.expected_frontend_form or "") + "V2")
        assert not fingerprint.fingerprints_equal(m, changed)
        diff = fingerprint.diff_fingerprints(
            fingerprint.contract_fingerprint(m), fingerprint.contract_fingerprint(changed)
        )
        assert "frontend_form" in diff


class TestSchemaVersionChangeDetected:
    def test_manifest_version_bump_changes_fingerprint(self):
        m = _base_manifest()
        changed = dataclasses.replace(m, manifest_version=m.manifest_version + 1)
        assert not fingerprint.fingerprints_equal(m, changed)
        diff = fingerprint.diff_fingerprints(
            fingerprint.contract_fingerprint(m), fingerprint.contract_fingerprint(changed)
        )
        assert "schema_version" in diff


class TestOrderIndependence:
    def test_record_type_ordering_does_not_affect_fingerprint(self):
        m = _base_manifest()
        reordered = dataclasses.replace(m, expected_record_types=tuple(reversed(m.expected_record_types)))
        assert fingerprint.fingerprints_equal(m, reordered)

    def test_credential_field_ordering_does_not_affect_fingerprint(self):
        m = _base_manifest()
        reordered = dataclasses.replace(m, credential_fields=tuple(reversed(m.credential_fields)))
        assert fingerprint.fingerprints_equal(m, reordered)

    def test_finding_id_ordering_does_not_affect_fingerprint(self):
        m = _base_manifest()
        reordered = dataclasses.replace(m, security_finding_rule_ids=tuple(reversed(m.security_finding_rule_ids)))
        assert fingerprint.fingerprints_equal(m, reordered)


class TestProseAndTimestampsExcluded:
    def test_known_limitations_prose_change_does_not_affect_fingerprint(self):
        m = _base_manifest()
        changed = dataclasses.replace(m, known_limitations=tuple(m.known_limitations) + ("Some new prose note.",))
        assert fingerprint.fingerprints_equal(m, changed)

    def test_display_name_change_does_not_affect_fingerprint(self):
        m = _base_manifest()
        changed = dataclasses.replace(m, display_name=m.display_name + " (renamed)")
        assert fingerprint.fingerprints_equal(m, changed)

    def test_evidence_test_file_list_change_does_not_affect_fingerprint(self):
        m = _base_manifest()
        changed = dataclasses.replace(m, evidence_test_files=tuple(m.evidence_test_files) + ("tests/some_new_test.py",))
        assert fingerprint.fingerprints_equal(m, changed)

    def test_evidence_report_path_change_does_not_affect_fingerprint(self):
        m = _base_manifest()
        changed = dataclasses.replace(m, evidence_reports=tuple(m.evidence_reports) + ("some/new/report.md",))
        assert fingerprint.fingerprints_equal(m, changed)

    def test_fingerprint_dict_contains_no_timestamp_like_keys(self):
        m = _base_manifest()
        keys = set(fingerprint.contract_fingerprint(m))
        for forbidden in ("timestamp", "generated_at", "updated_at", "created_at", "mtime"):
            assert forbidden not in keys


class TestHashDeterminism:
    def test_hash_is_hex_sha256_length(self):
        m = _base_manifest()
        h = fingerprint.fingerprint_hash(m)
        assert len(h) == 64
        int(h, 16)  # must be valid hex

    def test_reordered_tuple_fields_produce_identical_hash(self):
        m = _base_manifest()
        reordered = dataclasses.replace(m, credential_fields=tuple(reversed(m.credential_fields)))
        assert fingerprint.fingerprint_hash(m) == fingerprint.fingerprint_hash(reordered)


class TestDiffFingerprintsShape:
    def test_diff_of_identical_fingerprints_is_empty(self):
        m = _base_manifest()
        fp = fingerprint.contract_fingerprint(m)
        assert fingerprint.diff_fingerprints(fp, fp) == {}

    def test_diff_entries_carry_before_and_after(self):
        m = runner.get_manifest("google_cloud")
        changed = dataclasses.replace(m, expected_reconnect=not m.expected_reconnect)
        diff = fingerprint.diff_fingerprints(
            fingerprint.contract_fingerprint(m), fingerprint.contract_fingerprint(changed)
        )
        assert diff["reconnect"]["before"] == m.expected_reconnect
        assert diff["reconnect"]["after"] == changed.expected_reconnect
