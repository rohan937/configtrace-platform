"""Firebase detection-QA regression coverage (message-1 detection pass).

This file covers bugs found while auditing the Firebase connector -> diff ->
classify_firebase_change pipeline and Security Finding reachability:

  1. ``firebase_auth_provider`` is fully schema-defined, has a dedicated
     classifier (``_classify_auth_provider_change``) and diff-tracked fields,
     but the connector's ``_fetch_auth_config()`` only COUNTED SAML/OIDC
     provider list entries (``saml_count``/``oidc_count``) and discarded the
     actual per-provider objects — no ``firebase_auth_provider`` record was
     ever built. No new API call was needed: the SAML/OIDC list responses
     were already being fetched. Fixed by building one record per provider
     entry from the data already in scope, storing only ``provider_id``,
     ``provider_type`` ("saml"/"oidc"), and ``enabled`` — never
     ``clientSecret``/``clientId``/certificate material.
  2. ``firebase_database_ruleset`` (Realtime Database rules, M72A) is
     connector-emitted and its Security Findings (``firebase_database_
     public_read`` / ``firebase_database_public_write``) already fire
     correctly, but it had NO entry in ``_FIREBASE_TRACKED_FIELDS_BY_TYPE``
     and NO dispatch branch in ``classify_firebase_change()`` at all — every
     Change for this record type (including a transition to public
     read/write) silently fell to the generic
     ``"A Firebase configuration record changed (...)"`` low-severity
     fallback. Fixed by adding tracked fields, a dedicated classifier
     mirroring ``_classify_firestore_ruleset_change``/
     ``_classify_storage_ruleset_change``'s structure, and dispatch wiring.
  3. ``_build_provider_metadata()`` had no Firebase-specific stanza —
     ``_classify_auth_provider_change`` (``provider_id``), ``_classify_
     authorized_domain_change`` (``domain``/``is_default_firebase_domain``/
     ``is_localhost``), ``_classify_hosting_domain_change`` (``domain``/
     ``domain_type``), and ``_classify_function_metadata_change``
     (``function_name``) all read identifying fields directly from
     provider_metadata that the generic record_name/record_content stanza
     never populated. Fixed by adding a Firebase-specific stanza.

These tests exercise the REAL compute_diff() -> classify_firebase_change()
pipeline (not hand-built mocks) and the real connector fetch method
wherever practical.
"""

from __future__ import annotations

from unittest.mock import patch

from app.connectors.firebase import FirebaseConnector
from app.services.diff_service import compute_diff
from app.services.risk_rules.firebase import classify_firebase_change
from app.services.security_finding_evaluator import evaluate_record


class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]):
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


class TestAuthProviderConnectorReachability:
    """firebase_auth_provider must actually be emitted by the connector,
    using data already fetched (no new API calls)."""

    def _fetch(self, saml_configs, oidc_configs, base=None):
        connector = FirebaseConnector()

        def fake_get(access_token, url, params=None):
            if "inboundSamlConfigs" in url:
                return {"inboundSamlConfigs": saml_configs}
            if "oauthIdpConfigs" in url:
                return {"oauthIdpConfigs": oidc_configs}
            return dict(base or {})

        with patch.object(connector, "_get", side_effect=fake_get):
            return connector._fetch_auth_config("tok", "proj1", [])

    def test_saml_provider_is_emitted(self):
        records = self._fetch(
            saml_configs=[{"name": "projects/proj1/inboundSamlConfigs/my-saml", "enabled": True}],
            oidc_configs=[],
        )
        provider_records = [r for r in records if r["record_type"] == "firebase_auth_provider"]
        assert len(provider_records) == 1
        assert provider_records[0]["provider_id"] == "my-saml"
        assert provider_records[0]["provider_type"] == "saml"
        assert provider_records[0]["enabled"] is True

    def test_oidc_provider_is_emitted(self):
        records = self._fetch(
            saml_configs=[],
            oidc_configs=[{"name": "projects/proj1/oauthIdpConfigs/oidc.example", "enabled": False}],
        )
        provider_records = [r for r in records if r["record_type"] == "firebase_auth_provider"]
        assert len(provider_records) == 1
        assert provider_records[0]["provider_id"] == "oidc.example"
        assert provider_records[0]["provider_type"] == "oidc"
        assert provider_records[0]["enabled"] is False

    def test_no_client_secret_or_client_id_stored(self):
        records = self._fetch(
            saml_configs=[{
                "name": "projects/proj1/inboundSamlConfigs/my-saml", "enabled": True,
                "idpConfig": {"idpCertificates": ["FAKE_CERT_DATA"]},
            }],
            oidc_configs=[{
                "name": "projects/proj1/oauthIdpConfigs/oidc.example", "enabled": True,
                "clientId": "fake-client-id", "clientSecret": "fake-client-secret-value",
            }],
        )
        provider_records = [r for r in records if r["record_type"] == "firebase_auth_provider"]
        for r in provider_records:
            assert "clientSecret" not in r
            assert "clientId" not in r
            assert "idpConfig" not in r
            assert set(r.keys()) == {
                "record_type", "record_id", "name", "project_id",
                "provider_id", "provider_type", "enabled", "config_fetch_warnings",
            }

    def test_auth_config_counts_still_match_provider_records(self):
        records = self._fetch(
            saml_configs=[{"name": "projects/proj1/inboundSamlConfigs/s1", "enabled": True}],
            oidc_configs=[{"name": "projects/proj1/oauthIdpConfigs/o1", "enabled": True}],
        )
        auth_config = next(r for r in records if r["record_type"] == "firebase_auth_config")
        assert auth_config["saml_provider_count"] == 1
        assert auth_config["oidc_provider_count"] == 1


class TestAuthProviderRealComputeDiff:
    def test_provider_disabled_is_detected_and_classified(self):
        prev = [{
            "record_type": "firebase_auth_provider", "record_id": "proj1/my-saml",
            "provider_id": "my-saml", "provider_type": "saml", "enabled": True,
        }]
        new = [{**prev[0], "enabled": False}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "enabled"]
        assert len(matching) == 1, "firebase_auth_provider 'enabled' change was not detected by compute_diff"
        assert matching[0]["provider_metadata"]["provider_id"] == "my-saml"
        level, reason = classify_firebase_change(matching[0])
        assert level == "medium"
        assert "my-saml" in reason


class TestDatabaseRulesetTrackedAndClassified:
    _BASE = {
        "record_type": "firebase_database_ruleset", "record_id": "proj1/database/abc",
        "name": "default", "service": "realtime_database", "instance_name_hash": "abc",
        "rules_hash": "h1", "public_read_detected": False, "public_write_detected": False,
        "authenticated_only_detected": True, "rule_summary": "ok", "parser_confidence": "high",
    }

    def test_public_write_transition_is_detected_and_critical(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "public_write_detected": True}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "public_write_detected"]
        assert len(matching) == 1, "public_write_detected change was not detected by compute_diff"
        level, reason = classify_firebase_change(matching[0])
        assert level == "critical"
        assert "public write" in reason.lower()

    def test_public_read_transition_is_detected_and_high(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "public_read_detected": True}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "public_read_detected"]
        assert len(matching) == 1
        level, _ = classify_firebase_change(matching[0])
        assert level == "high"

    def test_no_longer_falls_to_generic_low_fallback(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "public_write_detected": True}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "public_write_detected"]
        _, reason = classify_firebase_change(matching[0])
        assert "A Firebase configuration record changed" not in reason

    def test_finding_still_reachable_for_public_write(self):
        record = {**self._BASE, "public_write_detected": True}
        findings = evaluate_record(record, "firebase")
        keys = {f.rule_key for f in findings}
        assert "firebase_database_public_write" in keys


class TestProviderMetadataCompleteness:
    def test_authorized_domain_metadata_survives_real_compute_diff(self):
        prev = [{
            "record_type": "firebase_authorized_domain", "record_id": "proj1/example.com",
            "domain": "example.com", "is_localhost": False, "is_default_firebase_domain": False,
        }]
        new = [dict(prev[0])]
        removed = _real_changes(prev, [])
        assert len(removed) == 1
        assert removed[0]["provider_metadata"]["domain"] == "example.com"
        _, reason = classify_firebase_change(removed[0])
        assert "example.com" in reason

    def test_hosting_domain_metadata_survives_real_compute_diff(self):
        prev = [{
            "record_type": "firebase_hosting_domain", "record_id": "proj1/site1/example.com",
            "domain": "example.com", "domain_type": "CUSTOM", "status": "ACTIVE",
        }]
        new = [{**prev[0], "status": "PENDING"}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "status"]
        assert len(matching) == 1
        assert matching[0]["provider_metadata"]["domain"] == "example.com"

    def test_function_metadata_name_survives_real_compute_diff(self):
        prev = [{
            "record_type": "firebase_function_metadata", "record_id": "proj1/us-central1/myFn",
            "function_name": "myFn", "region": "us-central1", "status": "ACTIVE",
        }]
        new = [{**prev[0], "status": "OFFLINE"}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "status"]
        assert len(matching) == 1
        assert matching[0]["provider_metadata"]["function_name"] == "myFn"
        _, reason = classify_firebase_change(matching[0])
        assert "myFn" in reason
