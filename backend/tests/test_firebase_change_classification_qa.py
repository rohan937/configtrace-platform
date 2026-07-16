"""Firebase change-classification QA regression coverage (message-2 pass).

This file covers bugs found while auditing classification correctness across
all 13 currently-emitted Firebase record types (message-1 detection QA, fixed
in commit 7f9b375, established reachability/routing). This pass focuses on
whether the *content* of each classification is correct — in particular,
unknown-Boolean-as-False coercion and unconditional-else branches that
overstate an unknown posture as either restoration or weakening.

Bugs fixed and covered here:

  1. ``app/connectors/firebase.py`` coerced several Management/Identity
     Toolkit API booleans (``enabled`` for SAML/OIDC providers,
     ``sign_in_email_enabled``, ``sign_in_phone_enabled``,
     ``anonymous_enabled``, and the ``mfa_enabled`` derivation) to ``False``
     when the source field was missing, via ``bool(x.get(key, False))``.
     Fixed with a ``_bool_or_none()`` helper that preserves ``None``.
  2. ``_analyze_rules()`` / ``_analyze_rtdb_rules()`` / the per-release
     analysis initializer in ``_fetch_firebase_rules()`` defaulted
     ``public_read_detected`` / ``public_write_detected`` /
     ``authenticated_only_detected`` to ``False`` when the rules source could
     not be fetched — an unknown posture reported as a confirmed non-public
     state. Fixed to default to ``None``.
  3. The classifiers for all of the above fields used unconditional
     ``if X: ...; else: ...`` branches with no explicit ``is None`` check, so
     an unknown value fell into the "else" (typically "improved"/"disabled")
     branch. Fixed by adding explicit ``is None`` branches with cautious
     "could not be determined" copy, for: ``_classify_auth_config_change``
     (``anonymous_enabled``, ``mfa_enabled``/``mfa_state``,
     ``sign_in_email_enabled``, ``sign_in_phone_enabled``),
     ``_classify_auth_provider_change`` (``enabled``),
     ``_classify_firestore_ruleset_change`` / ``_classify_storage_ruleset_
     change`` / ``_classify_database_ruleset_change`` (``public_write_
     detected``, ``public_read_detected``, ``authenticated_only_detected``),
     and ``_classify_storage_bucket_change`` (``uniform_bucket_level_
     access``).
  4. ``_classify_remote_config_change`` and ``_classify_app_check_change``
     both read a Change's previous value via ``old_value`` — a field real
     ``compute_diff()`` Changes never carry (the actual field is
     ``prev_value``) — combined with a local ``_int()`` helper that silently
     defaulted unparseable/missing input to ``0``. The result: every "count
     decreased" comparison used a phantom previous value of 0, meaning App
     Check enforcement REMOVALS (e.g. enforced_service_count 5 -> 2) were
     misclassified as enforcement ADDITIONS — the literal opposite of what
     happened. Fixed by reading ``prev_value`` and replacing the unsafe
     ``_int()`` with an ``_int_or_none()`` that preserves unknown, paired
     with explicit ``None``-branch handling.
  5. The "added" branches for ``_classify_firestore_ruleset_change`` /
     ``_classify_storage_ruleset_change`` / ``_classify_database_ruleset_
     change`` / ``_classify_storage_bucket_change`` returned a flat generic
     "baseline captured" severity regardless of the new record's actual
     public-read/write or bucket-hardening posture. Fixed to inspect the
     full new record dict (``new_value`` for an "added" Change).

These tests exercise the REAL compute_diff() -> classify_firebase_change()
pipeline (not hand-built Change objects with fabricated field names).
"""

from __future__ import annotations

from app.services.diff_service import compute_diff
from app.services.risk_rules.firebase import classify_firebase_change


class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]):
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


def _classify_field(prev: list[dict], new: list[dict], field_path: str):
    changes = _real_changes(prev, new)
    matching = [c for c in changes if c["field_path"] == field_path]
    assert len(matching) == 1, f"expected exactly one Change for {field_path!r}, got {len(matching)}"
    return classify_firebase_change(matching[0])


# ── Auth config: unknown Boolean handling ────────────────────────────────────

class TestAuthConfigUnknownHandling:
    _BASE = {
        "record_type": "firebase_auth_config", "record_id": "proj1/auth_config",
        "project_id": "proj1", "anonymous_enabled": False, "mfa_enabled": False,
        "mfa_state": "DISABLED", "sign_in_email_enabled": True,
        "sign_in_phone_enabled": True, "authorized_domain_count": 2,
        "saml_provider_count": 0, "oidc_provider_count": 0,
    }

    def test_anonymous_enabled_becoming_unknown_is_not_reported_as_disabled(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "anonymous_enabled": None}]
        level, reason = _classify_field(prev, new, "anonymous_enabled")
        assert level == "medium"
        assert "could not be determined" in reason.lower()
        assert "disabled" not in reason.lower()

    def test_mfa_enabled_becoming_unknown_is_not_reported_as_disabled(self):
        prev = [{**self._BASE, "mfa_enabled": True, "mfa_state": "ENABLED"}]
        new = [{**self._BASE, "mfa_enabled": None, "mfa_state": None}]
        level, reason = _classify_field(prev, new, "mfa_enabled")
        assert level == "medium"
        assert "could not be determined" in reason.lower()
        assert "was disabled" not in reason.lower()

    def test_sign_in_email_enabled_becoming_unknown_is_not_reported_as_disabled(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "sign_in_email_enabled": None}]
        level, reason = _classify_field(prev, new, "sign_in_email_enabled")
        assert level == "medium"
        assert "could not be determined" in reason.lower()

    def test_sign_in_phone_enabled_becoming_unknown_is_not_reported_as_disabled(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "sign_in_phone_enabled": None}]
        level, reason = _classify_field(prev, new, "sign_in_phone_enabled")
        assert level == "medium"
        assert "could not be determined" in reason.lower()

    def test_anonymous_enabled_true_still_reports_high(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "anonymous_enabled": True}]
        level, reason = _classify_field(prev, new, "anonymous_enabled")
        assert level == "high"
        assert "enabled" in reason.lower()


class TestAuthProviderUnknownHandling:
    def test_enabled_becoming_unknown_is_not_reported_as_disabled(self):
        prev = [{
            "record_type": "firebase_auth_provider", "record_id": "proj1/my-saml",
            "provider_id": "my-saml", "provider_type": "saml", "enabled": True,
        }]
        new = [{**prev[0], "enabled": None}]
        level, reason = _classify_field(prev, new, "enabled")
        assert level == "medium"
        assert "could not be determined" in reason.lower()
        assert "was disabled" not in reason.lower()


# ── Rules-fetch failure safety: Firestore / Realtime Database / Storage ──────

class TestFirestoreRulesetUnknownHandling:
    _BASE = {
        "record_type": "firebase_firestore_ruleset", "record_id": "proj1/firestore/abc",
        "name": "default", "rules_hash": "h1", "public_read_detected": False,
        "public_write_detected": False, "authenticated_only_detected": True,
        "rule_summary": "ok", "parser_confidence": "high",
    }

    def test_public_write_becoming_unknown_is_not_reported_as_improved(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "public_write_detected": None, "parser_confidence": "low"}]
        level, reason = _classify_field(prev, new, "public_write_detected")
        assert level == "medium"
        assert "could not be determined" in reason.lower()
        assert "improved" not in reason.lower()

    def test_public_read_becoming_unknown_is_not_reported_as_improved(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "public_read_detected": None, "parser_confidence": "low"}]
        level, reason = _classify_field(prev, new, "public_read_detected")
        assert level == "medium"
        assert "could not be determined" in reason.lower()

    def test_authenticated_only_becoming_unknown_is_not_reported_as_weakened(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "authenticated_only_detected": None, "parser_confidence": "low"}]
        level, reason = _classify_field(prev, new, "authenticated_only_detected")
        assert level == "medium"
        assert "could not be determined" in reason.lower()

    def test_added_record_with_public_write_is_critical_not_generic(self):
        new = [{**self._BASE, "public_write_detected": True}]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        level, reason = classify_firebase_change(added[0])
        assert level == "critical"
        assert "baseline captured" not in reason.lower()

    def test_added_record_safe_posture_is_low(self):
        new = [dict(self._BASE)]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        level, _ = classify_firebase_change(added[0])
        assert level == "low"


class TestDatabaseRulesetUnknownHandling:
    _BASE = {
        "record_type": "firebase_database_ruleset", "record_id": "proj1/database/abc",
        "name": "default", "service": "realtime_database", "instance_name_hash": "abc",
        "rules_hash": "h1", "public_read_detected": False, "public_write_detected": False,
        "authenticated_only_detected": True, "rule_summary": "ok", "parser_confidence": "high",
    }

    def test_public_write_becoming_unknown_is_not_reported_as_improved(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "public_write_detected": None, "parser_confidence": "low"}]
        level, reason = _classify_field(prev, new, "public_write_detected")
        assert level == "medium"
        assert "could not be determined" in reason.lower()

    def test_added_record_with_public_read_is_high_not_generic(self):
        new = [{**self._BASE, "public_read_detected": True}]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        level, reason = classify_firebase_change(added[0])
        assert level == "high"
        assert "baseline captured" not in reason.lower()


class TestStorageRulesetUnknownHandling:
    _BASE = {
        "record_type": "firebase_storage_ruleset", "record_id": "proj1/storage/abc",
        "name": "default", "rules_hash": "h1", "public_read_detected": False,
        "public_write_detected": False, "authenticated_only_detected": True,
        "rule_summary": "ok", "parser_confidence": "high",
    }

    def test_public_write_becoming_unknown_is_not_reported_as_improved(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "public_write_detected": None, "parser_confidence": "low"}]
        level, reason = _classify_field(prev, new, "public_write_detected")
        assert level == "medium"
        assert "could not be determined" in reason.lower()

    def test_added_record_with_public_write_is_critical_not_generic(self):
        new = [{**self._BASE, "public_write_detected": True}]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        level, reason = classify_firebase_change(added[0])
        assert level == "critical"
        assert "baseline captured" not in reason.lower()


class TestStorageBucketUnknownHandling:
    _BASE = {
        "record_type": "firebase_storage_bucket", "record_id": "proj1/bucket1",
        "name": "bucket1", "uniform_bucket_level_access": True,
        "public_access_prevention": "enforced", "storage_class": "STANDARD",
        "location": "US", "versioning_enabled": False,
    }

    def test_uniform_bucket_level_access_becoming_unknown_is_not_reported_as_disabled(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "uniform_bucket_level_access": None}]
        level, reason = _classify_field(prev, new, "uniform_bucket_level_access")
        assert level == "medium"
        assert "could not be determined" in reason.lower()

    def test_added_bucket_without_uniform_access_is_medium_not_generic_low(self):
        new = [{**self._BASE, "uniform_bucket_level_access": False}]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        level, reason = classify_firebase_change(added[0])
        assert level == "medium"
        assert "acls" in reason.lower() or "acl" in reason.lower()

    def test_added_bucket_hardened_is_low(self):
        new = [dict(self._BASE)]
        changes = _real_changes([], new)
        added = [c for c in changes if c["change_type"] == "added"]
        level, _ = classify_firebase_change(added[0])
        assert level == "low"


# ── Remote Config / App Check: prev_value + numeric-unknown handling ────────

class TestRemoteConfigPrevValueHandling:
    _BASE = {
        "record_type": "firebase_remote_config_template", "record_id": "proj1/remote_config",
        "parameter_count": 10, "condition_count": 3, "parameter_keys_hash": "h1",
        "condition_names_hash": "h2", "update_type": "INCREMENTAL_UPDATE",
        "version_number": "5", "update_origin": "CONSOLE", "parameter_group_count": 1,
    }

    def test_parameter_count_decrease_is_correctly_detected_as_medium(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "parameter_count": 3}]
        level, reason = _classify_field(prev, new, "parameter_count")
        assert level == "medium"
        assert "decreased from 10 to 3" in reason

    def test_parameter_count_increase_is_low(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "parameter_count": 15}]
        level, reason = _classify_field(prev, new, "parameter_count")
        assert level == "low"
        assert "changed from 10 to 15" in reason

    def test_condition_count_decrease_is_correctly_detected_as_medium(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "condition_count": 1}]
        level, reason = _classify_field(prev, new, "condition_count")
        assert level == "medium"
        assert "decreased from 3 to 1" in reason

    def test_update_origin_shows_real_previous_value(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "update_origin": "REST_API"}]
        _, reason = _classify_field(prev, new, "update_origin")
        assert "previously 'CONSOLE'" in reason


class TestAppCheckPrevValueHandling:
    _BASE = {
        "record_type": "firebase_app_check_config", "record_id": "proj1/app_check",
        "enforced_service_count": 5, "unenforced_service_count": 0,
        "service_count": 5, "enforced_service_names": "svc1,svc2",
    }

    def test_enforced_service_count_decrease_is_correctly_detected_as_high(self):
        """The core regression: a real enforcement REMOVAL (5 -> 2) must be
        reported as enforcement removed at high severity, not misread as
        enforcement added (the bug's previous, inverted behavior)."""
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "enforced_service_count": 2}]
        level, reason = _classify_field(prev, new, "enforced_service_count")
        assert level == "high"
        assert "removed" in reason.lower()
        assert "enforced: 5 → 2" in reason

    def test_enforced_service_count_increase_is_low(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "enforced_service_count": 8}]
        level, reason = _classify_field(prev, new, "enforced_service_count")
        assert level == "low"
        assert "added" in reason.lower()
        assert "enforced: 5 → 8" in reason

    def test_unenforced_service_count_increase_is_high(self):
        prev = [dict(self._BASE)]
        new = [{**self._BASE, "unenforced_service_count": 4}]
        level, reason = _classify_field(prev, new, "unenforced_service_count")
        assert level == "high"
        assert "increased from 0 to 4" in reason

    def test_unenforced_service_count_decrease_is_low(self):
        prev = [{**self._BASE, "unenforced_service_count": 4}]
        new = [{**self._BASE, "unenforced_service_count": 1}]
        level, reason = _classify_field(prev, new, "unenforced_service_count")
        assert level == "low"
        assert "decreased from 4 to 1" in reason
