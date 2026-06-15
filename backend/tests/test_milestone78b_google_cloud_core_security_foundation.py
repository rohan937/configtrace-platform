"""M78B — Google Cloud Core Security Foundation.

Pins the second Google Cloud arc milestone:
  * `app/services/security_rules/google_cloud.py` exists with 9 rule keys
    covering IAM policy summary, firewall rules, and Cloud Storage buckets
  * Each rule fires only on explicit, reliable normalized fields and
    refuses to read identifiers / payloads / customer data
  * Severity, confidence, and claim discipline match the spec
  * Registry / confidence / pack / coverage / catalog all stay in parity
  * Provider capability matrix flips:
      drift_risk_classification=True, security.security_rules=True
      (maturity stays "partial"; activity/correlation/demo stay False)
  * Expansion framework planned_next_stage → "M78C: Google Cloud IAM / Network
    / Storage / Runtime Risk Expansion"

These rules are configuration risks, NOT confirmed incidents — wording must say
"may", "evidence for review", and "does not confirm compromise, unauthorized
access, or data exposure", never "compromise confirmed", "secret leaked",
"data leaked", "attacker found", "breach detected", or similar.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from app.connectors.google_cloud_schema import (
    GOOGLE_CLOUD_FIREWALL_RULE,
    GOOGLE_CLOUD_IAM_POLICY_SUMMARY,
    GOOGLE_CLOUD_PROJECT,
    GOOGLE_CLOUD_STORAGE_BUCKET,
    GOOGLE_CLOUD_VPC_NETWORK,
)
from app.services.security_rules import google_cloud as gcp_rules
from app.services.security_rules.base import FindingCandidate

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"

# ── Rule key constants for use in tests ──────────────────────────────────────

_IAM_PUBLIC = "google_cloud_iam_public_member"
_IAM_BROAD_ROLE = "google_cloud_iam_broad_privileged_role"
_FW_ADMIN = "google_cloud_firewall_public_admin_ingress"
_FW_BROAD = "google_cloud_firewall_public_broad_ingress"
_FW_NO_TARGETS = "google_cloud_firewall_rule_no_targets"
_STORAGE_PAP = "google_cloud_storage_public_access_prevention_disabled"
_STORAGE_UNIFORM = "google_cloud_storage_uniform_access_disabled"
_STORAGE_VERSIONING = "google_cloud_storage_versioning_disabled"
_STORAGE_RETENTION = "google_cloud_storage_retention_not_locked"

ALL_M78B_RULE_KEYS = frozenset(
    {
        _IAM_PUBLIC,
        _IAM_BROAD_ROLE,
        _FW_ADMIN,
        _FW_BROAD,
        _FW_NO_TARGETS,
        _STORAGE_PAP,
        _STORAGE_UNIFORM,
        _STORAGE_VERSIONING,
        _STORAGE_RETENTION,
    }
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _iam_record(**over):
    base = {
        "record_type": GOOGLE_CLOUD_IAM_POLICY_SUMMARY,
        "record_id": "iam-summary-1",
        "project_id": "demo-proj-1",
        "binding_count": 3,
        "role_count": 3,
        "role_names": ["roles/storage.objectViewer"],
        "broad_role_count": 0,
        "user_member_count": 1,
        "group_member_count": 0,
        "service_account_member_count": 2,
        "domain_member_count": 0,
        "other_member_count": 0,
        "allusers_binding_present": False,
        "allauthenticatedusers_binding_present": False,
        "conditional_binding_count": 0,
    }
    base.update(over)
    return base


def _firewall_record(**over):
    base = {
        "record_type": GOOGLE_CLOUD_FIREWALL_RULE,
        "record_id": "fw-1",
        "firewall_name": "fw-1",
        "network_name": "vpc-1",
        "project_id": "demo-proj-1",
        "direction": "INGRESS",
        "priority": 1000,
        "disabled": False,
        "source_ranges_summary": ["0.0.0.0/0"],
        "destination_ranges_summary": [],
        "allowed_summary": [{"protocol": "tcp", "ports": ["22"]}],
        "denied_summary": [],
        "target_tag_count": 1,
        "target_service_account_count": 0,
        "has_log_config": False,
    }
    base.update(over)
    return base


def _bucket_record(**over):
    base = {
        "record_type": GOOGLE_CLOUD_STORAGE_BUCKET,
        "record_id": "bucket-1",
        "bucket_name": "demo-bucket-1",
        "location": "US",
        "storage_class": "STANDARD",
        "uniform_bucket_level_access_enabled": True,
        "public_access_prevention": "enforced",
        "versioning_enabled": True,
        "retention_policy_seconds": "604800",
        "retention_policy_locked": True,
        "lifecycle_rule_count": 1,
        "encryption_default_kms_key_present": False,
    }
    base.update(over)
    return base


def _keys(findings):
    return {f.rule_key for f in findings}


def _by_key(findings, rule_key):
    return [f for f in findings if f.rule_key == rule_key]


# ══════════════════════════════════════════════════════════════════════════════
# 1. Module-level contract
# ══════════════════════════════════════════════════════════════════════════════


class TestModuleContract:
    def test_evaluate_callable(self):
        assert callable(gcp_rules.evaluate)

    def test_evaluate_returns_list_for_unknown_record(self):
        assert gcp_rules.evaluate({"record_type": "not_a_record"}) == []
        assert gcp_rules.evaluate({}) == []

    def test_evaluate_ignores_non_dict(self):
        assert gcp_rules.evaluate(None) == []  # type: ignore[arg-type]
        assert gcp_rules.evaluate("string") == []  # type: ignore[arg-type]
        assert gcp_rules.evaluate(42) == []  # type: ignore[arg-type]

    def test_evaluate_ignores_project_and_vpc_records(self):
        # M78B intentionally has no rules on project / VPC network records.
        assert gcp_rules.evaluate({"record_type": GOOGLE_CLOUD_PROJECT}) == []
        assert gcp_rules.evaluate({"record_type": GOOGLE_CLOUD_VPC_NETWORK}) == []

    def test_rule_keys_frozenset_contains_m78b_keys(self):
        # M78C added more rules; M78B keys must be a subset of the full set.
        assert ALL_M78B_RULE_KEYS.issubset(gcp_rules.GOOGLE_CLOUD_RULE_KEYS)

    def test_rule_keys_count_at_least_nine(self):
        # M78B introduced 9 rules; M78C expanded the set.
        assert len(gcp_rules.GOOGLE_CLOUD_RULE_KEYS) >= 9

    def test_all_findings_carry_provider_google_cloud(self):
        # Trigger every rule and verify provider tagging.
        records = [
            _iam_record(allusers_binding_present=True),
            _iam_record(role_names=["roles/owner"], broad_role_count=1),
            _firewall_record(allowed_summary=[{"protocol": "tcp", "ports": ["3389"]}]),
            _firewall_record(allowed_summary=[{"protocol": "all", "ports": []}]),
            _firewall_record(target_tag_count=0, target_service_account_count=0),
            _bucket_record(public_access_prevention="inherited"),
            _bucket_record(uniform_bucket_level_access_enabled=False),
            _bucket_record(versioning_enabled=False),
            _bucket_record(retention_policy_locked=False, retention_policy_seconds=None),
        ]
        for rec in records:
            for f in gcp_rules.evaluate(rec):
                assert f.provider == "google_cloud"
                assert isinstance(f, FindingCandidate)


# ══════════════════════════════════════════════════════════════════════════════
# 2. IAM public member rule
# ══════════════════════════════════════════════════════════════════════════════


class TestIamPublicMember:
    def test_fires_on_allusers_sentinel(self):
        rec = _iam_record(allusers_binding_present=True)
        findings = gcp_rules.evaluate(rec)
        match = _by_key(findings, _IAM_PUBLIC)
        assert len(match) == 1
        f = match[0]
        assert f.severity == "high"
        assert f.evidence["allusers_binding_present"] is True
        assert f.evidence["project_id"] == "demo-proj-1"

    def test_fires_on_allauthenticatedusers_sentinel(self):
        rec = _iam_record(allauthenticatedusers_binding_present=True)
        findings = gcp_rules.evaluate(rec)
        match = _by_key(findings, _IAM_PUBLIC)
        assert len(match) == 1
        assert match[0].severity == "high"
        assert match[0].evidence["allauthenticatedusers_binding_present"] is True

    def test_does_not_fire_when_both_false(self):
        rec = _iam_record()
        assert _by_key(gcp_rules.evaluate(rec), _IAM_PUBLIC) == []

    def test_finding_key_includes_record_id(self):
        rec = _iam_record(allusers_binding_present=True, record_id="abc-123")
        f = _by_key(gcp_rules.evaluate(rec), _IAM_PUBLIC)[0]
        assert f.finding_key == f"{_IAM_PUBLIC}:abc-123"
        assert f.record_id == "abc-123"

    def test_evidence_excludes_member_identities(self):
        rec = _iam_record(allusers_binding_present=True)
        f = _by_key(gcp_rules.evaluate(rec), _IAM_PUBLIC)[0]
        # Forbidden identifier-like substrings — restricted to the kinds of
        # values that would betray a real email / principal id. The rule key
        # value itself legitimately contains the word "member" (e.g.
        # google_cloud_iam_public_member) so we don't check for that here.
        for forbidden in ("@", "email", "principal_id"):
            for k, v in f.evidence.items():
                if isinstance(v, str):
                    assert forbidden not in v.lower(), f"forbidden token in evidence[{k}]"

    def test_description_carries_claim_discipline(self):
        rec = _iam_record(allusers_binding_present=True)
        f = _by_key(gcp_rules.evaluate(rec), _IAM_PUBLIC)[0]
        assert "may broaden access" in f.description
        assert "does not confirm compromise" in f.description


# ══════════════════════════════════════════════════════════════════════════════
# 3. IAM broad privileged role rule
# ══════════════════════════════════════════════════════════════════════════════


class TestIamBroadPrivilegedRole:
    @pytest.mark.parametrize(
        "role",
        [
            "roles/owner",
            "roles/editor",
            "roles/iam.securityAdmin",
            "roles/resourcemanager.projectIamAdmin",
        ],
    )
    def test_fires_high_on_top_tier_broad_role(self, role):
        rec = _iam_record(role_names=[role], broad_role_count=1)
        f = _by_key(gcp_rules.evaluate(rec), _IAM_BROAD_ROLE)
        assert len(f) == 1
        assert f[0].severity == "high"
        assert role in f[0].evidence["broad_roles"]

    @pytest.mark.parametrize(
        "role",
        [
            "roles/iam.serviceAccountAdmin",
            "roles/iam.serviceAccountKeyAdmin",
        ],
    )
    def test_fires_medium_on_service_account_admin_roles(self, role):
        rec = _iam_record(role_names=[role], broad_role_count=1)
        f = _by_key(gcp_rules.evaluate(rec), _IAM_BROAD_ROLE)
        assert len(f) == 1
        assert f[0].severity == "medium"

    def test_high_wins_when_both_tiers_present(self):
        rec = _iam_record(
            role_names=["roles/owner", "roles/iam.serviceAccountAdmin"],
            broad_role_count=2,
        )
        f = _by_key(gcp_rules.evaluate(rec), _IAM_BROAD_ROLE)
        assert len(f) == 1
        assert f[0].severity == "high"
        assert "roles/owner" in f[0].evidence["broad_roles"]
        assert "roles/iam.serviceAccountAdmin" in f[0].evidence["broad_roles"]

    def test_does_not_fire_on_narrow_roles(self):
        rec = _iam_record(
            role_names=["roles/storage.objectViewer", "roles/iam.viewer"],
            broad_role_count=0,
        )
        assert _by_key(gcp_rules.evaluate(rec), _IAM_BROAD_ROLE) == []

    def test_evidence_includes_counts_not_identities(self):
        rec = _iam_record(role_names=["roles/owner"], broad_role_count=1)
        f = _by_key(gcp_rules.evaluate(rec), _IAM_BROAD_ROLE)[0]
        ev = f.evidence
        assert ev["binding_count"] == 3
        assert ev["user_member_count"] == 1
        assert ev["service_account_member_count"] == 2
        assert ev["broad_role_count"] == 1
        # No identifier-bearing keys should appear.
        forbidden_keys = {"member_emails", "principals", "user_emails", "service_account_emails"}
        assert not (forbidden_keys & set(ev.keys()))


# ══════════════════════════════════════════════════════════════════════════════
# 4. Firewall public admin ingress
# ══════════════════════════════════════════════════════════════════════════════


class TestFirewallPublicAdminIngress:
    def test_ssh_fires_high(self):
        rec = _firewall_record(allowed_summary=[{"protocol": "tcp", "ports": ["22"]}])
        f = _by_key(gcp_rules.evaluate(rec), _FW_ADMIN)
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].evidence["admin_port"] == 22

    @pytest.mark.parametrize(
        "port", [3389, 5985, 5986, 1433, 3306, 5432, 6379, 9200, 27017]
    )
    def test_db_and_admin_ports_fire_critical(self, port):
        rec = _firewall_record(
            allowed_summary=[{"protocol": "tcp", "ports": [str(port)]}]
        )
        f = _by_key(gcp_rules.evaluate(rec), _FW_ADMIN)
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].evidence["admin_port"] == port

    def test_does_not_fire_on_non_admin_port(self):
        rec = _firewall_record(
            allowed_summary=[{"protocol": "tcp", "ports": ["443"]}]
        )
        assert _by_key(gcp_rules.evaluate(rec), _FW_ADMIN) == []

    def test_does_not_fire_when_disabled(self):
        rec = _firewall_record(
            disabled=True,
            allowed_summary=[{"protocol": "tcp", "ports": ["22"]}],
        )
        assert _by_key(gcp_rules.evaluate(rec), _FW_ADMIN) == []

    def test_does_not_fire_on_non_public_source(self):
        rec = _firewall_record(
            source_ranges_summary=["10.0.0.0/8"],
            allowed_summary=[{"protocol": "tcp", "ports": ["22"]}],
        )
        assert _by_key(gcp_rules.evaluate(rec), _FW_ADMIN) == []

    def test_does_not_fire_on_egress(self):
        rec = _firewall_record(
            direction="EGRESS",
            allowed_summary=[{"protocol": "tcp", "ports": ["22"]}],
        )
        assert _by_key(gcp_rules.evaluate(rec), _FW_ADMIN) == []

    def test_critical_wins_when_both_admin_ports_present(self):
        rec = _firewall_record(
            allowed_summary=[
                {"protocol": "tcp", "ports": ["22"]},
                {"protocol": "tcp", "ports": ["3389"]},
            ]
        )
        f = _by_key(gcp_rules.evaluate(rec), _FW_ADMIN)
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].evidence["admin_port"] == 3389

    def test_ipv6_public_source_also_fires(self):
        rec = _firewall_record(
            source_ranges_summary=["::/0"],
            allowed_summary=[{"protocol": "tcp", "ports": ["22"]}],
        )
        f = _by_key(gcp_rules.evaluate(rec), _FW_ADMIN)
        assert len(f) == 1

    def test_port_range_expands_to_admin_port(self):
        # 20-25 covers SSH (22).
        rec = _firewall_record(
            allowed_summary=[{"protocol": "tcp", "ports": ["20-25"]}]
        )
        f = _by_key(gcp_rules.evaluate(rec), _FW_ADMIN)
        assert len(f) == 1
        assert f[0].evidence["admin_port"] == 22

    def test_description_carries_claim_discipline(self):
        rec = _firewall_record(allowed_summary=[{"protocol": "tcp", "ports": ["22"]}])
        f = _by_key(gcp_rules.evaluate(rec), _FW_ADMIN)[0]
        assert "may expose" in f.description
        assert "does not confirm compromise" in f.description
        # Must not over-promise reachability.
        assert "does not confirm reachability" in f.description.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 5. Firewall public broad ingress
# ══════════════════════════════════════════════════════════════════════════════


class TestFirewallPublicBroadIngress:
    def test_all_protocol_fires_critical(self):
        rec = _firewall_record(
            allowed_summary=[{"protocol": "all", "ports": []}]
        )
        f = _by_key(gcp_rules.evaluate(rec), _FW_BROAD)
        assert len(f) == 1
        assert f[0].severity == "critical"

    def test_empty_ports_list_means_all_ports(self):
        rec = _firewall_record(
            allowed_summary=[{"protocol": "tcp", "ports": []}]
        )
        f = _by_key(gcp_rules.evaluate(rec), _FW_BROAD)
        assert len(f) == 1
        assert f[0].severity == "critical"

    def test_full_port_range_fires(self):
        rec = _firewall_record(
            allowed_summary=[{"protocol": "tcp", "ports": ["0-65535"]}]
        )
        f = _by_key(gcp_rules.evaluate(rec), _FW_BROAD)
        assert len(f) == 1
        assert f[0].severity == "critical"

    def test_does_not_fire_for_narrow_port(self):
        rec = _firewall_record(
            allowed_summary=[{"protocol": "tcp", "ports": ["22"]}]
        )
        assert _by_key(gcp_rules.evaluate(rec), _FW_BROAD) == []

    def test_does_not_fire_on_non_public_source(self):
        rec = _firewall_record(
            source_ranges_summary=["10.0.0.0/8"],
            allowed_summary=[{"protocol": "all", "ports": []}],
        )
        assert _by_key(gcp_rules.evaluate(rec), _FW_BROAD) == []

    def test_does_not_fire_when_disabled(self):
        rec = _firewall_record(
            disabled=True,
            allowed_summary=[{"protocol": "all", "ports": []}],
        )
        assert _by_key(gcp_rules.evaluate(rec), _FW_BROAD) == []


# ══════════════════════════════════════════════════════════════════════════════
# 6. Firewall rule with no targets
# ══════════════════════════════════════════════════════════════════════════════


class TestFirewallRuleNoTargets:
    def test_fires_medium_when_public_ingress_with_no_targets(self):
        # tcp/443 → no broad, no admin → medium severity.
        rec = _firewall_record(
            allowed_summary=[{"protocol": "tcp", "ports": ["443"]}],
            target_tag_count=0,
            target_service_account_count=0,
        )
        f = _by_key(gcp_rules.evaluate(rec), _FW_NO_TARGETS)
        assert len(f) == 1
        assert f[0].severity == "medium"
        assert f[0].evidence["target_tag_count"] == 0
        assert f[0].evidence["target_service_account_count"] == 0

    def test_bumps_to_high_when_admin_ingress_too(self):
        rec = _firewall_record(
            allowed_summary=[{"protocol": "tcp", "ports": ["22"]}],
            target_tag_count=0,
            target_service_account_count=0,
        )
        f = _by_key(gcp_rules.evaluate(rec), _FW_NO_TARGETS)
        assert len(f) == 1
        assert f[0].severity == "high"

    def test_bumps_to_high_when_broad_ingress_too(self):
        rec = _firewall_record(
            allowed_summary=[{"protocol": "all", "ports": []}],
            target_tag_count=0,
            target_service_account_count=0,
        )
        f = _by_key(gcp_rules.evaluate(rec), _FW_NO_TARGETS)
        assert len(f) == 1
        assert f[0].severity == "high"

    def test_does_not_fire_when_target_tags_present(self):
        rec = _firewall_record(
            allowed_summary=[{"protocol": "tcp", "ports": ["443"]}],
            target_tag_count=2,
            target_service_account_count=0,
        )
        assert _by_key(gcp_rules.evaluate(rec), _FW_NO_TARGETS) == []

    def test_does_not_fire_when_target_service_accounts_present(self):
        rec = _firewall_record(
            allowed_summary=[{"protocol": "tcp", "ports": ["443"]}],
            target_tag_count=0,
            target_service_account_count=1,
        )
        assert _by_key(gcp_rules.evaluate(rec), _FW_NO_TARGETS) == []

    def test_does_not_fire_on_non_public_source(self):
        rec = _firewall_record(
            source_ranges_summary=["10.0.0.0/8"],
            target_tag_count=0,
            target_service_account_count=0,
        )
        assert _by_key(gcp_rules.evaluate(rec), _FW_NO_TARGETS) == []


# ══════════════════════════════════════════════════════════════════════════════
# 7. Storage public access prevention
# ══════════════════════════════════════════════════════════════════════════════


class TestStoragePublicAccessPrevention:
    @pytest.mark.parametrize(
        "pap",
        ["inherited", "", "unspecified", "disabled"],
    )
    def test_fires_when_not_enforced(self, pap):
        rec = _bucket_record(public_access_prevention=pap)
        f = _by_key(gcp_rules.evaluate(rec), _STORAGE_PAP)
        assert len(f) == 1

    def test_does_not_fire_when_enforced(self):
        rec = _bucket_record(public_access_prevention="enforced")
        assert _by_key(gcp_rules.evaluate(rec), _STORAGE_PAP) == []

    def test_high_severity_when_uniform_also_disabled(self):
        rec = _bucket_record(
            public_access_prevention="inherited",
            uniform_bucket_level_access_enabled=False,
        )
        f = _by_key(gcp_rules.evaluate(rec), _STORAGE_PAP)
        assert len(f) == 1
        assert f[0].severity == "high"

    def test_medium_severity_when_uniform_still_enabled(self):
        rec = _bucket_record(
            public_access_prevention="inherited",
            uniform_bucket_level_access_enabled=True,
        )
        f = _by_key(gcp_rules.evaluate(rec), _STORAGE_PAP)
        assert len(f) == 1
        assert f[0].severity == "medium"

    def test_evidence_excludes_object_contents(self):
        rec = _bucket_record(public_access_prevention="inherited")
        f = _by_key(gcp_rules.evaluate(rec), _STORAGE_PAP)[0]
        forbidden_keys = {"objects", "object_names", "object_acls", "data", "contents"}
        assert not (forbidden_keys & set(f.evidence.keys()))

    def test_description_explicitly_disclaims_object_acl_inspection(self):
        rec = _bucket_record(public_access_prevention="inherited")
        f = _by_key(gcp_rules.evaluate(rec), _STORAGE_PAP)[0]
        # The description must explicitly disclaim that ConfigTrace inspected
        # individual object ACLs / claimed objects are public.
        low = f.description.lower()
        assert "does not inspect" in low or "does not claim objects are public" in low


# ══════════════════════════════════════════════════════════════════════════════
# 8. Storage uniform access disabled
# ══════════════════════════════════════════════════════════════════════════════


class TestStorageUniformAccessDisabled:
    def test_fires_when_explicit_false(self):
        rec = _bucket_record(uniform_bucket_level_access_enabled=False)
        f = _by_key(gcp_rules.evaluate(rec), _STORAGE_UNIFORM)
        assert len(f) == 1
        assert f[0].severity == "medium"

    def test_does_not_fire_when_true(self):
        rec = _bucket_record(uniform_bucket_level_access_enabled=True)
        assert _by_key(gcp_rules.evaluate(rec), _STORAGE_UNIFORM) == []

    def test_does_not_fire_when_none(self):
        rec = _bucket_record(uniform_bucket_level_access_enabled=None)
        assert _by_key(gcp_rules.evaluate(rec), _STORAGE_UNIFORM) == []


# ══════════════════════════════════════════════════════════════════════════════
# 9. Storage versioning disabled
# ══════════════════════════════════════════════════════════════════════════════


class TestStorageVersioningDisabled:
    def test_fires_when_explicit_false(self):
        rec = _bucket_record(versioning_enabled=False)
        f = _by_key(gcp_rules.evaluate(rec), _STORAGE_VERSIONING)
        assert len(f) == 1
        assert f[0].severity == "low"

    def test_does_not_fire_when_true(self):
        rec = _bucket_record(versioning_enabled=True)
        assert _by_key(gcp_rules.evaluate(rec), _STORAGE_VERSIONING) == []

    def test_does_not_fire_when_none(self):
        rec = _bucket_record(versioning_enabled=None)
        assert _by_key(gcp_rules.evaluate(rec), _STORAGE_VERSIONING) == []


# ══════════════════════════════════════════════════════════════════════════════
# 10. Storage retention not locked
# ══════════════════════════════════════════════════════════════════════════════


class TestStorageRetentionNotLocked:
    def test_fires_medium_when_policy_set_but_unlocked(self):
        rec = _bucket_record(
            retention_policy_seconds="604800",
            retention_policy_locked=False,
        )
        f = _by_key(gcp_rules.evaluate(rec), _STORAGE_RETENTION)
        assert len(f) == 1
        assert f[0].severity == "medium"

    def test_fires_low_when_no_policy(self):
        rec = _bucket_record(
            retention_policy_seconds=None,
            retention_policy_locked=None,
        )
        f = _by_key(gcp_rules.evaluate(rec), _STORAGE_RETENTION)
        assert len(f) == 1
        assert f[0].severity == "low"

    def test_does_not_fire_when_locked(self):
        rec = _bucket_record(
            retention_policy_seconds="604800",
            retention_policy_locked=True,
        )
        assert _by_key(gcp_rules.evaluate(rec), _STORAGE_RETENTION) == []


# ══════════════════════════════════════════════════════════════════════════════
# 11. Privacy / claim discipline (cross-rule)
# ══════════════════════════════════════════════════════════════════════════════


_FORBIDDEN_CLAIM_PHRASES = [
    "compromise confirmed",
    "secret leaked",
    "secrets leaked",
    "data leaked",
    "customer data leaked",
    "payment fraud detected",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
    "orders exposed",
    "card data exposed",
]

_FORBIDDEN_PRIVACY_TOKENS = [
    # Identifiers / payloads that the connector intentionally avoids — they
    # should never appear as evidence field names or values.
    "service_account_private_key",
    "private_key",
    "access_token",
    "refresh_token",
    "authorization_header",
    "raw_request",
    "raw_response",
    "api_payload",
    "secret_value",
    "kms_key_material",
    "principal_email",
    "service_account_email",
    "user_name",
]


def _trigger_all_findings():
    records = [
        _iam_record(
            allusers_binding_present=True,
            allauthenticatedusers_binding_present=True,
            role_names=["roles/owner", "roles/iam.serviceAccountAdmin"],
            broad_role_count=2,
        ),
        _firewall_record(
            allowed_summary=[
                {"protocol": "tcp", "ports": ["22"]},
                {"protocol": "all", "ports": []},
            ],
            target_tag_count=0,
            target_service_account_count=0,
        ),
        _bucket_record(
            public_access_prevention="inherited",
            uniform_bucket_level_access_enabled=False,
            versioning_enabled=False,
            retention_policy_locked=False,
        ),
    ]
    findings = []
    for r in records:
        findings.extend(gcp_rules.evaluate(r))
    return findings


class TestClaimDisciplineAndPrivacy:
    def test_no_forbidden_claim_phrases_in_descriptions(self):
        for f in _trigger_all_findings():
            low = f.description.lower()
            for phrase in _FORBIDDEN_CLAIM_PHRASES:
                assert phrase not in low, (
                    f"forbidden claim phrase {phrase!r} in {f.rule_key}"
                )

    def test_no_forbidden_claim_phrases_in_titles(self):
        for f in _trigger_all_findings():
            low = f.title.lower()
            for phrase in _FORBIDDEN_CLAIM_PHRASES:
                assert phrase not in low

    def test_no_privacy_sensitive_evidence_field_names(self):
        for f in _trigger_all_findings():
            for k in f.evidence.keys():
                low = k.lower()
                for tok in _FORBIDDEN_PRIVACY_TOKENS:
                    assert tok not in low, (
                        f"forbidden evidence key fragment {tok!r} in "
                        f"{f.rule_key}.evidence: {k}"
                    )

    def test_no_privacy_sensitive_evidence_values(self):
        for f in _trigger_all_findings():
            for k, v in f.evidence.items():
                if isinstance(v, str):
                    low = v.lower()
                    for tok in _FORBIDDEN_PRIVACY_TOKENS:
                        assert tok not in low

    def test_every_description_carries_disclaimer(self):
        for f in _trigger_all_findings():
            assert "does not confirm compromise, unauthorized access, or data exposure" in f.description

    def test_severity_is_in_allowed_set(self):
        allowed = {"critical", "high", "medium", "low", "info"}
        for f in _trigger_all_findings():
            assert f.severity in allowed

    def test_module_docstring_mentions_privacy_constraints(self):
        src = inspect.getsource(gcp_rules)
        # Spot-check that the module docstring explicitly says the connector
        # avoids customer data and identifiers.
        for token in [
            "Customer data",
            "service-account private keys",
            "principal",
            "PII",
        ]:
            assert token in src


# ══════════════════════════════════════════════════════════════════════════════
# 12. Parity guards — registry / confidence / pack / coverage
# ══════════════════════════════════════════════════════════════════════════════


class TestRegistryParity:
    def test_all_rule_keys_in_known_rule_keys(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for k in ALL_M78B_RULE_KEYS:
            assert k in KNOWN_RULE_KEYS

    def test_all_rule_keys_in_confidence(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for k in ALL_M78B_RULE_KEYS:
            assert k in RULE_CONFIDENCE
            confidence, guard = RULE_CONFIDENCE[k]
            assert confidence in ("high", "medium")
            assert guard  # not empty

    def test_all_rule_keys_in_rule_pack(self):
        from app.services.security_rule_pack import _RULE_META
        for k in ALL_M78B_RULE_KEYS:
            assert k in _RULE_META
            provider, severity, category = _RULE_META[k]
            assert provider == "google_cloud"
            assert severity in ("critical", "high", "medium", "low")
            assert category in (
                "IAM policies",
                "Firewall rules",
                "Cloud Storage buckets",
            )

    def test_all_rule_keys_in_coverage_record_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for k in ALL_M78B_RULE_KEYS:
            assert k in RULE_RECORD_TYPES
            assert RULE_RECORD_TYPES[k]  # non-empty tuple

    def test_iam_rules_point_to_iam_summary_record(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        assert RULE_RECORD_TYPES[_IAM_PUBLIC] == ("google_cloud_iam_policy_summary",)
        assert RULE_RECORD_TYPES[_IAM_BROAD_ROLE] == ("google_cloud_iam_policy_summary",)

    def test_firewall_rules_point_to_firewall_record(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for k in (_FW_ADMIN, _FW_BROAD, _FW_NO_TARGETS):
            assert RULE_RECORD_TYPES[k] == ("google_cloud_firewall_rule",)

    def test_storage_rules_point_to_bucket_record(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for k in (_STORAGE_PAP, _STORAGE_UNIFORM, _STORAGE_VERSIONING, _STORAGE_RETENTION):
            assert RULE_RECORD_TYPES[k] == ("google_cloud_storage_bucket",)


# ══════════════════════════════════════════════════════════════════════════════
# 13. Provider evaluator dispatcher wiring
# ══════════════════════════════════════════════════════════════════════════════


class TestProviderRulesDispatcher:
    def test_google_cloud_dispatch_registered(self):
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert "google_cloud" in _PROVIDER_RULES
        assert gcp_rules.evaluate in _PROVIDER_RULES["google_cloud"]

    def test_evaluate_record_routes_to_google_cloud(self):
        from app.services.security_finding_evaluator import evaluate_record
        rec = _iam_record(allusers_binding_present=True)
        candidates = evaluate_record(rec, "google_cloud")
        keys = {c.rule_key for c in candidates}
        assert _IAM_PUBLIC in keys


# ══════════════════════════════════════════════════════════════════════════════
# 14. Capability matrix flipped on
# ══════════════════════════════════════════════════════════════════════════════


class TestCapabilityMatrix:
    def test_drift_risk_classification_true(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("google_cloud")
        assert cap is not None
        assert cap.drift.drift_risk_classification is True

    def test_security_rules_true(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("google_cloud")
        assert cap.security.security_rules is True

    def test_other_security_capabilities_still_false(self):
        """M78D landed activity ingestion; signals/correlation/demo still deferred."""
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("google_cloud")
        assert cap.security.activity_ingestion is True  # M78D complete
        assert cap.security.activity_signals is True  # M78E complete
        assert cap.security.risk_activity_correlations is False
        assert cap.security.demo_seed_clear is False
        assert cap.security.case_report is False
        assert cap.security.evidence_timeline is False
        assert cap.security.evidence_graph is False

    def test_maturity_still_partial(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("google_cloud")
        assert cap.maturity == "partial"

    def test_google_cloud_still_in_partial_list(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES_PARTIAL,
        )
        providers = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        assert "google_cloud" in providers

    def test_notes_describe_security_foundation(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("google_cloud")
        # The notes should reference the security foundation lighting up.
        assert "security" in cap.notes.lower()
        # And should NOT pretend GCP is now full-stack.
        assert "complete" not in cap.notes.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 15. Expansion framework rolled forward
# ══════════════════════════════════════════════════════════════════════════════


class TestExpansionFramework:
    def test_planned_next_stage_is_beyond_m78c(self):
        """M78C is complete; planned next stage must now point to M78D or later."""
        from app.services import provider_expansion_framework as svc
        fw = svc.get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "M78" in stage
        assert "M78C" not in stage  # M78C done; pointer advanced

    def test_planned_next_stage_is_beyond_m78d(self):
        """M78D is complete; planned next stage must be M78E or later."""
        from app.services import provider_expansion_framework as svc
        fw = svc.get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "M78" in stage
        assert "M78D" not in stage  # M78D done; pointer advanced


# ══════════════════════════════════════════════════════════════════════════════
# 16. Frontend catalog
# ══════════════════════════════════════════════════════════════════════════════


class TestFrontendCatalog:
    def test_catalog_file_exists(self):
        assert FE_CATALOG.exists()

    def test_all_rule_keys_present_in_catalog(self):
        text = FE_CATALOG.read_text()
        for k in ALL_M78B_RULE_KEYS:
            assert f'"{k}"' in text, f"missing catalog entry for {k}"

    def test_catalog_marks_google_cloud_provider(self):
        text = FE_CATALOG.read_text()
        # Each GCP rule must be tagged provider: "google_cloud" near its key.
        for k in ALL_M78B_RULE_KEYS:
            # Match the slice of text from this rule key down 30 lines.
            idx = text.find(f'"{k}"')
            assert idx >= 0
            section = text[idx : idx + 600]
            assert 'provider: "google_cloud"' in section

    def test_catalog_uses_only_known_categories(self):
        text = FE_CATALOG.read_text()
        # Ensure each of our 3 category labels appears at least once.
        for cat in ("IAM policies", "Firewall rules", "Cloud Storage buckets"):
            assert f'category: "{cat}"' in text


# ══════════════════════════════════════════════════════════════════════════════
# 17. Cross-record / regression smoke
# ══════════════════════════════════════════════════════════════════════════════


class TestCrossRecordSmoke:
    def test_clean_iam_record_emits_nothing(self):
        assert gcp_rules.evaluate(_iam_record()) == []

    def test_clean_firewall_record_emits_nothing(self):
        # Public source + SSH still fires admin — make it truly clean.
        rec = _firewall_record(
            source_ranges_summary=["10.0.0.0/8"],
            allowed_summary=[{"protocol": "tcp", "ports": ["443"]}],
            target_tag_count=1,
        )
        assert gcp_rules.evaluate(rec) == []

    def test_clean_bucket_record_emits_nothing(self):
        assert gcp_rules.evaluate(_bucket_record()) == []

    def test_multiple_rules_can_co_emit_on_one_bucket(self):
        rec = _bucket_record(
            public_access_prevention="inherited",
            uniform_bucket_level_access_enabled=False,
            versioning_enabled=False,
            retention_policy_locked=False,
        )
        keys = _keys(gcp_rules.evaluate(rec))
        assert _STORAGE_PAP in keys
        assert _STORAGE_UNIFORM in keys
        assert _STORAGE_VERSIONING in keys
        assert _STORAGE_RETENTION in keys

    def test_per_firewall_findings_are_at_most_three(self):
        # Worst case: broad + admin + no-targets → 3 distinct findings, never more.
        rec = _firewall_record(
            allowed_summary=[
                {"protocol": "tcp", "ports": ["22"]},
                {"protocol": "all", "ports": []},
            ],
            target_tag_count=0,
            target_service_account_count=0,
        )
        findings = gcp_rules.evaluate(rec)
        rule_keys = [f.rule_key for f in findings]
        assert sorted(rule_keys) == sorted([_FW_ADMIN, _FW_BROAD, _FW_NO_TARGETS])

    def test_finding_key_format_is_stable(self):
        rec = _firewall_record(
            record_id="fw-xyz",
            allowed_summary=[{"protocol": "tcp", "ports": ["22"]}],
        )
        f = _by_key(gcp_rules.evaluate(rec), _FW_ADMIN)[0]
        assert f.finding_key == f"{_FW_ADMIN}:fw-xyz"
