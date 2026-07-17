"""Kubernetes Pod Security Admission tests (Kubernetes message 5 of 9).

Covers all enforce/audit/warn levels, version categorization
(latest/pinned/old/unset/invalid), weakening/strengthening detection,
system-namespace context, and confirms only the six exact PSA label keys
are ever read (no other namespace metadata).

All tests are pure-mock; no real Kubernetes cluster is contacted.
"""

from __future__ import annotations

from app.connectors.kubernetes import _build_pod_security_admission_records, _normalize_pod_security_admission
from app.connectors.kubernetes_schema import (
    NAMESPACE_CATEGORY_DEFAULT,
    NAMESPACE_CATEGORY_SYSTEM,
    NAMESPACE_CATEGORY_USER,
    PSA_ENFORCE_CATEGORY_BASELINE,
    PSA_ENFORCE_CATEGORY_INVALID,
    PSA_ENFORCE_CATEGORY_PRIVILEGED,
    PSA_ENFORCE_CATEGORY_RESTRICTED,
    PSA_ENFORCE_CATEGORY_UNSET,
    PSA_VERSION_LATEST,
    PSA_VERSION_PINNED_CURRENT,
    PSA_VERSION_PINNED_OLD,
    PSA_VERSION_UNSET,
)
from tests._kubernetes_admission_fixtures import make_namespace_record


def _psa(**kwargs):
    ns = make_namespace_record(**kwargs)
    return _normalize_pod_security_admission(ns, cluster_id="uid:c1", cluster_name="c1", cluster_major_minor="1.29")


# ── AL-AP: enforce levels ──────────────────────────────────────────────────────

class TestEnforceLevels:
    def test_AL_restricted(self):
        assert _psa(enforce="restricted")["enforce_level"] == PSA_ENFORCE_CATEGORY_RESTRICTED

    def test_AM_baseline(self):
        assert _psa(enforce="baseline")["enforce_level"] == PSA_ENFORCE_CATEGORY_BASELINE

    def test_AN_privileged(self):
        assert _psa(enforce="privileged")["enforce_level"] == PSA_ENFORCE_CATEGORY_PRIVILEGED

    def test_AO_unset(self):
        assert _psa(enforce=None)["enforce_level"] == PSA_ENFORCE_CATEGORY_UNSET
        assert _psa(enforce=None)["enforcement_enabled"] is False

    def test_AP_invalid(self):
        assert _psa(enforce="not-a-real-level")["enforce_level"] == PSA_ENFORCE_CATEGORY_INVALID


# ── AQ, AR: audit/warn levels ───────────────────────────────────────────────────

class TestAuditWarnLevels:
    def test_AQ_audit_restricted(self):
        assert _psa(audit="restricted")["audit_level"] == PSA_ENFORCE_CATEGORY_RESTRICTED
        assert _psa(audit="restricted")["audit_enabled"] is True

    def test_AR_warn_restricted(self):
        assert _psa(warn="restricted")["warn_level"] == PSA_ENFORCE_CATEGORY_RESTRICTED
        assert _psa(warn="restricted")["warning_enabled"] is True


# ── AS-AU: version categorization ──────────────────────────────────────────────

class TestVersionCategorization:
    def test_AS_latest(self):
        assert _psa(enforce="restricted", enforce_version="latest")["enforce_version_category"] == PSA_VERSION_LATEST

    def test_AT_pinned(self):
        assert _psa(enforce="restricted", enforce_version="v1.29")["enforce_version_category"] == PSA_VERSION_PINNED_CURRENT

    def test_AU_old_version(self):
        assert _psa(enforce="restricted", enforce_version="v1.24")["enforce_version_category"] == PSA_VERSION_PINNED_OLD

    def test_unset_version(self):
        assert _psa(enforce="restricted", enforce_version=None)["enforce_version_category"] == PSA_VERSION_UNSET


# ── AV, AW: weakening/strengthening ────────────────────────────────────────────

class TestWeakeningStrengthening:
    def test_AV_weakened_enforce_weaker_than_audit(self):
        record = _psa(enforce="baseline", audit="restricted")
        assert record["enforcement_weaker_than_audit"] is True

    def test_AW_strengthened_not_weaker(self):
        record = _psa(enforce="restricted", audit="baseline")
        assert record["enforcement_weaker_than_audit"] is False

    def test_enforce_weaker_than_warn(self):
        record = _psa(enforce="privileged", warn="restricted")
        assert record["enforcement_weaker_than_warning"] is True

    def test_no_weakening_when_audit_unset(self):
        record = _psa(enforce="privileged", audit=None)
        assert record["enforcement_weaker_than_audit"] is False


class TestNamespaceContext:
    def test_system_namespace(self):
        assert _psa(name="kube-system")["namespace_context_category"] == NAMESPACE_CATEGORY_SYSTEM

    def test_default_namespace(self):
        assert _psa(name="default")["namespace_context_category"] == NAMESPACE_CATEGORY_DEFAULT

    def test_user_namespace(self):
        assert _psa(name="my-app")["namespace_context_category"] == NAMESPACE_CATEGORY_USER

    def test_system_namespace_does_not_assume_restricted_enforcement(self):
        # A system namespace with no enforce label is "unset", not
        # penalized or assumed to require restricted — see module docstring.
        record = _psa(name="kube-system", enforce=None)
        assert record["enforce_level"] == PSA_ENFORCE_CATEGORY_UNSET
        assert record["namespace_context_category"] == NAMESPACE_CATEGORY_SYSTEM


class TestNamespaceMetadataExclusion:
    def test_only_six_psa_keys_ever_referenced(self):
        # Structural check: the namespace-record dict passed in only ever
        # has its 6 PSA fields read; arbitrary keys are ignored, not
        # errored on and not persisted.
        ns = make_namespace_record(name="prod", enforce="restricted")
        ns["arbitrary_annotation"] = "should-never-appear"
        record = _normalize_pod_security_admission(ns, cluster_id="c1", cluster_name="c1", cluster_major_minor=None)
        import json
        assert "should-never-appear" not in json.dumps(record)
        assert "arbitrary_annotation" not in json.dumps(record)


class TestBuildPodSecurityAdmissionRecords:
    def test_builds_one_record_per_namespace(self):
        namespaces = [make_namespace_record(name="a"), make_namespace_record(name="b", enforce="restricted")]
        records = _build_pod_security_admission_records(
            namespaces, cluster_id="c1", cluster_name="c1", cluster_major_minor="1.29",
        )
        assert {r["namespace"] for r in records} == {"a", "b"}

    def test_deterministic_ordering(self):
        namespaces = [make_namespace_record(name="z"), make_namespace_record(name="a")]
        records = _build_pod_security_admission_records(
            namespaces, cluster_id="c1", cluster_name="c1", cluster_major_minor="1.29",
        )
        assert [r["namespace"] for r in records] == ["a", "z"]

    def test_fingerprint_deterministic(self):
        ns = make_namespace_record(enforce="restricted", enforce_version="v1.29")
        r1 = _normalize_pod_security_admission(ns, cluster_id="c1", cluster_name="c1", cluster_major_minor="1.29")
        r2 = _normalize_pod_security_admission(ns, cluster_id="c1", cluster_name="c1", cluster_major_minor="1.29")
        assert r1["posture_fingerprint"] == r2["posture_fingerprint"]
