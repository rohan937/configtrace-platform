"""Kubernetes Change unknown/missing-evidence regression tests
(Kubernetes message 7 of 9).

Every risky Boolean/numeric predicate in risk_rules/kubernetes.py must never
describe an unknown (``None``/non-int) value as an explicit risky or safe
state. This file is the permanent regression guard for that discipline —
including the 20 numeric "unknown silently became zero" sites fixed in this
message (the ``(nv or 0)`` / ``(pv or 0)`` pattern, replaced with
``_count_transition()``/``_as_int()``).
"""

from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace as NS

from app.services.diff_service import compute_diff
from app.services.risk_rules import kubernetes as k8s_risk
from app.services.risk_rules.kubernetes import classify_kubernetes_change

from tests.test_kubernetes_change_classification import (
    _container_ctx,
    _deployment,
    _diff,
    _find,
    _governance,
    _network_policy,
    _psa,
    _service,
    _subject_binding,
    _webhook,
)


def _classify(change: dict) -> tuple[str, str]:
    return classify_kubernetes_change(change)


# ═══════════════════════ Stale-field-name regression guard ═════════════════


class TestStaleFieldNameGuard:
    """Permanent regression guard: the Kubernetes classifier module must
    only ever read the real Change model's ``prev_value``/``new_value``
    attributes — never the stale ``old_value``/``previous_value``/
    ``prior_value`` names used by no real Change shape."""

    def test_no_stale_field_names_in_source(self):
        src = Path(inspect.getfile(k8s_risk)).read_text()
        for stale in ("old_value", "previous_value", "prior_value"):
            assert stale not in src, f"stale field name {stale!r} found in risk_rules/kubernetes.py"

    def test_classifier_reads_real_change_model_attribute_names(self):
        from app.models.change import Change
        assert hasattr(Change, "prev_value")
        assert hasattr(Change, "new_value")
        assert not hasattr(Change, "old_value")
        assert not hasattr(Change, "previous_value")


# ═══════════════════════ Boolean unknown audit ══════════════════════════════


class TestWorkloadBooleanUnknowns:
    def test_privileged_none_never_fires_high(self):
        prev = [_container_ctx(privileged=False)]
        new = [_container_ctx(privileged=None)]
        c = _find(_diff(prev, new), field_path="privileged")
        sev, _ = _classify(c)
        assert sev == "low"

    def test_allow_privilege_escalation_none_never_fires_medium(self):
        prev = [_container_ctx(allow_privilege_escalation=False)]
        new = [_container_ctx(allow_privilege_escalation=None)]
        c = _find(_diff(prev, new), field_path="allow_privilege_escalation")
        assert _classify(c)[0] == "low"

    def test_run_as_non_root_none_never_fires_high(self):
        prev = [_container_ctx(run_as_non_root=True)]
        new = [_container_ctx(run_as_non_root=None)]
        c = _find(_diff(prev, new), field_path="run_as_non_root")
        assert _classify(c)[0] == "low"

    def test_read_only_root_filesystem_none_never_fires_medium(self):
        prev = [_container_ctx(read_only_root_filesystem=True)]
        new = [_container_ctx(read_only_root_filesystem=None)]
        c = _find(_diff(prev, new), field_path="read_only_root_filesystem")
        assert _classify(c)[0] == "low"

    def test_automount_none_never_fires_medium(self):
        prev = [_deployment(automount_service_account_token=True)]
        new = [_deployment(automount_service_account_token=None)]
        c = _find(_diff(prev, new), field_path="automount_service_account_token")
        assert _classify(c)[0] == "low"


class TestNetworkBooleanUnknowns:
    def test_service_exposure_unknown_never_treated_as_external(self):
        prev = [_service(exposure_category="cluster_internal")]
        new = [_service(exposure_category="unknown")]
        c = _find(_diff(prev, new), field_path="exposure_category")
        sev, _ = _classify(c)
        assert sev != "high"

    def test_network_policy_allows_all_none_never_fires_critical(self):
        # allows_all_ingress is a plain bool in the schema, but the
        # classifier's equality check (`if nv:`) must not treat a
        # non-boolean/None as truthy.
        prev = [_network_policy(allows_all_ingress=False)]
        new = [_network_policy(allows_all_ingress=None)]
        c = _find(_diff(prev, new), field_path="allows_all_ingress")
        assert _classify(c)[0] != "critical"


class TestAdmissionBooleanUnknowns:
    def test_ca_bundle_none_is_not_treated_as_present(self):
        prev = [_webhook(ca_bundle_present=True)]
        new = [_webhook(ca_bundle_present=None)]
        c = _find(_diff(prev, new), field_path="ca_bundle_present")
        sev, msg = _classify(c)
        # None is not "True" so the low/"configured" branch must not fire;
        # it falls into the else (medium, "removed") branch, which is safe
        # (treats unknown as "not confirmed present", never claims restored).
        assert "configured" not in msg or sev != "low"

    def test_wildcard_resource_none_never_fires_high(self):
        prev = [_webhook(wildcard_resource=False)]
        new = [_webhook(wildcard_resource=None)]
        c = _find(_diff(prev, new), field_path="wildcard_resource")
        assert _classify(c)[0] == "low"

    def test_plaintext_http_client_none_never_fires_high(self):
        prev = [_webhook(plaintext_http_client=False)]
        new = [_webhook(plaintext_http_client=None)]
        c = _find(_diff(prev, new), field_path="plaintext_http_client")
        assert _classify(c)[0] == "low"


class TestPsaGovernanceUnknowns:
    def test_psa_enforce_level_unknown_does_not_claim_weakened(self):
        prev = [_psa(enforce_level="restricted")]
        new = [_psa(enforce_level="some_unrecognized_future_value")]
        c = _find(_diff(prev, new), field_path="enforce_level")
        sev, _ = _classify(c)
        # Falls to the safe "medium: enforce level changed" catch-all — never
        # silently high (weakened) nor low (strengthened) without evidence.
        assert sev == "medium"

    def test_collection_partial_never_becomes_explicit_risky_claim(self):
        prev = [_psa(collection_completeness_category="complete")]
        new = [_psa(collection_completeness_category="partial")]
        c = _find(_diff(prev, new), field_path="collection_completeness_category")
        sev, msg = _classify(c)
        assert sev == "medium"
        assert "partial" in msg.lower() or "visibility" in msg.lower()

    def test_governance_privileged_workload_none_never_fires_medium(self):
        prev = [_governance(privileged_workload_present=False)]
        new = [_governance(privileged_workload_present=None)]
        c = _find(_diff(prev, new), field_path="privileged_workload_present")
        assert _classify(c)[0] == "low"


class TestRbacUnknowns:
    def test_cluster_admin_binding_none_never_fires_critical(self):
        prev = [_subject_binding(cluster_admin_binding=False)]
        new = [_subject_binding(cluster_admin_binding=None)]
        c = _find(_diff(prev, new), field_path="cluster_admin_binding")
        assert _classify(c)[0] != "critical"

    def test_role_resolution_unresolved_is_medium_not_low_not_high(self):
        prev = [_subject_binding(role_resolution_status="resolved", resolved_privilege_category="low")]
        new = [_subject_binding(role_resolution_status="unresolved", resolved_privilege_category="unknown")]
        changes = _diff(prev, new)
        c = _find(changes, field_path="role_resolution_status")
        sev, _ = _classify(c)
        assert sev == "medium"


# ═══════════════════════ Numeric unknown audit (the 20 fixed sites) ════════


def _int_field_change(record_builder, field: str, prev_val, new_val, **shared):
    prev = [record_builder(**{field: prev_val, **shared})]
    new = [record_builder(**{field: new_val, **shared})]
    return _find(_diff(prev, new), field_path=field)


class TestNumericUnknownNeverBecomesZero:
    """For every numeric field fixed in this message: an unknown (None) value
    on either side of the transition must never be silently treated as 0,
    which would misreport an unknown state as an increase or decrease."""

    def test_privileged_container_count_unknown_new_value(self):
        c = _int_field_change(_deployment, "privileged_container_count", 2, None)
        sev, msg = _classify(c)
        assert sev == "low"
        assert "could not be safely compared" in msg

    def test_privileged_container_count_unknown_prev_value(self):
        c = _int_field_change(_deployment, "privileged_container_count", None, 2)
        sev, msg = _classify(c)
        assert sev == "low"
        assert "could not be safely compared" in msg

    def test_privileged_container_count_real_increase_still_high(self):
        c = _int_field_change(_deployment, "privileged_container_count", 0, 1)
        assert _classify(c)[0] == "high"

    def test_privileged_container_count_real_decrease_still_low(self):
        c = _int_field_change(_deployment, "privileged_container_count", 1, 0)
        assert _classify(c)[0] == "low"

    def test_privileged_container_count_exact_zero_distinct_from_none(self):
        # Exact zero on both sides never happens (compute_diff only fires on
        # differing values) but 0 -> explicit non-zero must still work.
        c = _int_field_change(_deployment, "privileged_container_count", 0, 2)
        assert _classify(c)[0] == "high"

    def test_root_container_count_unknown(self):
        c = _int_field_change(_deployment, "root_container_count", 1, None)
        assert _classify(c)[0] == "low"
        assert "compared" in _classify(c)[1]

    def test_allow_privilege_escalation_count_unknown(self):
        c = _int_field_change(_deployment, "allow_privilege_escalation_count", 1, None)
        assert _classify(c)[0] == "low"

    def test_host_port_count_unknown(self):
        c = _int_field_change(_container_ctx, "host_port_count", 1, None)
        assert _classify(c)[0] == "low"

    def test_hostpath_mount_count_unknown(self):
        c = _int_field_change(_container_ctx, "hostpath_mount_count", 1, None)
        assert _classify(c)[0] == "low"

    def test_service_load_balancer_ingress_count_unknown(self):
        c = _int_field_change(_service, "load_balancer_ingress_count", 1, None)
        sev, msg = _classify(c)
        assert sev == "low"
        assert "compared" in msg

    def test_service_external_ip_count_unknown(self):
        c = _int_field_change(_service, "external_ip_count", 1, None)
        assert _classify(c)[0] == "low"

    def test_network_policy_broad_cidr_count_unknown(self):
        c = _int_field_change(_network_policy, "broad_cidr_count", 1, None)
        assert _classify(c)[0] == "low"

    def test_webhook_timeout_seconds_unknown(self):
        c = _int_field_change(_webhook, "timeout_seconds", 10, None)
        sev, msg = _classify(c)
        assert sev == "low"
        assert "could not be safely compared" in msg

    def test_webhook_timeout_seconds_real_decrease_still_medium(self):
        c = _int_field_change(_webhook, "timeout_seconds", 10, 3)
        assert _classify(c)[0] == "medium"

    def test_webhook_timeout_seconds_real_increase_still_low(self):
        c = _int_field_change(_webhook, "timeout_seconds", 3, 10)
        assert _classify(c)[0] == "low"

    def test_count_transition_helper_treats_bool_as_unknown(self):
        # Defensive: bool is an int subclass in Python; _as_int must reject
        # it so a stray boolean never masquerades as a count of 0/1.
        assert k8s_risk._as_int(True) is None
        assert k8s_risk._as_int(False) is None
        assert k8s_risk._as_int(0) == 0
        assert k8s_risk._as_int(3) == 3
        assert k8s_risk._as_int(None) is None
        assert k8s_risk._as_int("3") is None
