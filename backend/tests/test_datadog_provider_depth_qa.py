"""Datadog provider depth QA.

Durable, mostly-static guardrails that pin the full Datadog rule taxonomy
across every registration surface, validate the privacy / claim-discipline
invariants for the Datadog provider, and — most importantly — assert the
central-evaluator wiring that makes Datadog rules actually fire during
snapshot evaluation.

  TestDatadogRuleRegistration        — all 31 Datadog rule keys present in the
                                       module export, registry, confidence map,
                                       rule pack, and coverage service.
  TestDatadogFrontendCatalogParity   — all 31 keys appear in the TypeScript
                                       securityRuleCatalog.ts with matching
                                       severities and provider.
  TestDatadogEvidenceSafety          — fired-rule evidence carries no secret /
                                       token / PII / raw-URL keys.
  TestDatadogCopySafety              — rule copy carries no forbidden
                                       (breach-style) wording.
  TestDatadogEvaluatorDispatch       — "datadog" is wired into the central
                                       evaluator and produces findings through
                                       it (webhook-no-secret-headers High,
                                       non-https-endpoint High, dashboard
                                       public-url Medium), and a healthy webhook
                                       fires none of the High rules.
  TestDatadogExpansionFramework      — expansion framework points at M89A
                                       Kubernetes.
  TestDatadogProviderCapabilityMatrix — Datadog is implemented (partial) with
                                       security_rules=True; Kubernetes is not yet
                                       implemented and has no connector file.

Pure unit tests: the registry / catalog / copy / severity / dispatch checks
read Python dicts and the TypeScript catalog as text and require no database
connection.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import Any

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend" / "app"
FRONTEND = REPO_ROOT / "frontend" / "src"

DATADOG_RULES_FILE = BACKEND / "services" / "security_rules" / "datadog.py"
FE_RULE_CATALOG = FRONTEND / "lib" / "securityRuleCatalog.ts"

CANONICAL_PROVIDER = "datadog"

# ── Canonical Datadog rule set (the 31 shipped rules, M82B + M82C) ────────────

DATADOG_RULE_KEYS = [
    # Monitor (M82B)
    "datadog_monitor_disabled",
    "datadog_monitor_unrestricted_roles",
    "datadog_monitor_notify_no_data_disabled",
    "datadog_monitor_long_query",
    # Monitor (M82C expansion)
    "datadog_monitor_no_notifications",
    "datadog_monitor_message_template_present",
    "datadog_monitor_no_warning_threshold",
    "datadog_monitor_no_recovery_threshold",
    "datadog_monitor_silenced_scopes_present",
    "datadog_monitor_notify_audit_disabled",
    "datadog_monitor_require_full_window_disabled",
    "datadog_monitor_query_wildcard_scope",
    "datadog_monitor_broad_group_by",
    "datadog_monitor_long_no_data_timeframe",
    # SLO
    "datadog_slo_no_monitors",
    "datadog_slo_low_target",
    # Dashboard
    "datadog_dashboard_public_url_present",
    "datadog_dashboard_unrestricted_roles",
    # Webhook integration (M82B)
    "datadog_webhook_without_secret_headers",
    "datadog_webhook_payload_template_present",
    # Webhook integration (M82C expansion)
    "datadog_webhook_custom_headers_without_secret_headers",
    "datadog_webhook_large_payload_template",
    "datadog_webhook_auth_material_present",
    "datadog_webhook_non_https_endpoint",
    # Notification integration
    "datadog_notification_integration_no_channels",
    # Application key
    "datadog_application_key_broad_scopes",
    # API key
    "datadog_api_key_disabled",
    # Role
    "datadog_role_high_permission_count",
    # Team
    "datadog_team_no_members",
    # Cloud integration
    "datadog_cloud_integration_broad_collection",
    "datadog_cloud_integration_log_collection_enabled",
]

ALL_DATADOG_RULE_KEYS: frozenset[str] = frozenset(DATADOG_RULE_KEYS)

# Forbidden claim wording — never in Datadog rule code or user-facing copy.
FORBIDDEN_PHRASES = [
    "breach confirmed",
    "compromise confirmed",
    "attacker found",
    "someone has access",
    "data leaked",
    "secret leaked",
    "secrets exposed",
    "customer data exposed",
    "unauthorized access confirmed",
    "monitoring data exposed",
    "incident data exposed",
    "credentials exposed",
    "tokens leaked",
    "attack detected",
    "fraud detected",
]

# Evidence dicts must never carry secret-bearing / PII-bearing / raw-value keys.
FORBIDDEN_EVIDENCE_KEYS = [
    "api_key",
    "application_key",
    "app_key",
    "secret",
    "token",
    "bearer",
    "authorization",
    "url",
    "webhook_url",
    "custom_headers",
    "secret_headers",
    "payload",
    "payload_template",
    "query",
    "message",
    "account_id",
    "project_id",
    "tenant_id",
    "subscription_id",
    "email",
    "user_id",
    "user_name",
    "handle",
    "last4",
    "raw_payload",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rule_key(f: Any) -> str:
    return f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")


def _evidence(f: Any) -> dict:
    ev = f.evidence if hasattr(f, "evidence") else f.get("evidence", {})
    return ev if isinstance(ev, dict) else {}


def _title(f: Any) -> str:
    return (f.title if hasattr(f, "title") else f.get("title", "")) or ""


def _description(f: Any) -> str:
    return (f.description if hasattr(f, "description") else f.get("description", "")) or ""


def _datadog_eval(record: dict) -> list[Any]:
    from app.services.security_rules.datadog import evaluate
    return evaluate(record)


# ── Representative risky records (field names mirror datadog_schema, M82A-C) ──

def _risky_webhook_no_secret_headers() -> dict:
    """Webhook with an HTTPS URL but no secret headers → High rule fires."""
    from app.connectors.datadog_schema import DATADOG_WEBHOOK_INTEGRATION
    return {
        "record_type": DATADOG_WEBHOOK_INTEGRATION,
        "provider": "datadog",
        "record_id": "datadog-depth-webhook",
        "resource_id": "datadog-depth-webhook",
        "resource_name": "datadog-depth-webhook",
        "url_present": True,
        "url_scheme_category": "https",
        "custom_headers_present": False,
        "custom_header_count": 0,
        "auth_material_present": False,
        "payload_template_present": False,
        "payload_template_length_category": "absent",
        "secret_headers_present": False,
        "secret_headers_count": 0,
        "encode_as_category": "json",
    }


def _risky_webhook_http_endpoint() -> dict:
    """Webhook configured over plain HTTP → High non-https rule fires."""
    from app.connectors.datadog_schema import DATADOG_WEBHOOK_INTEGRATION
    return {
        "record_type": DATADOG_WEBHOOK_INTEGRATION,
        "provider": "datadog",
        "record_id": "datadog-depth-webhook-http",
        "resource_id": "datadog-depth-webhook-http",
        "resource_name": "datadog-depth-webhook-http",
        "url_present": True,
        "url_scheme_category": "http",
        "custom_headers_present": True,
        "custom_header_count": 1,
        "auth_material_present": True,
        "payload_template_present": True,
        "payload_template_length_category": "long",
        "secret_headers_present": False,
        "secret_headers_count": 0,
        "encode_as_category": "json",
    }


def _healthy_webhook() -> dict:
    """Properly configured webhook → none of the High webhook rules fire."""
    from app.connectors.datadog_schema import DATADOG_WEBHOOK_INTEGRATION
    return {
        "record_type": DATADOG_WEBHOOK_INTEGRATION,
        "provider": "datadog",
        "record_id": "datadog-depth-webhook-healthy",
        "resource_id": "datadog-depth-webhook-healthy",
        "resource_name": "datadog-depth-webhook-healthy",
        "url_present": True,
        "url_scheme_category": "https",
        "custom_headers_present": False,
        "custom_header_count": 0,
        "auth_material_present": False,
        "payload_template_present": False,
        "payload_template_length_category": "absent",
        "secret_headers_present": True,
        "secret_headers_count": 1,
        "encode_as_category": "json",
    }


def _risky_dashboard_public_url() -> dict:
    """Dashboard with a public sharing URL → Medium rule fires."""
    from app.connectors.datadog_schema import DATADOG_DASHBOARD
    return {
        "record_type": DATADOG_DASHBOARD,
        "provider": "datadog",
        "record_id": "datadog-depth-dashboard",
        "resource_id": "datadog-depth-dashboard",
        "resource_name": "Depth Dashboard",
        "layout_type": "ordered",
        "widget_count": 5,
        "template_variable_count": 0,
        "restricted_roles_count": 2,
        "public_url_present": True,
        "description_present": False,
        "description_length_category": "absent",
    }


def _all_datadog_findings() -> list[Any]:
    """Fire a broad set of Datadog rules across representative risky records.

    Field names mirror the canonical connector-normalizer schema consumed by
    ``security_rules.datadog.evaluate`` (M82A/M82C).
    """
    from app.connectors.datadog_schema import (
        DATADOG_API_KEY_METADATA,
        DATADOG_APPLICATION_KEY_METADATA,
        DATADOG_CLOUD_INTEGRATION,
        DATADOG_MONITOR,
        DATADOG_NOTIFICATION_INTEGRATION,
        DATADOG_ROLE,
        DATADOG_SLO,
        DATADOG_TEAM,
    )

    records: list[dict] = [
        # Monitor: disabled, unrestricted, no notify-no-data, long query, no
        # routing, message template, critical-no-warning, critical-no-recovery,
        # silenced scopes, notify-audit off, require-full-window off, wildcard
        # scope, broad group-by, extended no-data timeframe.
        {
            "record_type": DATADOG_MONITOR,
            "record_id": "datadog-depth-monitor",
            "resource_id": "datadog-depth-monitor",
            "monitor_type": "metric alert",
            "enabled": False,
            "restricted_roles_count": 0,
            "notify_no_data": False,
            "query_present": True,
            "query_complexity_category": "long",
            "query_uses_wildcard_scope": True,
            "query_group_by_count": 4,
            "notification_routing_present": False,
            "notification_count": 0,
            "message_template_present": True,
            "threshold_critical_present": True,
            "threshold_warning_present": False,
            "threshold_recovery_present": False,
            "silenced_scope_count": 2,
            "notify_audit": False,
            "require_full_window": False,
            "no_data_timeframe_category": "extended",
        },
        # SLO: monitor-based with no monitors + below-95 target.
        {
            "record_type": DATADOG_SLO,
            "record_id": "datadog-depth-slo",
            "resource_id": "datadog-depth-slo",
            "slo_type": "monitor",
            "monitor_count": 0,
            "target_category": "below_95",
        },
        # Dashboard: public URL + unrestricted roles.
        {
            "record_type": "datadog_dashboard",
            "record_id": "datadog-depth-dashboard-2",
            "resource_id": "datadog-depth-dashboard-2",
            "public_url_present": True,
            "restricted_roles_count": 0,
        },
        # Webhook: HTTP endpoint, custom headers w/o secret, large template,
        # auth material, no secret headers.
        _risky_webhook_http_endpoint(),
        # Webhook: HTTPS but no secret headers (High).
        _risky_webhook_no_secret_headers(),
        # Notification integration: enabled with no channels/handles.
        {
            "record_type": DATADOG_NOTIFICATION_INTEGRATION,
            "record_id": "datadog_notif_slack",
            "resource_id": "datadog_notif_slack",
            "integration_type": "slack",
            "enabled": True,
            "handle_count": 0,
            "channel_count": 0,
        },
        # Application key: broad scopes.
        {
            "record_type": DATADOG_APPLICATION_KEY_METADATA,
            "record_id": "datadog-depth-appkey",
            "resource_id": "datadog-depth-appkey",
            "scopes_count": 25,
        },
        # API key: disabled.
        {
            "record_type": DATADOG_API_KEY_METADATA,
            "record_id": "datadog-depth-apikey",
            "resource_id": "datadog-depth-apikey",
            "disabled": True,
        },
        # Role: high permission count.
        {
            "record_type": DATADOG_ROLE,
            "record_id": "datadog-depth-role",
            "resource_id": "datadog-depth-role",
            "permission_count": 50,
        },
        # Team: no members.
        {
            "record_type": DATADOG_TEAM,
            "record_id": "datadog-depth-team",
            "resource_id": "datadog-depth-team",
            "member_count": 0,
        },
        # Cloud integration: all collection types + log collection.
        {
            "record_type": DATADOG_CLOUD_INTEGRATION,
            "record_id": "datadog_cloud_aws_0",
            "resource_id": "datadog_cloud_aws_0",
            "cloud_provider": "aws",
            "resource_collection_enabled": True,
            "metric_collection_enabled": True,
            "log_collection_enabled": True,
        },
    ]
    out: list[Any] = []
    for r in records:
        out.extend(_datadog_eval(r))
    return out


# ── TestDatadogRuleRegistration ───────────────────────────────────────────────

class TestDatadogRuleRegistration:
    def test_rule_key_count_is_thirty_one(self) -> None:
        assert len(ALL_DATADOG_RULE_KEYS) == 31

    def test_module_export_matches_canonical_set(self) -> None:
        from app.services.security_rules.datadog import DATADOG_RULE_KEYS as MOD_KEYS
        assert set(MOD_KEYS) == ALL_DATADOG_RULE_KEYS

    def test_all_datadog_rule_keys_in_registry(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for key in ALL_DATADOG_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS, f"{key!r} missing from KNOWN_RULE_KEYS"

    def test_all_datadog_rule_keys_have_confidence(self) -> None:
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for key in ALL_DATADOG_RULE_KEYS:
            assert key in RULE_CONFIDENCE, f"{key!r} missing from RULE_CONFIDENCE"

    def test_all_datadog_rule_keys_in_pack(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_DATADOG_RULE_KEYS:
            assert key in _RULE_META, f"{key!r} missing from _RULE_META"
            provider, _sev, _cat = _RULE_META[key]
            assert provider == CANONICAL_PROVIDER, (
                f"{key!r} wrong provider: {provider!r}"
            )

    def test_all_datadog_rule_keys_in_coverage(self) -> None:
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in ALL_DATADOG_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, f"{key!r} missing from RULE_RECORD_TYPES"
            assert RULE_RECORD_TYPES[key], f"{key!r} has empty record-type tuple"

    def test_registry_has_no_unexpected_datadog_keys(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        reg = {k for k in KNOWN_RULE_KEYS if k.startswith("datadog_")}
        extra = reg - ALL_DATADOG_RULE_KEYS
        assert not extra, f"unexpected datadog keys in registry: {sorted(extra)}"


# ── TestDatadogFrontendCatalogParity ──────────────────────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
class TestDatadogFrontendCatalogParity:
    def _catalog_text(self) -> str:
        return FE_RULE_CATALOG.read_text(encoding="utf-8")

    def test_all_datadog_rule_keys_in_frontend_catalog(self) -> None:
        text = self._catalog_text()
        missing = [k for k in ALL_DATADOG_RULE_KEYS if f'key: "{k}"' not in text]
        assert not missing, (
            f"Datadog rule keys missing from frontend catalog: {missing}"
        )

    def test_catalog_keys_match_via_regex(self) -> None:
        text = self._catalog_text()
        found = set(re.findall(r'key:\s*"(datadog_[a-z0-9_]+)"', text))
        missing = ALL_DATADOG_RULE_KEYS - found
        assert not missing, (
            f"Regex did not find Datadog keys in catalog: {sorted(missing)}"
        )

    def test_catalog_has_no_unexpected_datadog_keys(self) -> None:
        text = self._catalog_text()
        found = set(re.findall(r'key:\s*"(datadog_[a-z0-9_]+)"', text))
        extra = found - ALL_DATADOG_RULE_KEYS
        assert not extra, (
            f"Unexpected datadog keys in frontend catalog: {sorted(extra)}"
        )

    def test_backend_frontend_severity_match(self) -> None:
        text = self._catalog_text()
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_DATADOG_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            assert idx != -1, f"Datadog rule {key!r} not found in frontend catalog"
            block = text[idx:idx + 900]
            _provider, expected_sev, _cat = _RULE_META[key]
            assert f'severity: "{expected_sev}"' in block, (
                f"Frontend severity for {key!r} does not match backend "
                f"({expected_sev!r})"
            )

    def test_catalog_provider_is_canonical(self) -> None:
        text = self._catalog_text()
        for key in ALL_DATADOG_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            block = text[idx:idx + 900]
            assert 'provider: "datadog"' in block, (
                f"Frontend catalog entry for {key!r} must use provider 'datadog'"
            )


# ── TestDatadogEvidenceSafety ─────────────────────────────────────────────────

class TestDatadogEvidenceSafety:
    def test_representative_records_fire_many_rules(self) -> None:
        fired = {_rule_key(f) for f in _all_datadog_findings()}
        assert len(fired) >= 20, (
            f"expected representative records to fire >= 20 distinct rules; "
            f"got {len(fired)}: {sorted(fired)}"
        )

    def test_evidence_keys_are_safe(self) -> None:
        findings = _all_datadog_findings()
        assert findings, "expected at least one finding across representative records"
        for f in findings:
            ev_keys = {k.lower() for k in _evidence(f)}
            for forbidden in FORBIDDEN_EVIDENCE_KEYS:
                assert forbidden not in ev_keys, (
                    f"Forbidden evidence key {forbidden!r} in finding "
                    f"{_rule_key(f)!r}: {sorted(ev_keys)}"
                )

    def test_evidence_is_flat_safe_scalars(self) -> None:
        def _is_safe_scalar(x: Any) -> bool:
            return isinstance(x, (str, int, float, bool, type(None)))

        for f in _all_datadog_findings():
            for k, v in _evidence(f).items():
                if _is_safe_scalar(v):
                    continue
                assert isinstance(v, list), (
                    f"Non-scalar evidence value in {_rule_key(f)!r} key {k!r}: "
                    f"{type(v).__name__}"
                )
                for item in v:
                    assert _is_safe_scalar(item), (
                        f"Unsafe list item in {_rule_key(f)!r} key {k!r}: "
                        f"{type(item).__name__}"
                    )


# ── TestDatadogCopySafety ─────────────────────────────────────────────────────

class TestDatadogCopySafety:
    def test_no_forbidden_wording_in_rule_copy(self) -> None:
        from app.services.security_rules import datadog as dd_rules
        src = inspect.getsource(dd_rules).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in src, (
                f"forbidden phrase {phrase!r} present in security_rules.datadog"
            )

    def test_no_forbidden_wording_in_finding_copy(self) -> None:
        for f in _all_datadog_findings():
            blob = f"{_title(f)}\n{_description(f)}".lower()
            for phrase in FORBIDDEN_PHRASES:
                assert phrase not in blob, (
                    f"Finding {_rule_key(f)!r} copy contains forbidden phrase "
                    f"{phrase!r}"
                )


# ── TestDatadogEvaluatorDispatch ──────────────────────────────────────────────

class TestDatadogEvaluatorDispatch:
    def test_datadog_in_provider_rules(self) -> None:
        """Regression guard: Datadog must be wired into the central evaluator."""
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert "datadog" in _PROVIDER_RULES, (
            "datadog missing from security_finding_evaluator._PROVIDER_RULES"
        )
        assert _PROVIDER_RULES["datadog"], "datadog dispatch list is empty"

    def test_evaluate_record_dispatch(self) -> None:
        """A risky webhook routed through the central evaluator yields a finding."""
        from app.services.security_finding_evaluator import evaluate_record
        candidates = evaluate_record(_risky_webhook_no_secret_headers(), "datadog")
        assert candidates, "central evaluator produced no Datadog findings"
        keys = {c.rule_key for c in candidates}
        assert "datadog_webhook_without_secret_headers" in keys, (
            f"expected webhook-without-secret-headers via central dispatch; "
            f"got {keys}"
        )

    def test_central_evaluator_webhook_without_secret_headers_high(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        cands = evaluate_record(_risky_webhook_no_secret_headers(), "datadog")
        match = [
            c for c in cands
            if c.rule_key == "datadog_webhook_without_secret_headers"
        ]
        assert match, "expected datadog_webhook_without_secret_headers to fire"
        assert match[0].severity == "high"

    def test_central_evaluator_webhook_non_https_endpoint_high(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        cands = evaluate_record(_risky_webhook_http_endpoint(), "datadog")
        keys = {c.rule_key for c in cands}
        assert "datadog_webhook_non_https_endpoint" in keys, (
            f"expected datadog_webhook_non_https_endpoint via central dispatch; "
            f"got {keys}"
        )
        match = [
            c for c in cands if c.rule_key == "datadog_webhook_non_https_endpoint"
        ]
        assert match[0].severity == "high"

    def test_central_evaluator_dashboard_public_url_present(self) -> None:
        from app.services.security_finding_evaluator import evaluate_record
        cands = evaluate_record(_risky_dashboard_public_url(), "datadog")
        keys = {c.rule_key for c in cands}
        assert "datadog_dashboard_public_url_present" in keys, (
            f"expected datadog_dashboard_public_url_present via central dispatch; "
            f"got {keys}"
        )
        match = [
            c for c in cands if c.rule_key == "datadog_dashboard_public_url_present"
        ]
        assert match[0].severity == "medium"

    def test_central_evaluator_healthy_webhook_fires_no_high_rules(self) -> None:
        """A properly configured webhook fires none of the High webhook rules."""
        from app.services.security_finding_evaluator import evaluate_record
        cands = evaluate_record(_healthy_webhook(), "datadog")
        keys = {c.rule_key for c in cands}
        assert "datadog_webhook_without_secret_headers" not in keys, (
            "healthy webhook must not fire datadog_webhook_without_secret_headers"
        )
        assert "datadog_webhook_non_https_endpoint" not in keys, (
            "healthy webhook must not fire datadog_webhook_non_https_endpoint"
        )


# ── TestDatadogExpansionFramework ─────────────────────────────────────────────

class TestDatadogExpansionFramework:
    def test_planned_next_stage_is_kubernetes(self) -> None:
        """Regression note: Kubernetes launched (message 1 / M89A) — Sentry/M90A is now next."""
        from app.services.provider_expansion_framework import get_framework
        stage = get_framework()["summary"]["planned_next_stage"]
        assert stage.startswith("M90A") or "Sentry" in stage, (
            f"planned_next_stage should reference M90A Sentry, got {stage!r}"
        )

    def test_datadog_not_in_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        providers = [r["provider"] for r in fw["recommended_next_providers"]]
        assert CANONICAL_PROVIDER not in providers, (
            "Datadog has launched and must not be in the recommended queue"
        )


# ── TestDatadogProviderCapabilityMatrix ───────────────────────────────────────

class TestDatadogProviderCapabilityMatrix:
    def test_provider_capability_matrix_datadog(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability(CANONICAL_PROVIDER)
        assert cap is not None, "Datadog missing from provider capability matrix"
        assert cap.provider == CANONICAL_PROVIDER
        assert cap.security.security_rules is True
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True
        assert cap.maturity == "partial"

    def test_datadog_capability_count_matches_rule_set(self) -> None:
        """The Datadog rule pack must expose exactly the 31 canonical rules."""
        from app.services.security_rule_pack import _RULE_META
        dd_keys = {k for k, v in _RULE_META.items() if v[0] == CANONICAL_PROVIDER}
        assert dd_keys == ALL_DATADOG_RULE_KEYS, (
            f"Datadog rule-pack key set drift. Missing: "
            f"{ALL_DATADOG_RULE_KEYS - dd_keys}; Extra: "
            f"{dd_keys - ALL_DATADOG_RULE_KEYS}"
        )

    def test_kubernetes_not_implemented(self) -> None:
        """Regression note: Kubernetes now has a static Security Finding
        layer (message 6). It has a capability-matrix entry
        (maturity='partial', security_rules=True) and is wired into the
        central evaluator/registry."""
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        from app.services.security_rule_registry import KNOWN_RULE_KEYS

        cap = get_provider_capability("kubernetes")
        assert cap is not None
        assert cap.maturity == "partial"
        assert cap.security.security_rules is True
        assert "kubernetes" in _PROVIDER_RULES, (
            "kubernetes must be wired into the central evaluator"
        )
        assert any(k.startswith("kubernetes_") for k in KNOWN_RULE_KEYS), (
            "kubernetes_* rule keys should exist in the registry"
        )

    def test_kubernetes_connector_does_not_exist(self) -> None:
        """Regression note: the Kubernetes connector now exists (foundation stage only)."""
        k8s_connector = BACKEND / "connectors" / "kubernetes.py"
        assert k8s_connector.exists()
