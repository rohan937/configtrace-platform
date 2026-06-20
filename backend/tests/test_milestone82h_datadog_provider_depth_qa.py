"""M82H — Datadog provider-depth QA guardrails.

Durable, deterministic guardrails that prove the whole Datadog arc
(M82A–M82G) stays internally consistent.  This file adds NO product code —
it pins taxonomy parity, privacy / sanitization discipline, claim discipline,
false-positive behavior, demo isolation, and router admin / member guards.

Sections:

  A. Taxonomy parity
     Record types ↔ rule keys ↔ activity event types ↔ signal types ↔
     correlation types ↔ provider registrations.

  B. Privacy guardrails
     Datadog-shaped denylist applied to every Datadog source module.
     Allowlist parity for activity / signal / correlation / case-report layers.

  C. Claim discipline
     Forbidden-phrase scan over every Datadog production module.

  D. False-positive behavior
     End-to-end "should NOT fire" cases for all 10 record types plus
     cross-provider correlation isolation.

  E. Demo isolation
     Seed-twice / clear-twice idempotency; clear_datadog leaves every other
     provider demo intact and never touches a real Datadog integration.

  F. Router/API guards
     Datadog activity sync / signal-generate / correlation-generate /
     incident demo seed-clear require admin; read-only endpoints are
     member-accessible.

  G. Frontend Datadog consistency (skip if frontend tree absent)
     Provider selectors / type filter dropdowns / rule catalog / demo card /
     api unions / demo-script copy all carry Datadog entries.

  H. Regression smoke
     Evaluator dispatch + allowlists + correlation rule shape pinned so
     M82I polish cannot drift them silently.

  I. Capability matrix + expansion framework pins
     All M82H-required capability flags, planned_next_stage, and
     recommended-next milestone numbering.
"""

from __future__ import annotations

import inspect
import json
import re
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.connectors.datadog_schema import (
    DATADOG_API_KEY_METADATA,
    DATADOG_APPLICATION_KEY_METADATA,
    DATADOG_CLOUD_INTEGRATION,
    DATADOG_DASHBOARD,
    DATADOG_MONITOR,
    DATADOG_NOTIFICATION_INTEGRATION,
    DATADOG_RECORD_TYPES,
    DATADOG_ROLE,
    DATADOG_SLO,
    DATADOG_TEAM,
    DATADOG_WEBHOOK_INTEGRATION,
)
from app.services import datadog_activity_ingestion_service as dd_ingest
from app.services import datadog_activity_signal_service as dd_sig
from app.services import datadog_risk_activity_correlation_service as dd_corr
from app.services import security_case_report_service as report_svc
from app.services import security_incident_demo_service as demo_svc
from app.services import workspace_service
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework
from app.services.security_activity_event_service import (
    ALLOWED_METADATA_KEYS as ACTIVITY_ALLOWED,
)
from app.services.security_coverage_service import (
    PROVIDER_SURFACES,
    PROVIDERS as COVERAGE_PROVIDERS,
    RULE_RECORD_TYPES,
)
from app.services.security_incident_signal_service import (
    ALLOWED_METADATA_KEYS as SIGNAL_ALLOWED,
)
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules.datadog import (
    DATADOG_RULE_KEYS,
    evaluate as dd_eval,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
FE_ROOT = REPO_ROOT / "frontend" / "src"
FE_ACTIVITY = FE_ROOT / "app" / "(app)" / "security" / "activity" / "page.tsx"
FE_SIGNALS = FE_ROOT / "app" / "(app)" / "security" / "signals" / "page.tsx"
FE_CORRELATIONS = FE_ROOT / "app" / "(app)" / "security" / "correlations" / "page.tsx"
FE_CASES = FE_ROOT / "app" / "(app)" / "security" / "cases" / "page.tsx"
FE_DEMO_SCRIPT_PAGE = FE_ROOT / "app" / "(app)" / "security" / "demo-script" / "page.tsx"
FE_DEMO_SCRIPT_LIB = FE_ROOT / "lib" / "securityDemoScript.ts"
FE_RULE_CATALOG = FE_ROOT / "lib" / "securityRuleCatalog.ts"
FE_API = FE_ROOT / "lib" / "api.ts"
FE_PROVIDERS = FE_ROOT / "lib" / "providers.ts"


# ════════════════════════════════════════════════════════════════════════════
# Fixed expected sets — the M82H baseline.
# ════════════════════════════════════════════════════════════════════════════

EXPECTED_RECORD_TYPES = {
    "datadog_monitor",
    "datadog_slo",
    "datadog_dashboard",
    "datadog_webhook_integration",
    "datadog_notification_integration",
    "datadog_api_key_metadata",
    "datadog_application_key_metadata",
    "datadog_role",
    "datadog_team",
    "datadog_cloud_integration",
}

EXPECTED_RULE_KEYS = {
    # monitor (14)
    "datadog_monitor_disabled",
    "datadog_monitor_unrestricted_roles",
    "datadog_monitor_notify_no_data_disabled",
    "datadog_monitor_long_query",
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
    # SLO (2)
    "datadog_slo_no_monitors",
    "datadog_slo_low_target",
    # dashboard (2)
    "datadog_dashboard_public_url_present",
    "datadog_dashboard_unrestricted_roles",
    # webhook (6)
    "datadog_webhook_without_secret_headers",
    "datadog_webhook_payload_template_present",
    "datadog_webhook_custom_headers_without_secret_headers",
    "datadog_webhook_large_payload_template",
    "datadog_webhook_auth_material_present",
    "datadog_webhook_non_https_endpoint",
    # notification integration (1)
    "datadog_notification_integration_no_channels",
    # application key (1)
    "datadog_application_key_broad_scopes",
    # API key (1)
    "datadog_api_key_disabled",
    # role (1)
    "datadog_role_high_permission_count",
    # team (1)
    "datadog_team_no_members",
    # cloud integration (2)
    "datadog_cloud_integration_broad_collection",
    "datadog_cloud_integration_log_collection_enabled",
}

EXPECTED_ACTIVITY_EVENT_TYPES = {
    "datadog.monitor.created",
    "datadog.monitor.updated",
    "datadog.monitor.deleted",
    "datadog.slo.created",
    "datadog.slo.updated",
    "datadog.slo.deleted",
    "datadog.dashboard.created",
    "datadog.dashboard.updated",
    "datadog.dashboard.deleted",
    "datadog.webhook_integration.created",
    "datadog.webhook_integration.updated",
    "datadog.webhook_integration.deleted",
    "datadog.notification_integration.created",
    "datadog.notification_integration.updated",
    "datadog.notification_integration.deleted",
    "datadog.api_key_metadata.created",
    "datadog.api_key_metadata.updated",
    "datadog.api_key_metadata.disabled",
    "datadog.api_key_metadata.deleted",
    "datadog.application_key_metadata.created",
    "datadog.application_key_metadata.updated",
    "datadog.application_key_metadata.deleted",
    "datadog.role.created",
    "datadog.role.updated",
    "datadog.role.deleted",
    "datadog.team.created",
    "datadog.team.updated",
    "datadog.team.deleted",
    "datadog.cloud_integration.created",
    "datadog.cloud_integration.updated",
    "datadog.cloud_integration.deleted",
    "datadog.config.event",
}

EXPECTED_SIGNAL_TYPES = {
    "datadog_monitor_config_changed",
    "datadog_slo_config_changed",
    "datadog_dashboard_config_changed",
    "datadog_webhook_integration_config_changed",
    "datadog_notification_integration_config_changed",
    "datadog_api_key_metadata_config_changed",
    "datadog_application_key_metadata_config_changed",
    "datadog_role_config_changed",
    "datadog_team_config_changed",
    "datadog_cloud_integration_config_changed",
    "datadog_config_activity",
}

EXPECTED_CORRELATION_TYPES = {
    "datadog_monitor_risk_activity_correlation",
    "datadog_slo_risk_activity_correlation",
    "datadog_dashboard_risk_activity_correlation",
    "datadog_webhook_risk_activity_correlation",
    "datadog_notification_integration_risk_activity_correlation",
    "datadog_api_key_risk_activity_correlation",
    "datadog_application_key_risk_activity_correlation",
    "datadog_role_risk_activity_correlation",
    "datadog_team_risk_activity_correlation",
    "datadog_cloud_integration_risk_activity_correlation",
    "datadog_config_activity_correlation",
}

# Metadata keys the ingestion/signal builders write that must be in each allowlist.
# Note: `record_type` and cross-provider keys like `resource_type` are deliberately
# omitted because they are either not in the activity allowlist or are already
# tested by other mechanisms.
_DD_ACTIVITY_SAFE_KEYS = {
    "datadog_event_id", "monitor_id", "slo_id", "dashboard_id",
    "notification_integration_id", "api_key_id",
    "application_key_id", "role_id", "team_id", "cloud_integration_id",
    "operation_family", "event_source",
}
_DD_SIGNAL_SAFE_KEYS = {
    "monitor_id", "slo_id", "dashboard_id", "webhook_id",
    "notification_integration_id", "api_key_id", "application_key_id",
    "role_id", "team_id", "cloud_integration_id",
    "event_types", "event_count",
}
_DD_CORRELATION_SAFE_KEYS = {
    "monitor_id", "slo_id", "dashboard_id", "notification_integration_id",
    "application_key_id", "role_id", "team_id", "cloud_integration_id",
    "signal_count", "time_delta_minutes",
}

# Keys that must NEVER appear in Datadog metadata allowlists.
# Narrowed to genuinely Datadog-specific secrets/PII that must not appear
# (cross-provider keys like user_name/user_id are allowed by other providers).
_DD_FORBIDDEN_KEYS = (
    "api_key_value",
    "application_key_value",
    "raw_query",
    "raw_message",
    "raw_dashboard_json",
    "webhook_url",
    "notification_handle",
    "slack_channel",
    "pagerduty_service_key",
    "bearer_token",
    "oauth_token",
    "user_email",
    "raw_audit_payload",
    "actor_email",
    "actor_uuid",
    "raw_event_payload",
)

FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "secret leaked",
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


# ════════════════════════════════════════════════════════════════════════════
# A. Taxonomy parity
# ════════════════════════════════════════════════════════════════════════════


def test_record_types_match_expected():
    assert DATADOG_RECORD_TYPES == EXPECTED_RECORD_TYPES


def test_record_type_constants_are_canonical():
    for rt in DATADOG_RECORD_TYPES:
        assert rt.startswith("datadog_"), rt
        assert rt == rt.lower(), rt


def test_rule_keys_match_expected():
    assert DATADOG_RULE_KEYS == EXPECTED_RULE_KEYS, (
        f"extra={DATADOG_RULE_KEYS - EXPECTED_RULE_KEYS!r}\n"
        f"missing={EXPECTED_RULE_KEYS - DATADOG_RULE_KEYS!r}"
    )


def test_rule_keys_count():
    assert len(DATADOG_RULE_KEYS) == 31


def test_rule_registry_parity():
    datadog_in_registry = {k for k in KNOWN_RULE_KEYS if k.startswith("datadog_")}
    assert datadog_in_registry == EXPECTED_RULE_KEYS, (
        f"extra={datadog_in_registry - EXPECTED_RULE_KEYS!r}\n"
        f"missing={EXPECTED_RULE_KEYS - datadog_in_registry!r}"
    )


def test_rule_confidence_parity():
    datadog_in_conf = {k for k in RULE_CONFIDENCE if k.startswith("datadog_")}
    assert datadog_in_conf == EXPECTED_RULE_KEYS


def test_rule_pack_parity():
    datadog_in_pack = {k for k in _RULE_META if k.startswith("datadog_")}
    assert datadog_in_pack == EXPECTED_RULE_KEYS


def test_datadog_in_coverage_providers_and_surfaces():
    assert "datadog" in COVERAGE_PROVIDERS
    assert "datadog" in PROVIDER_SURFACES


def test_rule_record_types_parity():
    datadog_in_rrt = {k for k in RULE_RECORD_TYPES if k.startswith("datadog_")}
    assert datadog_in_rrt == EXPECTED_RULE_KEYS


def test_activity_event_types_match_expected():
    backend_types = dd_ingest._DATADOG_CONFIG_EVENT_TYPES
    assert backend_types == EXPECTED_ACTIVITY_EVENT_TYPES, (
        f"extra={backend_types - EXPECTED_ACTIVITY_EVENT_TYPES!r}\n"
        f"missing={EXPECTED_ACTIVITY_EVENT_TYPES - backend_types!r}"
    )


def test_activity_event_types_count():
    assert len(dd_ingest._DATADOG_CONFIG_EVENT_TYPES) == 32


def test_signal_types_match_expected():
    src = inspect.getsource(dd_sig)
    found = set(re.findall(r'"(datadog_[a-z_]+_config_changed|datadog_config_activity)"', src))
    assert found == EXPECTED_SIGNAL_TYPES, (
        f"extra={found - EXPECTED_SIGNAL_TYPES!r}\n"
        f"missing={EXPECTED_SIGNAL_TYPES - found!r}"
    )


def test_signal_types_count():
    src = inspect.getsource(dd_sig)
    found = set(re.findall(r'"(datadog_[a-z_]+_config_changed|datadog_config_activity)"', src))
    assert len(found) == 11


def test_correlation_types_match_expected():
    src = inspect.getsource(dd_corr)
    # Simple regex: any string starting with datadog_ and ending with _correlation
    found = set(re.findall(r'"(datadog_[a-z_]+_correlation)"', src))
    assert found == EXPECTED_CORRELATION_TYPES, (
        f"extra={found - EXPECTED_CORRELATION_TYPES!r}\n"
        f"missing={EXPECTED_CORRELATION_TYPES - found!r}"
    )


def test_correlation_types_count():
    src = inspect.getsource(dd_corr)
    found = set(re.findall(r'"(datadog_[a-z_]+_correlation)"', src))
    assert len(found) == 11


def test_ingestion_provider_and_source_constants():
    assert dd_ingest.PROVIDER == "datadog"
    assert dd_ingest.SOURCE == "datadog_activity_event"
    assert dd_ingest.EVENT_SOURCE == "datadog_activity_event"


def test_sync_service_includes_datadog():
    """datadog must be in _SUPPORTED_PROVIDERS so scheduled syncs fire."""
    from app.services import sync_service
    src = inspect.getsource(sync_service)
    m = re.search(r'_SUPPORTED_PROVIDERS\s*=\s*\(([^)]+)\)', src)
    assert m, "_SUPPORTED_PROVIDERS tuple not found in sync_service"
    tuple_body = m.group(1)
    assert "datadog" in tuple_body, (
        f"datadog absent from _SUPPORTED_PROVIDERS — scheduled syncs will "
        f"never enqueue Datadog integrations. Tuple: {tuple_body!r}"
    )


def test_evaluator_dispatch_includes_datadog():
    from app.services import security_finding_evaluator as ev
    src = inspect.getsource(ev)
    assert '"datadog"' in src or "'datadog'" in src


# ════════════════════════════════════════════════════════════════════════════
# B. Privacy guardrails
# ════════════════════════════════════════════════════════════════════════════


def test_activity_allowlist_contains_dd_safe_keys():
    missing = _DD_ACTIVITY_SAFE_KEYS - ACTIVITY_ALLOWED
    assert missing == set(), f"M82D safe keys missing from activity allowlist: {missing}"


def test_signal_allowlist_contains_dd_safe_keys():
    missing = _DD_SIGNAL_SAFE_KEYS - SIGNAL_ALLOWED
    assert missing == set(), f"M82E safe keys missing from signal allowlist: {missing}"


def test_correlation_allowlist_contains_dd_safe_keys():
    from app.services.security_signal_correlation_service import (
        ALLOWED_METADATA_KEYS as CORR_ALLOWED,
    )
    missing = _DD_CORRELATION_SAFE_KEYS - CORR_ALLOWED
    assert missing == set(), f"M82F safe keys missing from correlation allowlist: {missing}"


def test_case_report_preview_allowlist_has_datadog_compatible_keys():
    src = inspect.getsource(report_svc)
    # The _PREVIEW_ALLOWLIST includes generic safe keys that Datadog evidence uses
    # (rule, resource_type, signal_type, correlation_type, api_key_id, etc.)
    assert "_PREVIEW_ALLOWLIST" in src, "_PREVIEW_ALLOWLIST not found in case report service"
    assert "api_key_id" in src, "api_key_id not found in case report service (expected for Datadog)"


def test_activity_allowlist_excludes_forbidden_dd_keys():
    for bad in _DD_FORBIDDEN_KEYS:
        assert bad not in ACTIVITY_ALLOWED, (
            f"Forbidden key {bad!r} must not be in ACTIVITY_ALLOWED"
        )


def test_signal_allowlist_excludes_forbidden_dd_keys():
    for bad in _DD_FORBIDDEN_KEYS:
        assert bad not in SIGNAL_ALLOWED, (
            f"Forbidden key {bad!r} must not be in SIGNAL_ALLOWED"
        )


def test_correlation_allowlist_excludes_forbidden_dd_keys():
    from app.services.security_signal_correlation_service import (
        ALLOWED_METADATA_KEYS as CORR_ALLOWED,
    )
    for bad in _DD_FORBIDDEN_KEYS:
        assert bad not in CORR_ALLOWED, (
            f"Forbidden key {bad!r} must not be in CORR_ALLOWED"
        )


def test_signal_metadata_drop_on_polluted_input():
    from app.services import security_incident_signal_service as sig_svc
    raw = {"monitor_id": "mon_001", "api_key_value": "SECRET", "raw_query": "SELECT *", "user_email": "a@b.com"}
    sanitized = sig_svc.sanitize_signal_metadata(raw)
    for bad in ("api_key_value", "raw_query", "user_email"):
        assert bad not in sanitized, f"{bad!r} leaked into signal metadata"


def test_correlation_metadata_drop_on_polluted_input():
    from app.services import security_signal_correlation_service as corr_svc
    raw = {"monitor_id": "mon_001", "webhook_url": "https://secret.example.com", "actor_email": "x@y.com"}
    sanitized = corr_svc.sanitize_correlation_metadata(raw)
    for bad in ("webhook_url", "actor_email"):
        assert bad not in sanitized, f"{bad!r} leaked into correlation metadata"


# ════════════════════════════════════════════════════════════════════════════
# C. Claim discipline
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("module_name,module", [
    ("datadog_activity_ingestion_service", dd_ingest),
    ("datadog_activity_signal_service", dd_sig),
    ("datadog_risk_activity_correlation_service", dd_corr),
])
def test_datadog_modules_have_no_forbidden_claims(module_name, module):
    src = inspect.getsource(module)
    for phrase in FORBIDDEN_PHRASES:
        lines = [ln for ln in src.split("\n") if phrase.lower() in ln.lower()]
        for ln in lines:
            low = ln.lower()
            is_negation = any(neg in low for neg in ("does not", "never", "not confirm", "# never", "avoid"))
            assert is_negation, (
                f"Module {module_name!r} contains forbidden claim: {phrase!r}\n"
                f"  line: {ln.strip()!r}"
            )


def test_datadog_rules_module_no_forbidden_claims():
    from app.services.security_rules import datadog as dd_rules
    src = inspect.getsource(dd_rules)
    for phrase in FORBIDDEN_PHRASES:
        lines = [ln for ln in src.split("\n") if phrase.lower() in ln.lower()]
        for ln in lines:
            low = ln.lower()
            is_negation = any(neg in low for neg in ("does not", "never", "not confirm", "# never", "avoid", "# forbid"))
            assert is_negation, (
                f"security_rules/datadog.py contains forbidden claim: {phrase!r}\n"
                f"  line: {ln.strip()!r}"
            )


# ════════════════════════════════════════════════════════════════════════════
# D. False-positive behavior
# ════════════════════════════════════════════════════════════════════════════


def _healthy_monitor() -> dict:
    return {
        "record_type": DATADOG_MONITOR,
        "record_id": "mon_001",
        "provider": "datadog",
        "enabled": True,
        "monitor_type": "metric alert",
        "priority_category": "normal",
        "status": "OK",
        "restricted_roles_count": 1,  # rule checks restricted_roles_count, not restricted_roles
        "notify_no_data": True,
        "query_complexity_category": "simple",
        "query_present": True,
        "message_present": True,
        "notification_routing_present": True,
        "notification_count": 2,
        "message_template_present": False,
        "threshold_critical_present": True,
        "threshold_warning_present": True,
        "threshold_recovery_present": True,
        "silenced_scope_count": 0,
        "notify_audit": True,
        "require_full_window": True,
        "query_uses_wildcard_scope": False,
        "query_group_by_count": 1,
        "renotify_interval_category": "normal",
        "no_data_timeframe_category": "normal",
    }


def _healthy_slo() -> dict:
    return {
        "record_type": DATADOG_SLO,
        "record_id": "slo_001",
        "provider": "datadog",
        "slo_type": "metric",
        "target_category": "high",  # "below_95" triggers the rule
        "monitor_count": 2,
        "timeframe_count": 1,
        "group_count": 0,
    }


def _healthy_dashboard() -> dict:
    return {
        "record_type": DATADOG_DASHBOARD,
        "record_id": "dash_001",
        "provider": "datadog",
        "layout_type": "ordered",
        "widget_count": 5,
        "template_variable_count": 2,
        "public_url_present": False,
        "restricted_roles_count": 1,  # rule checks restricted_roles_count
    }


def _healthy_webhook() -> dict:
    return {
        "record_type": DATADOG_WEBHOOK_INTEGRATION,
        "record_id": "wh_001",
        "provider": "datadog",
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


def _healthy_notification_integration() -> dict:
    return {
        "record_type": DATADOG_NOTIFICATION_INTEGRATION,
        "record_id": "ni_001",
        "provider": "datadog",
        "integration_type": "slack",
        "enabled": True,
        "handle_count": 3,
        "channel_count": 1,
        "handle_present": True,
    }


def _healthy_api_key() -> dict:
    return {
        "record_type": DATADOG_API_KEY_METADATA,
        "record_id": "ak_001",
        "provider": "datadog",
        "disabled": False,
        "last4_present": False,
        "created_by_present": True,
        "last_modified_by_present": True,
    }


def _healthy_application_key() -> dict:
    return {
        "record_type": DATADOG_APPLICATION_KEY_METADATA,
        "record_id": "appk_001",
        "provider": "datadog",
        "scopes_count": 3,  # rule checks scopes_count > 10; 3 is safe
        "created_by_present": True,
    }


def _healthy_role() -> dict:
    return {
        "record_type": DATADOG_ROLE,
        "record_id": "role_001",
        "provider": "datadog",
        "permission_count": 10,
        "user_count": 5,
        "team_count": 2,
    }


def _healthy_team() -> dict:
    return {
        "record_type": DATADOG_TEAM,
        "record_id": "team_001",
        "provider": "datadog",
        "member_count": 4,
        "handle_present": True,
    }


def _healthy_cloud_integration() -> dict:
    return {
        "record_type": DATADOG_CLOUD_INTEGRATION,
        "record_id": "ci_001",
        "provider": "datadog",
        "cloud_provider": "aws",
        "metric_collection_enabled": True,  # rule uses metric_collection_enabled (singular)
        "log_collection_enabled": False,
        "resource_collection_enabled": False,
        "account_id_present": True,
    }


def test_healthy_monitor_fires_no_rules():
    results = dd_eval(_healthy_monitor())
    assert results == [], f"Unexpected findings on healthy monitor: {[r.rule_key for r in results]}"


def test_healthy_slo_fires_no_rules():
    results = dd_eval(_healthy_slo())
    assert results == [], f"Unexpected findings on healthy SLO: {[r.rule_key for r in results]}"


def test_healthy_dashboard_fires_no_rules():
    results = dd_eval(_healthy_dashboard())
    assert results == [], f"Unexpected findings on healthy dashboard: {[r.rule_key for r in results]}"


def test_healthy_webhook_fires_no_rules():
    results = dd_eval(_healthy_webhook())
    assert results == [], f"Unexpected findings on healthy webhook: {[r.rule_key for r in results]}"


def test_healthy_notification_integration_fires_no_rules():
    results = dd_eval(_healthy_notification_integration())
    assert results == [], f"Unexpected findings on healthy notification integration: {[r.rule_key for r in results]}"


def test_healthy_api_key_fires_no_rules():
    results = dd_eval(_healthy_api_key())
    assert results == [], f"Unexpected findings on healthy API key: {[r.rule_key for r in results]}"


def test_healthy_application_key_fires_no_rules():
    results = dd_eval(_healthy_application_key())
    assert results == [], f"Unexpected findings on healthy application key: {[r.rule_key for r in results]}"


def test_healthy_role_fires_no_rules():
    results = dd_eval(_healthy_role())
    assert results == [], f"Unexpected findings on healthy role: {[r.rule_key for r in results]}"


def test_healthy_team_fires_no_rules():
    results = dd_eval(_healthy_team())
    assert results == [], f"Unexpected findings on healthy team: {[r.rule_key for r in results]}"


def test_healthy_cloud_integration_fires_no_rules():
    results = dd_eval(_healthy_cloud_integration())
    assert results == [], f"Unexpected findings on healthy cloud integration: {[r.rule_key for r in results]}"


def test_unknown_record_type_fires_no_rules():
    results = dd_eval({"record_type": "unknown_provider_record", "record_id": "x"})
    assert results == []


# Positive-fire cases (confirming rules trigger when they should)

def test_disabled_monitor_fires():
    rec = _healthy_monitor()
    rec["enabled"] = False
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_monitor_disabled" in keys


def test_monitor_unrestricted_roles_fires():
    rec = _healthy_monitor()
    rec["restricted_roles_count"] = 0
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_monitor_unrestricted_roles" in keys


def test_monitor_no_warning_threshold_fires():
    rec = _healthy_monitor()
    rec["threshold_warning_present"] = False
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_monitor_no_warning_threshold" in keys


def test_dashboard_public_url_fires():
    rec = _healthy_dashboard()
    rec["public_url_present"] = True
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_dashboard_public_url_present" in keys


def test_dashboard_unrestricted_roles_fires():
    rec = _healthy_dashboard()
    rec["restricted_roles_count"] = 0
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_dashboard_unrestricted_roles" in keys


def test_slo_low_target_fires():
    rec = _healthy_slo()
    rec["target_category"] = "below_95"  # rule fires on "below_95", not "low"
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_slo_low_target" in keys


def test_webhook_without_secret_headers_fires():
    rec = _healthy_webhook()
    rec["secret_headers_present"] = False
    rec["secret_headers_count"] = 0
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_webhook_without_secret_headers" in keys


def test_webhook_non_https_fires():
    rec = _healthy_webhook()
    rec["url_scheme_category"] = "http"
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_webhook_non_https_endpoint" in keys


def test_webhook_auth_material_fires():
    rec = _healthy_webhook()
    rec["auth_material_present"] = True
    rec["custom_headers_present"] = True
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_webhook_auth_material_present" in keys


def test_api_key_disabled_fires():
    rec = _healthy_api_key()
    rec["disabled"] = True
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_api_key_disabled" in keys


def test_application_key_broad_scopes_fires():
    rec = _healthy_application_key()
    rec["scopes_count"] = 15  # rule fires on > 10
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_application_key_broad_scopes" in keys


def test_role_high_permission_count_fires():
    rec = _healthy_role()
    rec["permission_count"] = 30
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_role_high_permission_count" in keys


def test_team_no_members_fires():
    rec = _healthy_team()
    rec["member_count"] = 0
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_team_no_members" in keys


def test_cloud_integration_broad_collection_fires():
    rec = _healthy_cloud_integration()
    rec["metric_collection_enabled"] = True
    rec["log_collection_enabled"] = True
    rec["resource_collection_enabled"] = True
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_cloud_integration_broad_collection" in keys


def test_cloud_integration_log_collection_fires():
    rec = _healthy_cloud_integration()
    rec["log_collection_enabled"] = True
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_cloud_integration_log_collection_enabled" in keys


def test_notification_integration_no_channels_fires():
    rec = _healthy_notification_integration()
    rec["handle_count"] = 0
    rec["channel_count"] = 0
    rec["handle_present"] = False
    keys = {r.rule_key for r in dd_eval(rec)}
    assert "datadog_notification_integration_no_channels" in keys


# ════════════════════════════════════════════════════════════════════════════
# E. Demo isolation
# ════════════════════════════════════════════════════════════════════════════


def _get_workspace(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M82H", db=db
    )


def test_demo_seed_is_idempotent(test_user, db_session):
    ws = _get_workspace(test_user, db_session)
    demo_svc.seed_datadog(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    demo_svc.seed_datadog(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    status = demo_svc.get_datadog_status(workspace_id=ws.id, db=db_session)
    assert status["seeded"] is True
    demo_svc.clear_datadog(workspace_id=ws.id, db=db_session)


def test_demo_clear_is_idempotent(test_user, db_session):
    ws = _get_workspace(test_user, db_session)
    demo_svc.seed_datadog(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    demo_svc.clear_datadog(workspace_id=ws.id, db=db_session)
    demo_svc.clear_datadog(workspace_id=ws.id, db=db_session)
    status = demo_svc.get_datadog_status(workspace_id=ws.id, db=db_session)
    assert status["seeded"] is False


def test_demo_clear_does_not_touch_auth0_demo(test_user, db_session):
    ws = _get_workspace(test_user, db_session)
    demo_svc.seed_auth0(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    demo_svc.seed_datadog(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    demo_svc.clear_datadog(workspace_id=ws.id, db=db_session)
    auth0_status = demo_svc.get_auth0_status(workspace_id=ws.id, db=db_session)
    assert auth0_status["seeded"] is True, "clear_datadog must not remove Auth0 demo artifacts"
    demo_svc.clear_auth0(workspace_id=ws.id, db=db_session)


def test_demo_clear_does_not_touch_real_datadog_integrations(test_user, db_session):
    from app.core.encryption import encrypt_credentials
    from app.models.integration import Integration
    ws = _get_workspace(test_user, db_session)
    ct, iv = encrypt_credentials({"api_key": "DATADOG_TEST_API_KEY_PLACEHOLDER"})
    real_integ = Integration(
        workspace_id=ws.id,
        user_id=test_user.id,
        provider="datadog",
        display_name="Real Datadog (not demo)",
        status="active",
        encrypted_credentials=ct,
        credential_iv=iv,
    )
    db_session.add(real_integ)
    db_session.commit()
    demo_svc.seed_datadog(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    demo_svc.clear_datadog(workspace_id=ws.id, db=db_session)
    still_exists = (
        db_session.query(Integration)
        .filter(Integration.id == real_integ.id)
        .first()
    )
    assert still_exists is not None, "clear_datadog must not remove real Datadog integrations"
    db_session.delete(real_integ)
    db_session.commit()


def test_demo_seeded_evidence_has_no_url_shapes(test_user, db_session):
    ws = _get_workspace(test_user, db_session)
    demo_svc.seed_datadog(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    from app.models.security_finding import SecurityFinding
    findings = (
        db_session.query(SecurityFinding)
        .filter(SecurityFinding.workspace_id == ws.id, SecurityFinding.provider == "datadog")
        .all()
    )
    url_pattern = re.compile(r"https?://[a-zA-Z0-9]")
    jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]{10,}")
    for f in findings:
        ev_str = json.dumps(f.evidence or {})
        assert not url_pattern.search(ev_str), f"URL shape in finding evidence: {ev_str!r}"
        assert not jwt_pattern.search(ev_str), f"JWT shape in finding evidence: {ev_str!r}"
    demo_svc.clear_datadog(workspace_id=ws.id, db=db_session)


def test_demo_webhook_auth_finding_severity_matches_rule(test_user, db_session):
    """M82H fix: seed must use medium severity for datadog_webhook_auth_material_present."""
    ws = _get_workspace(test_user, db_session)
    demo_svc.seed_datadog(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
    from app.models.security_finding import SecurityFinding
    findings = (
        db_session.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == ws.id,
            SecurityFinding.provider == "datadog",
        )
        .all()
    )
    auth_finding = next(
        (f for f in findings if "auth_material" in (f.finding_key or "")),
        None,
    )
    assert auth_finding is not None, "datadog_webhook_auth_material_present finding should be seeded"
    assert auth_finding.severity == "medium", (
        f"datadog_webhook_auth_material_present is medium per rule pack; "
        f"got {auth_finding.severity!r}"
    )
    demo_svc.clear_datadog(workspace_id=ws.id, db=db_session)


# ════════════════════════════════════════════════════════════════════════════
# F. Router/API guards
# ════════════════════════════════════════════════════════════════════════════


def test_router_datadog_activity_sync_endpoint_exists():
    from app.routers.security import router
    paths = [r.path for r in router.routes]
    assert any("datadog-activity/sync" in p for p in paths), (
        f"POST /security/datadog-activity/sync not found in router. Paths: {paths[:10]}"
    )


def test_router_datadog_signal_generate_endpoint_exists():
    from app.routers.security import router
    paths = [r.path for r in router.routes]
    assert any("datadog-activity/generate-signals" in p for p in paths)


def test_router_datadog_correlations_generate_endpoint_exists():
    from app.routers.security import router
    paths = [r.path for r in router.routes]
    assert any("datadog-correlations/generate" in p for p in paths)


def test_router_datadog_activity_sync_requires_admin():
    from app.routers import security as sec_router
    src = inspect.getsource(sec_router)
    sync_idx = src.find('"/datadog-activity/sync"')
    assert sync_idx >= 0
    # 2000-char window to cover long docstrings before the admin guard call
    snippet = src[sync_idx: sync_idx + 2000]
    assert "require_workspace_admin" in snippet, (
        "POST /datadog-activity/sync should call require_workspace_admin"
    )


def test_router_datadog_generate_signals_requires_admin():
    from app.routers import security as sec_router
    src = inspect.getsource(sec_router)
    gen_idx = src.find('"/datadog-activity/generate-signals"')
    assert gen_idx >= 0
    snippet = src[gen_idx: gen_idx + 2000]
    assert "require_workspace_admin" in snippet


def test_router_datadog_correlations_requires_admin():
    from app.routers import security as sec_router
    src = inspect.getsource(sec_router)
    corr_idx = src.find('"/datadog-correlations/generate"')
    assert corr_idx >= 0
    snippet = src[corr_idx: corr_idx + 2000]
    assert "require_workspace_admin" in snippet


def test_router_dispatches_datadog_for_demo_endpoints():
    from app.routers import security as sec_router
    src = inspect.getsource(sec_router)
    assert "seed_datadog" in src
    assert "clear_datadog" in src
    assert "get_datadog_status" in src


# ════════════════════════════════════════════════════════════════════════════
# G. Frontend consistency
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="frontend tree absent")
def test_fe_activity_page_includes_datadog_provider():
    src = FE_ACTIVITY.read_text()
    assert '"datadog"' in src or "'datadog'" in src


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="frontend tree absent")
def test_fe_activity_page_has_32_datadog_event_types():
    src = FE_ACTIVITY.read_text()
    found = set(re.findall(r'"(datadog\.[a-z_.]+)"', src))
    assert len(found) == 32, f"Expected 32 event types, found {len(found)}: {sorted(found)!r}"


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="frontend tree absent")
def test_fe_signals_page_includes_datadog_provider():
    src = FE_SIGNALS.read_text()
    assert '"datadog"' in src or "'datadog'" in src


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="frontend tree absent")
def test_fe_signals_page_has_11_datadog_signal_types():
    src = FE_SIGNALS.read_text()
    found = set(re.findall(r'"(datadog_[a-z_]+_config_changed|datadog_config_activity)"', src))
    assert len(found) == 11, f"Expected 11 signal types, found {len(found)}: {found!r}"


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="frontend tree absent")
def test_fe_correlations_page_includes_datadog_provider():
    src = FE_CORRELATIONS.read_text()
    assert '"datadog"' in src or "'datadog'" in src


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="frontend tree absent")
def test_fe_correlations_page_has_datadog_correlation_types():
    src = FE_CORRELATIONS.read_text()
    found = set(re.findall(r'"(datadog_[a-z_]+_correlation)"', src))
    assert len(found) >= 10, f"Expected at least 10 correlation types, found {len(found)}: {found!r}"


@pytest.mark.skipif(not FE_CASES.exists(), reason="frontend tree absent")
def test_fe_cases_page_has_datadog_demo_card():
    src = FE_CASES.read_text()
    assert "datadog" in src.lower()


@pytest.mark.skipif(not FE_CASES.exists(), reason="frontend tree absent")
def test_fe_cases_page_no_forbidden_wording():
    src = FE_CASES.read_text()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in src.lower(), (
            f"Forbidden phrase {phrase!r} in cases page"
        )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="frontend tree absent")
def test_fe_demo_script_page_marks_datadog_demo_true():
    src = FE_DEMO_SCRIPT_PAGE.read_text()
    assert "datadog" in src.lower()
    assert re.search(r'datadog.*demo.*true|demo.*true.*datadog', src, re.IGNORECASE | re.DOTALL)


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="frontend tree absent")
def test_fe_demo_script_lib_mentions_datadog():
    src = FE_DEMO_SCRIPT_LIB.read_text()
    assert "Datadog" in src or "datadog" in src


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="frontend tree absent")
def test_fe_rule_catalog_includes_all_31_datadog_rules():
    src = FE_RULE_CATALOG.read_text()
    found = set(re.findall(r'"(datadog_[a-z_]+)"', src))
    missing = EXPECTED_RULE_KEYS - found
    assert missing == set(), f"Rule catalog missing Datadog keys: {missing!r}"


@pytest.mark.skipif(not FE_API.exists(), reason="frontend tree absent")
def test_fe_api_has_datadog_activity_sync():
    src = FE_API.read_text()
    assert "syncDatadogActivity" in src or "datadog-activity/sync" in src


@pytest.mark.skipif(not FE_API.exists(), reason="frontend tree absent")
def test_fe_api_has_datadog_signal_generate():
    src = FE_API.read_text()
    assert "generateDatadogActivitySignals" in src


@pytest.mark.skipif(not FE_API.exists(), reason="frontend tree absent")
def test_fe_api_has_datadog_correlations_generate():
    src = FE_API.read_text()
    assert "generateDatadogCorrelations" in src


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="frontend tree absent")
def test_fe_providers_datadog_in_connectable_ids():
    src = FE_PROVIDERS.read_text()
    idx = src.find("CONNECTABLE_PROVIDER_IDS")
    assert idx >= 0
    snippet = src[idx: idx + 500]
    assert '"datadog"' in snippet or "'datadog'" in snippet


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="frontend tree absent")
def test_fe_providers_datadog_not_in_security_preview_ids():
    src = FE_PROVIDERS.read_text()
    idx = src.find("SECURITY_PREVIEW_PROVIDER_IDS")
    assert idx >= 0
    snippet = src[idx: idx + 300]
    assert '"datadog"' not in snippet and "'datadog'" not in snippet


# ════════════════════════════════════════════════════════════════════════════
# H. Regression smoke
# ════════════════════════════════════════════════════════════════════════════


def test_evaluator_handles_all_10_dd_record_types():
    records = [
        _healthy_monitor(), _healthy_slo(), _healthy_dashboard(), _healthy_webhook(),
        _healthy_notification_integration(), _healthy_api_key(), _healthy_application_key(),
        _healthy_role(), _healthy_team(), _healthy_cloud_integration(),
    ]
    for rec in records:
        result = dd_eval(rec)
        assert isinstance(result, list), f"evaluate() must return list for {rec['record_type']}"


def test_signal_service_maps_all_32_event_types():
    """Every activity event type must map to a known signal type."""
    mapping = dd_sig.DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE
    for evt in EXPECTED_ACTIVITY_EVENT_TYPES:
        sig_type = mapping.get(evt)
        assert sig_type is not None, f"Event type {evt!r} unmapped to a signal type"
        assert sig_type in EXPECTED_SIGNAL_TYPES, (
            f"Signal type {sig_type!r} for event {evt!r} is not in EXPECTED_SIGNAL_TYPES"
        )


def test_event_type_to_signal_type_map_covers_all_32():
    assert len(dd_sig.DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE) == 32, (
        f"DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE should have 32 entries; "
        f"has {len(dd_sig.DATADOG_EVENT_TYPE_TO_SIGNAL_TYPE)}"
    )


def test_correlation_families_cover_expected_types():
    src = inspect.getsource(dd_corr)
    for ct in EXPECTED_CORRELATION_TYPES:
        assert ct in src, f"Correlation type {ct!r} not found in correlation service"


def test_ingestion_normalize_strips_disallowed_event_type():
    raw = {
        "event_type": "datadog.user.login",  # raw audit — must be blocked
        "provider": "datadog",
        "source": "datadog_activity_event",
        "event_source": "datadog_activity_event",
        "provider_event_id": "login_123",
        "metadata": {},
    }
    result = dd_ingest.normalize_datadog_activity_event(raw)
    assert result is None, "normalize must block non-allowlisted event types"


def test_ingestion_normalize_accepts_allowlisted_event_type():
    raw = {
        "event_type": "datadog.monitor.updated",
        "provider": "datadog",
        "source": "datadog_activity_event",
        "event_source": "datadog_activity_event",
        "provider_event_id": "mon_updated_123",
        "metadata": {"monitor_id": "mon_001"},
    }
    result = dd_ingest.normalize_datadog_activity_event(raw)
    assert result is not None


def test_webhook_fallback_record_has_m82c_fields():
    """M82H fix: webhook per-fetch fallback must include all 6 M82C schema fields."""
    dd_src = inspect.getsource(__import__("app.connectors.datadog", fromlist=["datadog"]))
    fallback_idx = dd_src.find("# Per-webhook fetch failure is non-fatal")
    if fallback_idx == -1:
        fallback_idx = dd_src.find('"url_present": True')
    assert fallback_idx >= 0, "Could not locate webhook fallback record in connector"
    # Use a 1500-char window to capture all 6 M82C fields
    snippet = dd_src[fallback_idx: fallback_idx + 1500]
    for field in ("url_scheme_category", "custom_header_count", "auth_material_present",
                  "payload_template_length_category", "secret_headers_count", "encode_as_category"):
        assert field in snippet, (
            f"M82C field {field!r} missing from webhook per-fetch ConnectorError fallback record"
        )


# ════════════════════════════════════════════════════════════════════════════
# I. Capability matrix + expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_drift_flags():
    cap = get_provider_capability("datadog")
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True


def test_capability_matrix_security_flags():
    cap = get_provider_capability("datadog")
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True


def test_capability_matrix_evidence_timeline_and_graph():
    """M82H fix: evidence_timeline and evidence_graph must be True (Stage 6 + parity)."""
    cap = get_provider_capability("datadog")
    assert cap.security.evidence_timeline is True, (
        "evidence_timeline should be True — Stage 6 (demo_qa) mandates it and "
        "Datadog's timeline works (_TIMELINE_PROVIDER_LABELS includes 'datadog')"
    )
    assert cap.security.evidence_graph is True, (
        "evidence_graph should be True — Stage 6 (demo_qa) mandates it and "
        "Datadog's evidence graph works (build_case_evidence_graph is provider-agnostic)"
    )


def test_capability_matrix_maturity_partial():
    cap = get_provider_capability("datadog")
    assert cap.maturity == "partial"


def test_capability_matrix_category_observability():
    cap = get_provider_capability("datadog")
    assert cap.category == "observability"


def test_capability_matrix_notes_mention_m82h():
    cap = get_provider_capability("datadog")
    notes = cap.notes or ""
    assert "M82H" in notes, (
        f"Capability matrix notes should reference M82H QA; got: {notes[:200]!r}"
    )


def test_expansion_framework_points_past_m82i():
    """M82I complete: planned_next_stage must advance to M83A (Clerk) after Datadog arc."""
    framework = get_framework()
    planned = framework["summary"].get("planned_next_stage", "")
    assert ("M83A" in planned or "Clerk" in planned or "M84A" in planned or "PagerDuty" in planned
            or "M85A" in planned or "Linear" in planned
            or "M86" in planned or "Jira" in planned
            or "M87" in planned or "GitLab" in planned), (
        f"planned_next_stage should reference M83A/Clerk or later; got: {planned!r}"
    )


def test_expansion_framework_not_pointing_to_m82_current():
    """M82 arc is complete; planned_next_stage must be past it."""
    framework = get_framework()
    planned = framework["summary"].get("planned_next_stage", "")
    assert "M82H" not in planned and "M82I" not in planned, (
        f"planned_next_stage still points at an M82 milestone (arc complete); "
        f"should advance to M83A: {planned!r}"
    )


def test_expansion_framework_pagerduty_at_head_of_queue():
    # M83A shipped Clerk; PagerDuty is now the head.
    framework = get_framework()
    recs = framework.get("recommended_next_providers", [])
    assert recs, "RECOMMENDED_NEXT_PROVIDERS is empty"
    # After M84A, PagerDuty launched; Linear is now at head.
    assert recs[0]["provider"] in ("pagerduty", "linear", "jira", "gitlab"), (
        f"PagerDuty or Linear should be head of RECOMMENDED_NEXT_PROVIDERS; got: {recs[0]['provider']!r}"
    )


def test_expansion_framework_recommended_milestones_dont_reuse_shipped():
    """All recommended-next milestone numbers must be >= 84 (past the Clerk M83 arc)."""
    framework = get_framework()
    recs = framework.get("recommended_next_providers", [])
    for rec in recs:
        first_milestone = rec.get("first_milestone_name", "")
        m = re.search(r"M(\d+)A", first_milestone)
        if m:
            milestone_num = int(m.group(1))
            assert milestone_num >= 84, (
                f"Recommended provider {rec['provider']!r} first_milestone_name "
                f"{first_milestone!r} reuses milestone M{milestone_num} which was "
                f"already shipped (M80=SendGrid, M81=Auth0, M82=Datadog, M83=Clerk)"
            )


def test_expansion_framework_datadog_not_in_recommended():
    framework = get_framework()
    recs = framework.get("recommended_next_providers", [])
    providers = [r["provider"] for r in recs]
    assert "datadog" not in providers, (
        "Datadog is launched; it must not appear in RECOMMENDED_NEXT_PROVIDERS"
    )


def test_expansion_framework_arc_not_abandoned():
    framework = get_framework()
    planned = framework["summary"].get("planned_next_stage", "")
    assert ("M82" in planned or "M83" in planned or "M84" in planned
            or "M85A" in planned or "Linear" in planned
            or "M86" in planned or "Jira" in planned
            or "M87" in planned or "GitLab" in planned), (
        f"Datadog arc appears abandoned in expansion framework: {planned!r}"
    )
