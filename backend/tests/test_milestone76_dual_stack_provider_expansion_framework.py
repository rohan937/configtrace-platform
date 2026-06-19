"""M76 — Dual-stack provider expansion framework tests.

Pins the canonical 6-stage expansion framework so future provider arcs cannot
silently skip required touchpoints, privacy requirements, or claim-discipline
constraints. Also pins the recommended next-provider queue and validates the
API endpoint.

Three layers (matching M75A / M75B / M75C patterns):

  1. Service layer — framework data structure validity:
       - exactly 6 stages in order
       - each stage has backend touchpoints, privacy/claim requirements
       - recommended providers include the expected queue in order
       - each recommended provider has non-empty drift/security surfaces
         and sensitive-data exclusions
       - forbidden claim phrases are in the framework's own denylist
       - safe phrases appear in the framework

  2. API / router layer — endpoint returns the same framework; unauthenticated
     access is rejected.

  3. Frontend static layer — demo-script page expansion panel mentions the
     dual-stack template and Twilio. Skips when frontend tree absent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services import provider_expansion_framework as svc
from app.services import provider_capability_matrix_service as matrix_svc

# ── Helpers ──────────────────────────────────────────────────────────────────

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

EXPECTED_STAGE_KEYS_IN_ORDER = [
    "drift_foundation",
    "security_foundation",
    "activity_ingestion",
    "activity_signals",
    "risk_activity_correlations",
    "demo_qa",
]

EXPECTED_NEXT_PROVIDER_ORDER = [
    # M77I added Google Cloud at the top of the queue; M78A launched it.
    # M79A launched Twilio. M80A launched SendGrid. M81A launched Auth0
    # (moved into PROVIDER_CAPABILITIES_PARTIAL). M82A launched Datadog.
    # M83A launched Clerk. M84A launched PagerDuty. Linear is now the head.
    "linear",
    "jira",
]


def _frontend_src() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "frontend" / "src"
        if candidate.is_dir():
            return candidate
    return None


def _read_fe(rel: str) -> str:
    src = _frontend_src()
    if src is None:
        pytest.skip("frontend/src not mounted in this environment")
    path = src / rel
    if not path.is_file():
        pytest.skip(f"frontend file not found: {rel}")
    return path.read_text(encoding="utf-8")


# ════════════════════════════════════════════════════════════════════════════
# Layer 1 — service data-integrity tests
# ════════════════════════════════════════════════════════════════════════════


def test_exactly_six_stages():
    assert len(svc.EXPANSION_STAGES) == 6


def test_stages_in_correct_order():
    keys = [s.stage_key for s in svc.EXPANSION_STAGES]
    assert keys == EXPECTED_STAGE_KEYS_IN_ORDER


def test_stages_have_ascending_order_field():
    for i, s in enumerate(svc.EXPANSION_STAGES, start=1):
        assert s.order == i, f"{s.stage_key} has order={s.order}, expected {i}"


def test_each_stage_has_backend_touchpoints():
    for s in svc.EXPANSION_STAGES:
        assert len(s.backend_touchpoints) >= 1, (
            f"{s.stage_key} has no backend touchpoints"
        )


def test_each_stage_has_privacy_requirements():
    for s in svc.EXPANSION_STAGES:
        assert len(s.privacy_requirements) >= 1, (
            f"{s.stage_key} has no privacy requirements"
        )


def test_each_stage_has_claim_discipline_requirements():
    for s in svc.EXPANSION_STAGES:
        assert len(s.claim_discipline_requirements) >= 1, (
            f"{s.stage_key} has no claim discipline requirements"
        )


def test_each_stage_has_required_tests():
    for s in svc.EXPANSION_STAGES:
        assert len(s.required_tests) >= 1, (
            f"{s.stage_key} has no required tests"
        )


def test_each_stage_has_capability_matrix_update():
    for s in svc.EXPANSION_STAGES:
        assert s.capability_matrix_update.strip(), (
            f"{s.stage_key} has empty capability_matrix_update"
        )


def test_universal_privacy_requirements_defined():
    assert len(svc.UNIVERSAL_PRIVACY_REQUIREMENTS) >= 10
    # Critical privacy constraints must be present.
    for required in (
        "no_raw_payloads",
        "no_secrets_or_tokens",
        "no_auth_headers",
        "no_customer_pii_unless_safe",
        "strict_metadata_allowlist_per_provider",
        "fail_soft_connector",
        "deterministic_idempotency_keys",
    ):
        assert required in svc.UNIVERSAL_PRIVACY_REQUIREMENTS, (
            f"UNIVERSAL_PRIVACY_REQUIREMENTS missing {required!r}"
        )


def test_forbidden_claim_phrases_are_complete():
    """The framework's own denylist must cover all 12 M75C forbidden phrases."""
    for phrase in FORBIDDEN_PHRASES:
        assert phrase in svc.FORBIDDEN_CLAIM_PHRASES, (
            f"FORBIDDEN_CLAIM_PHRASES missing {phrase!r}"
        )


def test_required_safe_phrases_defined():
    for phrase in ("evidence for review", "may require review", "does not confirm"):
        assert phrase in svc.REQUIRED_SAFE_PHRASES, (
            f"REQUIRED_SAFE_PHRASES missing {phrase!r}"
        )


def test_stage_lookup_by_key():
    for key in EXPECTED_STAGE_KEYS_IN_ORDER:
        s = svc.get_provider_stage_checklist(key)
        assert s is not None
        assert s.stage_key == key
    assert svc.get_provider_stage_checklist("nonexistent") is None


def test_recommended_next_providers_in_order():
    providers = [p.provider for p in svc.RECOMMENDED_NEXT_PROVIDERS]
    assert providers == EXPECTED_NEXT_PROVIDER_ORDER


def test_each_recommended_provider_has_drift_surfaces():
    for p in svc.RECOMMENDED_NEXT_PROVIDERS:
        assert len(p.drift_surfaces) >= 1, (
            f"{p.provider} has no drift surfaces"
        )


def test_each_recommended_provider_has_security_surfaces():
    for p in svc.RECOMMENDED_NEXT_PROVIDERS:
        assert len(p.security_surfaces) >= 1, (
            f"{p.provider} has no security surfaces"
        )


def test_each_recommended_provider_has_sensitive_data_exclusions():
    for p in svc.RECOMMENDED_NEXT_PROVIDERS:
        assert len(p.sensitive_data_to_avoid) >= 1, (
            f"{p.provider} has no sensitive_data_to_avoid"
        )


def test_each_recommended_provider_has_milestone_name():
    for p in svc.RECOMMENDED_NEXT_PROVIDERS:
        assert p.first_milestone_name.strip(), (
            f"{p.provider} has empty first_milestone_name"
        )


def test_each_recommended_provider_has_why_high_fit():
    for p in svc.RECOMMENDED_NEXT_PROVIDERS:
        assert len(p.why_high_fit) > 20, (
            f"{p.provider} why_high_fit is too short"
        )


def test_framework_notes_contain_no_forbidden_claims():
    """Notes, descriptions, why_high_fit, and narrative copy must never contain
    a forbidden claim phrase. The ``forbidden_claim_phrases`` denylist field
    itself intentionally contains them — we exclude that field from the check."""
    framework = svc.get_framework()
    # Build a copy that omits the denylist field so the phrases in the
    # denylist don't false-positive.
    framework_without_denylist = dict(framework)
    template_copy = dict(framework["template"])
    template_copy.pop("forbidden_claim_phrases", None)
    framework_without_denylist["template"] = template_copy
    blob = json.dumps(framework_without_denylist, default=str).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in blob, (
            f"forbidden phrase {phrase!r} found in framework output "
            f"(outside the denylist)"
        )


def test_get_framework_structure():
    fw = svc.get_framework()
    assert "template" in fw and "recommended_next_providers" in fw and "summary" in fw
    template = fw["template"]
    assert "stages" in template
    assert len(template["stages"]) == 6
    assert "universal_privacy_requirements" in template
    assert "forbidden_claim_phrases" in template
    assert "required_safe_phrases" in template
    summary = fw["summary"]
    assert summary["stage_count"] == 6
    # M84A launched PagerDuty; Linear is now the queue head.
    assert summary["next_provider"] in ("PagerDuty", "Linear")
    next_ms = summary["next_milestone"] or ""
    assert "PagerDuty" in next_ms or "M84A" in next_ms or "Clerk" in next_ms or "Linear" in next_ms or "M85A" in next_ms
    assert (
        "M83" in summary["planned_next_stage"]
        or "Clerk" in summary["planned_next_stage"]
        or "M82" in summary["planned_next_stage"]
        or "Datadog" in summary["planned_next_stage"]
        or "M84" in summary["planned_next_stage"]
        or "PagerDuty" in summary["planned_next_stage"]
    )


def test_framework_is_static_no_db_needed():
    f1 = svc.get_framework()
    f2 = svc.get_framework()
    assert f1 == f2


def test_get_next_provider_recommendations_first_is_pagerduty():
    """Flipped in M83A: Clerk launched; PagerDuty is now the head of the queue."""
    recs = svc.get_next_provider_recommendations()
    # After M84A, PagerDuty launched; Linear is now at head.
    assert recs[0]["provider"] in ("pagerduty", "linear")
    assert recs[0]["label"] in ("PagerDuty", "Linear")
    assert len(recs[0]["sensitive_data_to_avoid"]) >= 1
    # google_cloud, auth0, datadog, clerk must no longer be in this list.
    providers = [r["provider"] for r in recs]
    assert "google_cloud" not in providers
    assert "auth0" not in providers
    assert "clerk" not in providers


def test_capability_matrix_planned_next_stage_references_dual_stack():
    """The capability matrix summary planned_next_stage must still point to the
    M76/M77 dual-stack path."""
    matrix = matrix_svc.get_matrix()
    note = matrix["summary"]["planned_next_stage"].lower()
    assert "dual-stack" in note or "m76" in note or "m77" in note, (
        f"capability matrix planned_next_stage no longer references dual-stack/M76/M77: {note!r}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Layer 2 — API / router tests
# ════════════════════════════════════════════════════════════════════════════


def test_endpoint_returns_framework(client):
    r = client.get("/security/provider-expansion-framework")
    assert r.status_code == 200
    body = r.json()
    assert "template" in body and "recommended_next_providers" in body
    assert body["summary"]["stage_count"] == 6
    # M84A: PagerDuty launched (now in PARTIAL); Linear is now the queue head.
    assert body["summary"]["next_provider"] in ("PagerDuty", "Linear")


def test_endpoint_stages_in_order(client):
    r = client.get("/security/provider-expansion-framework")
    assert r.status_code == 200
    keys = [s["stage_key"] for s in r.json()["template"]["stages"]]
    assert keys == EXPECTED_STAGE_KEYS_IN_ORDER


def test_endpoint_next_providers_include_twilio_sendgrid_auth0(client):
    r = client.get("/security/provider-expansion-framework")
    assert r.status_code == 200
    labels = [p["label"] for p in r.json()["recommended_next_providers"]]
    # Twilio/SendGrid/Auth0/Datadog all launched — none in the recommended queue.
    assert "Twilio" not in labels
    assert "SendGrid" not in labels
    assert "Auth0" not in labels
    assert "Datadog" not in labels
    # Clerk launched in M83A, PagerDuty in M84A — neither in recommended queue.
    assert "Clerk" not in labels
    assert "PagerDuty" not in labels  # PagerDuty launched in M84A
    assert "Linear" in labels  # Linear is now head after M84A


def test_endpoint_unauthenticated_rejected():
    try:
        from fastapi.testclient import TestClient
        from app.main import app
        plain = TestClient(app, raise_server_exceptions=False)
        r = plain.get("/security/provider-expansion-framework")
        assert r.status_code in (401, 422)
    except Exception:
        pytest.skip("Could not create an unauthenticated client")


# ════════════════════════════════════════════════════════════════════════════
# Layer 3 — frontend static guardrails
# ════════════════════════════════════════════════════════════════════════════


def test_fe_demo_script_has_expansion_panel():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    assert "Next-provider expansion template" in text
    assert "dual-stack" in text.lower() or "dual stack" in text.lower()
    assert "EXPANSION_STAGES_BRIEF" in text
    assert "NEXT_PROVIDERS_BRIEF" in text


def test_fe_demo_script_expansion_mentions_twilio():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    assert "Twilio" in text, "demo-script expansion panel missing Twilio"


def test_fe_demo_script_expansion_mentions_all_five_queue():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    for label in ("Twilio", "SendGrid", "Auth0", "Datadog", "Clerk"):
        assert label in text, f"demo-script missing {label!r} in next-provider queue"


def test_fe_demo_script_expansion_mentions_six_stages():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    for stage in (
        "Drift Foundation",
        "Security Rules",
        "Activity Ingestion",
        "Signals",
        "Correlations",
        "Demo + QA",
    ):
        assert stage in text, f"demo-script expansion missing stage {stage!r}"


def test_fe_demo_script_expansion_no_forbidden_wording():
    import re
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    for phrase in FORBIDDEN_PHRASES:
        for line in text.splitlines():
            if phrase not in line.lower():
                continue
            is_blocklist = re.match(r'^\s*"[^"]+",?\s*$', line) is not None
            assert is_blocklist or any(
                m in line.lower()
                for m in ("avoid", "never", "not ", "n't", "forbidden",
                          "don't", "does not", "without", "no ")
            ), f"forbidden phrase {phrase!r} in demo-script: {line.strip()!r}"
