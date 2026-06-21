"""Twilio provider depth QA.

Durable, mostly-static guardrails that pin the full Twilio rule taxonomy
across every registration surface and validate the privacy / claim-discipline
invariants for the Twilio provider, plus the central-evaluator wiring that
makes Twilio rules actually fire during snapshot evaluation.

  TestTwilioRuleRegistration       — all 17 Twilio rule keys present in the
                                     module export, registry, confidence map,
                                     rule pack, and coverage service.
  TestTwilioFrontendCatalogParity  — all 17 keys appear in the TypeScript
                                     securityRuleCatalog.ts with matching
                                     severities.
  TestTwilioEvidenceSafety         — fired-rule evidence is flat and carries
                                     no secret / token / PII / raw keys.
  TestTwilioCopySafety             — rule copy carries no forbidden
                                     (breach-style) wording.
  TestTwilioEvaluatorDispatch      — "twilio" is wired into the central
                                     evaluator and produces findings through it.
  TestTwilioExpansionFramework     — expansion framework points at M89A
                                     Kubernetes; Twilio is not the next stage.
  TestTwilioProviderCapabilityMatrix — Twilio is implemented (partial);
                                     Kubernetes is not yet implemented.

Pure unit tests: the registry / catalog / copy / severity checks read Python
dicts and the TypeScript catalog as text and require no database connection.
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

TWILIO_RULES_FILE = BACKEND / "services" / "security_rules" / "twilio.py"
FE_RULE_CATALOG = FRONTEND / "lib" / "securityRuleCatalog.ts"

CANONICAL_PROVIDER = "twilio"

# ── Canonical Twilio rule set (the 17 shipped rules) ──────────────────────────

TWILIO_RULE_KEYS = [
    "twilio_phone_number_sms_webhook_missing",
    "twilio_phone_number_voice_webhook_missing",
    "twilio_phone_number_status_callback_missing",
    "twilio_messaging_service_inbound_webhook_missing",
    "twilio_messaging_service_fallback_missing",
    "twilio_messaging_service_status_callback_missing",
    "twilio_verify_short_code_length",
    "twilio_verify_lookup_disabled",
    "twilio_account_suspended",
    "twilio_api_key_stale",
    "twilio_messaging_service_observability_gap",
    "twilio_messaging_service_number_level_inbound_webhook",
    "twilio_messaging_service_long_validity_period",
    "twilio_phone_number_messaging_observability_gap",
    "twilio_phone_number_voice_observability_gap",
    "twilio_verify_psd2_disabled",
    "twilio_verify_sms_to_landlines_allowed",
]

ALL_TWILIO_RULE_KEYS: frozenset[str] = frozenset(TWILIO_RULE_KEYS)

# Forbidden claim wording — never in Twilio rule code or user-facing copy
# (except inside an explicit negating disclaimer or a denylist constant).
FORBIDDEN_PHRASES = [
    "breach",
    "compromise",
    "leaked",
    "attacker",
    "exfiltration",
    "unauthorized access",
    "stolen",
    "fraud",
    "attack",
    "messages exposed",
    "phone numbers exposed",
    "sms fraud",
    "toll fraud",
]

# Evidence dicts must never carry secret-bearing / PII-bearing / raw keys.
FORBIDDEN_EVIDENCE_KEYS = [
    "auth_token",
    "api_secret",
    "token",
    "oauth_token",
    "authorization",
    "headers",
    "payload",
    "request",
    "response",
    "raw",
    "secret",
    "secret_value",
    "webhook_secret",
    "message_body",
    "sms_body",
    "mms_media_url",
    "customer_phone",
    "customer_email",
    "customer_name",
    "address",
    "call_recording",
    "transcript",
    "verification_code",
    "lookup_result",
    "customer",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rule_key(f: Any) -> str:
    return f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")


def _severity(f: Any) -> str:
    return f.severity if hasattr(f, "severity") else f.get("severity", "")


def _evidence(f: Any) -> dict:
    ev = f.evidence if hasattr(f, "evidence") else f.get("evidence", {})
    return ev if isinstance(ev, dict) else {}


def _title(f: Any) -> str:
    return (f.title if hasattr(f, "title") else f.get("title", "")) or ""


def _description(f: Any) -> str:
    return (f.description if hasattr(f, "description") else f.get("description", "")) or ""


def _tw_eval(record: dict) -> list[Any]:
    from app.services.security_rules.twilio import evaluate
    return evaluate(record)


def _all_twilio_findings() -> list[Any]:
    """Fire every Twilio rule across a set of representative risky records.

    Field names mirror the canonical connector-normalizer schema consumed by
    ``security_rules.twilio.evaluate`` (as exercised by the M79B/M79C tests).
    """
    from datetime import datetime, timedelta, timezone

    from app.connectors.twilio_schema import (
        TWILIO_ACCOUNT,
        TWILIO_API_KEY_SUMMARY,
        TWILIO_INCOMING_PHONE_NUMBER,
        TWILIO_MESSAGING_SERVICE,
        TWILIO_VERIFY_SERVICE,
    )

    old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()

    records: list[dict] = [
        # Phone number: SMS + voice capable, nothing configured → SMS webhook
        # missing, voice webhook missing, status callback missing, messaging
        # observability gap, voice observability gap (5 rules).
        {
            "record_type": TWILIO_INCOMING_PHONE_NUMBER,
            "record_id": "PNdepth01",
            "phone_number_sid": "PNdepth01",
            "friendly_name": "Depth Phone",
            "phone_number_last4": "4321",
            "iso_country": "US",
            "capability_sms": True,
            "capability_voice": True,
            "sms_url_configured": False,
            "voice_url_configured": False,
            "status_callback_configured": False,
        },
        # Messaging service: no inbound webhook, no fallback, no status callback
        # → inbound webhook missing, fallback missing, status callback missing,
        # observability gap (4 rules).
        {
            "record_type": TWILIO_MESSAGING_SERVICE,
            "record_id": "MGdepth01",
            "messaging_service_sid": "MGdepth01",
            "friendly_name": "Depth Messaging",
            "inbound_request_url_configured": False,
            "use_inbound_webhook_on_number": False,
            "fallback_url_configured": False,
            "status_callback_url_configured": False,
            "validity_period": 100000,  # > 86400 → long validity
        },
        # Messaging service: number-level inbound delegation (separate record so
        # it does not collide with the inbound-webhook-missing rule).
        {
            "record_type": TWILIO_MESSAGING_SERVICE,
            "record_id": "MGdepth02",
            "messaging_service_sid": "MGdepth02",
            "friendly_name": "Depth Messaging 2",
            "inbound_request_url_configured": False,
            "use_inbound_webhook_on_number": True,
            "fallback_url_configured": True,
            "status_callback_url_configured": True,
        },
        # Verify service: short code + lookup disabled + psd2 disabled + landline
        # SMS allowed (4 rules).
        {
            "record_type": TWILIO_VERIFY_SERVICE,
            "record_id": "VAdepth01",
            "verify_service_sid": "VAdepth01",
            "friendly_name": "Depth Verify",
            "code_length": 4,
            "lookup_enabled": False,
            "psd2_enabled": False,
            "skip_sms_to_landlines": False,
        },
        # Account: non-active status → account suspended (1 rule).
        {
            "record_type": TWILIO_ACCOUNT,
            "record_id": "twilio_account_DEPTH",
            "account_sid_prefix": "DEPTH",
            "friendly_name": "Depth Account",
            "status": "suspended",
            "account_type": "Full",
        },
        # API key: not updated in 200 days → stale (1 rule).
        {
            "record_type": TWILIO_API_KEY_SUMMARY,
            "record_id": "SKdepth01",
            "api_key_sid": "SKdepth01",
            "friendly_name": "Depth Key",
            "date_created": old,
            "date_updated": old,
        },
    ]
    out: list[Any] = []
    for r in records:
        out.extend(_tw_eval(r))
    return out


# ── TestTwilioRuleRegistration ────────────────────────────────────────────────

class TestTwilioRuleRegistration:
    def test_rule_key_count_is_seventeen(self) -> None:
        assert len(ALL_TWILIO_RULE_KEYS) == 17

    def test_module_export_matches_canonical_set(self) -> None:
        from app.services.security_rules.twilio import TWILIO_RULE_KEYS as MOD_KEYS
        assert set(MOD_KEYS) == ALL_TWILIO_RULE_KEYS

    def test_all_keys_in_registry(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for key in ALL_TWILIO_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS, f"{key!r} missing from KNOWN_RULE_KEYS"

    def test_all_keys_in_confidence(self) -> None:
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for key in ALL_TWILIO_RULE_KEYS:
            assert key in RULE_CONFIDENCE, f"{key!r} missing from RULE_CONFIDENCE"

    def test_all_keys_in_rule_pack(self) -> None:
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_TWILIO_RULE_KEYS:
            assert key in _RULE_META, f"{key!r} missing from _RULE_META"
            provider, _sev, _cat = _RULE_META[key]
            assert provider == CANONICAL_PROVIDER, (
                f"{key!r} wrong provider: {provider!r}"
            )

    def test_all_keys_in_coverage(self) -> None:
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in ALL_TWILIO_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, f"{key!r} missing from RULE_RECORD_TYPES"
            assert RULE_RECORD_TYPES[key], f"{key!r} has empty record-type tuple"

    def test_registry_has_no_unexpected_twilio_keys(self) -> None:
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        reg = {k for k in KNOWN_RULE_KEYS if k.startswith("twilio")}
        extra = reg - ALL_TWILIO_RULE_KEYS
        assert not extra, f"unexpected twilio keys in registry: {sorted(extra)}"


# ── TestTwilioFrontendCatalogParity ───────────────────────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
class TestTwilioFrontendCatalogParity:
    def _catalog_text(self) -> str:
        return FE_RULE_CATALOG.read_text(encoding="utf-8")

    def test_all_keys_present_in_catalog(self) -> None:
        text = self._catalog_text()
        missing = [k for k in ALL_TWILIO_RULE_KEYS if f'key: "{k}"' not in text]
        assert not missing, (
            f"Twilio rule keys missing from frontend catalog: {missing}"
        )

    def test_catalog_keys_match_via_regex(self) -> None:
        text = self._catalog_text()
        found = set(re.findall(r'key:\s*"(twilio_[a-z0-9_]+)"', text))
        missing = ALL_TWILIO_RULE_KEYS - found
        assert not missing, (
            f"Regex did not find Twilio keys in catalog: {sorted(missing)}"
        )

    def test_catalog_has_no_unexpected_twilio_keys(self) -> None:
        text = self._catalog_text()
        found = set(re.findall(r'key:\s*"(twilio_[a-z0-9_]+)"', text))
        extra = found - ALL_TWILIO_RULE_KEYS
        assert not extra, (
            f"Unexpected twilio keys in frontend catalog: {sorted(extra)}"
        )

    def test_catalog_severity_matches_backend_pack(self) -> None:
        text = self._catalog_text()
        from app.services.security_rule_pack import _RULE_META
        for key in ALL_TWILIO_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            assert idx != -1, f"Twilio rule {key!r} not found in frontend catalog"
            block = text[idx:idx + 900]
            _provider, expected_sev, _cat = _RULE_META[key]
            assert f'severity: "{expected_sev}"' in block, (
                f"Frontend severity for {key!r} does not match backend "
                f"({expected_sev!r})"
            )

    def test_catalog_provider_is_canonical(self) -> None:
        text = self._catalog_text()
        for key in ALL_TWILIO_RULE_KEYS:
            idx = text.find(f'key: "{key}"')
            block = text[idx:idx + 900]
            assert 'provider: "twilio"' in block, (
                f"Frontend catalog entry for {key!r} must use provider 'twilio'"
            )


# ── TestTwilioEvidenceSafety ──────────────────────────────────────────────────

class TestTwilioEvidenceSafety:
    def test_synthetic_records_fire_every_rule(self) -> None:
        fired = {_rule_key(f) for f in _all_twilio_findings()}
        missing = ALL_TWILIO_RULE_KEYS - fired
        assert not missing, f"Synthetic records did not fire rules: {sorted(missing)}"

    def test_evidence_has_no_forbidden_keys(self) -> None:
        findings = _all_twilio_findings()
        assert findings, "expected at least one finding across representative records"
        for f in findings:
            ev_keys = {k.lower() for k in _evidence(f)}
            for forbidden in FORBIDDEN_EVIDENCE_KEYS:
                assert forbidden not in ev_keys, (
                    f"Forbidden evidence key {forbidden!r} in finding "
                    f"{_rule_key(f)!r}: {sorted(ev_keys)}"
                )

    def test_evidence_is_flat_safe_scalars(self) -> None:
        # Twilio evidence is metadata-only: scalars or lists of scalars; no
        # nested dicts or lists-of-dicts.
        def _is_safe_scalar(x: Any) -> bool:
            return isinstance(x, (str, int, float, bool, type(None)))

        for f in _all_twilio_findings():
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


# ── TestTwilioCopySafety ──────────────────────────────────────────────────────

class TestTwilioCopySafety:
    _NEGATION_TOKENS = (
        "does not confirm", "never assert", "never claim", "do not claim",
        "is not a claim", "without claiming", "claim discipline",
        "claim-discipline", "without overclaim", "doesn't confirm",
        "forbidden", "not confirm", "denylist", "negating",
        # Module-docstring claim-discipline disclaimer (the CLAIM DISCIPLINE
        # block in security_rules.twilio explicitly enumerates the claims these
        # rules NEVER make). These are negating disclaimers, not assertions.
        "it never asserts", "intercepted, that calls were",
        "that a breach occurred", "does not", "not detect breaches",
        "may indicate", "evidence for review",
    )

    def _strip_negation_lines(self, src: str) -> str:
        out = []
        for line in src.splitlines():
            low = line.lower()
            if any(tok in low for tok in self._NEGATION_TOKENS):
                continue
            out.append(line)
        return "\n".join(out)

    def test_no_forbidden_wording_in_rules_module(self) -> None:
        from app.services.security_rules import twilio as tw_rules
        src = inspect.getsource(tw_rules).lower()
        # Collapse Python adjacent-string-literal concatenation so multi-line
        # disclaimers (split across "..." "..." literals) become contiguous,
        # then remove the canonical negating disclaimers wholesale. What
        # remains is asserting copy, which must carry no forbidden wording.
        src = re.sub(r'"\s*\n\s*[a-z]*"', " ", src)  # join "..."\n f"..." breaks
        src = re.sub(r'"\s+"', " ", src)             # join adjacent " " " "
        src = re.sub(r"\s+", " ", src)
        for disclaimer in (
            "this is evidence for review and does not confirm compromise, "
            "unauthorized access, or data exposure.",
            "this is evidence for review and does not confirm compromise or "
            "unauthorized access.",
            "it never asserts unauthorized access, that messages were "
            "intercepted, that calls were compromised, that customer data was "
            "exposed, that a breach occurred, or that any attacker is present.",
            "it does not detect breaches.",
        ):
            src = src.replace(disclaimer, " ")
        # Drop any residual line that still explicitly negates a claim.
        src = self._strip_negation_lines(src)
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in src, (
                f"forbidden phrase {phrase!r} present in security_rules.twilio "
                f"outside a negation/denylist context"
            )

    def test_no_forbidden_wording_in_finding_copy(self) -> None:
        for f in _all_twilio_findings():
            # Strip the per-finding claim-discipline disclaimer, which legitimately
            # contains negated forbidden words ("does not confirm compromise...").
            blob = f"{_title(f)}\n{_description(f)}"
            blob = self._strip_negation_lines(blob).lower()
            # Also drop the canonical disclaimer sentence wholesale.
            blob = blob.replace(
                "this is evidence for review and does not confirm compromise, "
                "unauthorized access, or data exposure.", ""
            )
            for phrase in FORBIDDEN_PHRASES:
                assert phrase not in blob, (
                    f"Finding {_rule_key(f)!r} copy contains forbidden phrase "
                    f"{phrase!r}"
                )


# ── TestTwilioEvaluatorDispatch ───────────────────────────────────────────────

class TestTwilioEvaluatorDispatch:
    def test_twilio_in_provider_rules(self) -> None:
        from app.services.security_finding_evaluator import _PROVIDER_RULES
        assert "twilio" in _PROVIDER_RULES, (
            "twilio missing from security_finding_evaluator._PROVIDER_RULES"
        )
        assert _PROVIDER_RULES["twilio"], "twilio dispatch list is empty"

    def test_central_evaluator_produces_a_twilio_finding(self) -> None:
        from app.connectors.twilio_schema import TWILIO_INCOMING_PHONE_NUMBER
        from app.services.security_finding_evaluator import evaluate_record
        rec = {
            "record_type": TWILIO_INCOMING_PHONE_NUMBER,
            "record_id": "PNdispatch01",
            "phone_number_sid": "PNdispatch01",
            "friendly_name": "Dispatch Test Number",
            "phone_number_last4": "4321",
            "iso_country": "US",
            "capability_sms": True,
            "capability_voice": False,
            "sms_url_configured": False,
            "voice_url_configured": True,
            "status_callback_configured": True,
        }
        candidates = evaluate_record(rec, "twilio")
        assert candidates, "central evaluator produced no Twilio findings"
        keys = {c.rule_key for c in candidates}
        assert "twilio_phone_number_sms_webhook_missing" in keys, (
            f"expected sms webhook missing finding via central dispatch; got {keys}"
        )


# ── TestTwilioExpansionFramework ──────────────────────────────────────────────

class TestTwilioExpansionFramework:
    def test_planned_next_stage_points_at_kubernetes(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        stage = get_framework()["summary"]["planned_next_stage"]
        assert "M89A" in stage or "Kubernetes" in stage, (
            f"planned_next_stage should reference M89A Kubernetes, got {stage!r}"
        )

    def test_twilio_is_not_the_next_stage(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        stage = get_framework()["summary"]["planned_next_stage"].lower()
        assert "twilio" not in stage, (
            f"Twilio must not be the planned_next_stage, got {stage!r}"
        )

    def test_twilio_not_in_recommended_queue(self) -> None:
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        providers = [r["provider"] for r in fw["recommended_next_providers"]]
        assert CANONICAL_PROVIDER not in providers, (
            "Twilio has launched and must not be in the recommended queue"
        )


# ── TestTwilioProviderCapabilityMatrix ────────────────────────────────────────

class TestTwilioProviderCapabilityMatrix:
    def test_twilio_present_with_expected_capabilities(self) -> None:
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability(CANONICAL_PROVIDER)
        assert cap is not None, "Twilio missing from provider capability matrix"
        assert cap.provider == CANONICAL_PROVIDER
        assert cap.security.security_rules is True
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True
        assert cap.maturity == "partial"

    def test_twilio_capability_count_matches_rule_set(self) -> None:
        """The Twilio rule pack must expose exactly the 17 canonical rules."""
        from app.services.security_rule_pack import _RULE_META
        twilio_keys = {k for k, v in _RULE_META.items() if v[0] == CANONICAL_PROVIDER}
        assert twilio_keys == ALL_TWILIO_RULE_KEYS, (
            f"Twilio rule-pack key set drift. Missing: "
            f"{ALL_TWILIO_RULE_KEYS - twilio_keys}; Extra: "
            f"{twilio_keys - ALL_TWILIO_RULE_KEYS}"
        )

    def test_kubernetes_is_not_yet_implemented(self) -> None:
        """Guard against accidental introduction of a Kubernetes provider."""
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        assert get_provider_capability("kubernetes") is None, (
            "Kubernetes must not be implemented yet — it is still in the "
            "recommended-next queue"
        )

    def test_kubernetes_connector_does_not_exist(self) -> None:
        """The Kubernetes provider connector module must not exist yet."""
        k8s_connector = BACKEND / "connectors" / "kubernetes.py"
        assert not k8s_connector.exists(), (
            "Kubernetes connector should not exist yet (provider not implemented)"
        )
