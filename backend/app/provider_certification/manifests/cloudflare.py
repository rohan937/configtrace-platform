"""Cloudflare certification manifest (message 4 of N).

Cloudflare is zone-scoped only (credentials are ``api_token`` + ``zone_id``,
both unprefixed — an "original-era" provider predating the
``<provider>_field`` naming convention, like Kubernetes/GitHub/GitLab).
There is no separate account-level credential or record family.

Two genuine discovery limitations were found and handled via a
provider-specific adapter (not by inventing new generic behavior that
would affect other providers):

1. Credential fields (``api_token``, ``zone_id``) carry no ``cloudflare_``
   prefix, so generic ``discover_credential_schema_fields`` finds nothing.
2. Change classification for Cloudflare is split across TWO risk-rule
   modules: ``risk_rules/cloudflare.py`` (7 of the 8 record types, via a
   single ``classify_cloudflare_change`` dispatcher) and
   ``risk_rules/cloudflare_dns.py`` (``cloudflare_ruleset``, routed there
   directly by ``risk_service.py``, plus the DNS-record fallthrough path).
   Generic ``discover_classifier_record_type_dispatch`` only imports the
   single ``risk_rules/<provider>.py`` module, so it correctly finds 7 of
   8 and needs the adapter to add the ruleset route.

DNS records ARE collected and classified (via ``classify_dns_change`` in
``risk_rules/cloudflare_dns.py``), but their ``record_type`` field holds
the raw DNS RR type (``"A"``, ``"CNAME"``, ...) rather than a fixed
schema constant — ``CLOUDFLARE_DNS_RECORD`` is declared in
``cloudflare_schema.py`` but never actually assigned anywhere (confirmed
by grep: the connector's ``_normalize()`` sets
``"record_type": raw["type"]``). This is a genuine, confirmed connector
architecture, not a bug — the framework's static discovery has no way to
represent a dynamically-valued record_type family, so it is intentionally
excluded from ``expected_record_types`` and documented in
``known_limitations`` rather than forced into the taxonomy.
"""

from __future__ import annotations

from app.provider_certification import adapters as adapt
from app.provider_certification import discovery as disc
from app.provider_certification.models import (
    FindingChangeParityEvidence,
    FindingReachabilityEvidence,
    ProviderCertificationManifest,
)
from app.provider_certification.runner import register_manifest

_EXPECTED_RECORD_TYPES = (
    "cloudflare_access_application",
    "cloudflare_access_policy",
    "cloudflare_page_rule",
    "cloudflare_ruleset",
    "cloudflare_waf_rule",
    "cloudflare_worker_route",
    "cloudflare_worker_script",
    "cloudflare_zone_setting",
)

_FINDING_RULE_IDS = (
    "cloudflare_access_application_disabled",
    "cloudflare_access_policy_bypass",
    "cloudflare_access_policy_disabled",
    "cloudflare_always_https_off",
    "cloudflare_development_mode_on",
    "cloudflare_dns_private_origin",
    "cloudflare_hsts_disabled",
    "cloudflare_min_tls_weak",
    "cloudflare_page_rule_http_forward",
    "cloudflare_security_level_low",
    "cloudflare_ssl_mode_weak",
    "cloudflare_waf_rule_disabled",
)

_CREDENTIAL_FIELDS = ("api_token", "zone_id")


def _discover_cloudflare_credential_fields() -> frozenset[str] | None:
    from app.schemas.integration import IntegrationCreateRequest

    found = frozenset(f for f in _CREDENTIAL_FIELDS if f in IntegrationCreateRequest.model_fields)
    return found or None


def _discover_cloudflare_classifier_record_types() -> frozenset[str] | None:
    direct = disc.discover_classifier_record_type_dispatch("cloudflare")
    # "cloudflare_ruleset" is routed by risk_service.py directly to
    # risk_rules/cloudflare_dns.py's classify_cloudflare_ruleset_change —
    # a second module the single-module generic scan can't see.
    try:
        import inspect

        from app.services import risk_service

        text = inspect.getsource(risk_service)
        if (
            'record_type == "cloudflare_ruleset"' in text
            and "classify_cloudflare_ruleset_change" in text
        ):
            direct = direct | {"cloudflare_ruleset"}
    except ImportError:
        pass
    return direct or None


_CLOUDFLARE_ADAPTER = adapt.ProviderDiscoveryAdapter(
    provider_id="cloudflare",
    discover_credential_fields=_discover_cloudflare_credential_fields,
    discover_classifier_record_types=_discover_cloudflare_classifier_record_types,
    note=(
        "Credential fields (api_token, zone_id) carry no 'cloudflare_' "
        "prefix. Classifier dispatch for 'cloudflare_ruleset' is routed by "
        "risk_service.py directly to risk_rules/cloudflare_dns.py — a "
        "second module the generic single-module scan of "
        "risk_rules/cloudflare.py cannot see."
    ),
)
adapt.register_adapter(_CLOUDFLARE_ADAPTER)


CLOUDFLARE_MANIFEST = ProviderCertificationManifest(
    provider_id="cloudflare",
    display_name="Cloudflare",
    category="edge_network",
    maturity="complete",
    expected_public=True,
    expected_connectable=True,
    expected_live=True,
    credential_fields=_CREDENTIAL_FIELDS,
    sensitive_credential_fields=("api_token",),
    authentication_model="api_token",
    expected_record_types=_EXPECTED_RECORD_TYPES,
    security_finding_rule_ids=_FINDING_RULE_IDS,
    supported_capabilities=(
        "security_findings",
        "activity_ingestion",
        "activity_signals",
        "risk_activity_correlations",
        "demo_case_reporting",
    ),
    unsupported_capabilities=(),
    completeness_scopes=(),
    false_removal_scopes=(),
    expected_frontend_form="CloudflareIntegrationForm.tsx",
    expected_reconnect=True,
    prohibited_dependencies=(),
    known_limitations=(
        "DNS records ARE collected and classified, but their record_type "
        "field holds the raw DNS RR type (e.g. 'A', 'CNAME') rather than "
        "the unused 'cloudflare_dns_record' schema constant — the "
        "framework's static discovery cannot represent a dynamically-"
        "valued record-type family, so DNS is intentionally excluded from "
        "expected_record_types rather than forced into the taxonomy.",
        "Zone-scoped only: there is no separate account-level credential "
        "or record family (single api_token + zone_id pair).",
        "No false-removal suppression function exists for Cloudflare yet "
        "(diff_service has no _cloudflare_removal_suppressed) — "
        "completeness_scopes/false_removal_scopes are honestly declared "
        "empty rather than claiming protection that doesn't exist.",
        "No request/traffic analytics, no customer traffic ingestion, no "
        "DNS query logs — only zone configuration metadata is collected.",
        "Workers/Pages coverage is limited to worker route/script "
        "metadata already implemented; no runtime request or event data "
        "is ingested from Workers.",
    ),
    evidence_test_files=(
        "tests/test_milestone60_4_3_cloudflare_rules.py",
        "tests/test_cloudflare_risk_audit.py",
    ),
    reachability_evidence=(
        FindingReachabilityEvidence(
            provider_id="cloudflare",
            test_file="tests/test_milestone60_4_3_cloudflare_rules.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=20,
            quality="direct",
        ),
    ),
    change_parity_evidence=(
        FindingChangeParityEvidence(
            provider_id="cloudflare",
            test_file="tests/test_cloudflare_risk_audit.py",
            test_selector="",
            covered_rule_ids=_FINDING_RULE_IDS,
            minimum_test_count=40,
            quality="direct",
        ),
    ),
)

register_manifest(CLOUDFLARE_MANIFEST)
