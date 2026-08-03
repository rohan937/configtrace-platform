"""Slack certification manifest (message 5 of N).

Slack is genuinely NOT a data-sync provider in this repository, unlike
every other provider certified so far. Confirmed via direct grep:

- No ``app/connectors/slack.py`` and no ``SlackConnector`` — no
  ``BaseConnector`` subclass exists for Slack at all.
- No ``app/connectors/slack_schema.py`` — no record-type schema module.
- No ``app/services/risk_rules/slack.py`` — no Finding rule module.
- ``"slack"`` appears in NEITHER
  ``app/services/provider_capability_matrix_service.py`` (no
  ``PROVIDER_CAPABILITIES``/``PROVIDER_CAPABILITIES_PARTIAL`` entry) NOR
  the backend sync-provider list (``sync_service._SUPPORTED_PROVIDERS``)
  NOR the frontend provider list.

What DOES exist is ``app/services/slack_service.py`` and
``app/routers/slack_oauth.py`` — an OUTBOUND OAuth-based alert-routing
integration (ConfigTrace sends notifications TO Slack), architecturally
the opposite direction from every other certified provider (which SYNC
configuration data FROM the provider INTO ConfigTrace).

This manifest is declared with ``maturity="planned"`` — the one
maturity level whose semantics ("internal groundwork only,
non-public/non-connectable/non-Live") are honest here: not because
Slack sync support is upcoming groundwork, but because it has no
data-sync surface for this framework to certify. The manifest exists
to formally document this architectural distinction (so a future reader
doesn't assume Slack was simply forgotten) rather than to claim any
sync functionality that doesn't exist. Certification legitimately
resolves PASS for a `planned` manifest with no capabilities/records/
Findings declared — see ``models.py``'s relaxed `planned` validation
path.
"""

from __future__ import annotations

from app.provider_certification.models import ProviderCertificationManifest
from app.provider_certification.runner import register_manifest

SLACK_MANIFEST = ProviderCertificationManifest(
    provider_id="slack",
    display_name="Slack",
    category="communication",
    maturity="planned",
    expected_public=False,
    expected_connectable=False,
    expected_live=False,
    credential_fields=(),
    sensitive_credential_fields=(),
    authentication_model="oauth",
    expected_record_types=(),
    security_finding_rule_ids=(),
    supported_capabilities=(),
    unsupported_capabilities=(),
    completeness_scopes=(),
    false_removal_scopes=(),
    expected_frontend_form=None,
    expected_reconnect=False,
    prohibited_dependencies=(),
    known_limitations=(
        "Slack is not a data-sync provider in this repository — there is "
        "no SlackConnector, no slack_schema.py, no "
        "risk_rules/slack.py, and no capability-matrix entry. It is not "
        "in the backend sync-provider list or the frontend provider list.",
        "What exists is app/services/slack_service.py and "
        "app/routers/slack_oauth.py — an OUTBOUND OAuth-based alert-"
        "routing integration (ConfigTrace sends notifications TO Slack), "
        "the opposite direction from every certified sync provider.",
        "This manifest intentionally declares zero record types, zero "
        "Finding IDs, and zero capabilities — there is no configuration "
        "data to sync, classify, or certify reachability/parity "
        "evidence for. Declaring anything else would be fabricated.",
        "If Slack is ever built as a genuine data-sync provider (a "
        "SlackConnector with schema/risk-rules modules and a "
        "capability-matrix entry), this manifest must be rewritten from "
        "scratch following the onboarding standard, not incrementally "
        "amended.",
    ),
)

register_manifest(SLACK_MANIFEST)
