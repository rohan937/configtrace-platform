"""Provider capability matrix (M75C).

Canonical, static description of what each completed ConfigTrace provider
supports across the two product stacks:

  Drift stack  — configuration snapshot, diff, risk classification, review.
  Security stack — security rules, activity ingestion, incident signals,
                   risk × activity correlations, demo seed/clear, case /
                   report / evidence timeline / evidence graph.

This module is READ-ONLY metadata — it never evaluates live provider state,
never calls external APIs, never changes DB records.  Its only job is to
give the operator / product a single source of truth for current capability
coverage and to identify where the next expansion milestone (M76) should
focus.

CLAIM DISCIPLINE: all copy in this module is framed as "supports",
"available", "review-ready" — never "secure", "safe", "compliant",
"breach-free", or "confirmed incident".

Privacy: the matrix contains no customer data, no credentials, no secrets,
no API keys, no tokens, and no per-workspace state.  It is fully static.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ── Types ────────────────────────────────────────────────────────────────────

MATURITY_LEVELS = frozenset({"complete", "partial", "planned"})
CATEGORIES = frozenset(
    {
        "devops",
        "cloud",
        "edge_network",
        "database_backend",
        "auth",
        "payments_commerce",
        "ecommerce",
        "observability",
    }
)


@dataclass(frozen=True)
class DriftCapabilities:
    """What the drift (snapshot / diff / risk) stack offers for this provider."""

    drift_snapshots: bool
    """True when the connector fetches configuration snapshots for this provider."""
    drift_diff: bool
    """True when ConfigTrace produces change diffs for this provider's snapshots."""
    drift_risk_classification: bool
    """True when security rules exist that classify drift findings for this provider."""
    drift_review_workflow: bool
    """True when the review / acknowledge / policy workflow is active for findings."""
    drift_remediation_preview: bool = False
    """True when the UI surfaces actionable remediation guidance for findings."""


@dataclass(frozen=True)
class SecurityCapabilities:
    """What the security investigation stack offers for this provider."""

    security_rules: bool
    """True when configuration-risk rules exist for this provider."""
    activity_ingestion: bool
    """True when activity events can be ingested from this provider."""
    activity_signals: bool
    """True when activity events can be promoted to Incident Signals."""
    risk_activity_correlations: bool
    """True when risk findings can be correlated with activity events."""
    demo_seed_clear: bool
    """True when a demo seed/clear/status lifecycle exists for this provider."""
    case_report: bool
    """True when cases and structured case reports include this provider."""
    evidence_timeline: bool
    """True when the chronological evidence timeline includes this provider."""
    evidence_graph: bool
    """True when the evidence relationship graph includes this provider."""


@dataclass(frozen=True)
class ProviderCapability:
    """Full capability record for one provider."""

    provider: str
    label: str
    category: str
    drift: DriftCapabilities
    security: SecurityCapabilities
    maturity: str
    notes: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "label": self.label,
            "category": self.category,
            "drift": {
                "drift_snapshots": self.drift.drift_snapshots,
                "drift_diff": self.drift.drift_diff,
                "drift_risk_classification": self.drift.drift_risk_classification,
                "drift_review_workflow": self.drift.drift_review_workflow,
                "drift_remediation_preview": self.drift.drift_remediation_preview,
            },
            "security": {
                "security_rules": self.security.security_rules,
                "activity_ingestion": self.security.activity_ingestion,
                "activity_signals": self.security.activity_signals,
                "risk_activity_correlations": self.security.risk_activity_correlations,
                "demo_seed_clear": self.security.demo_seed_clear,
                "case_report": self.security.case_report,
                "evidence_timeline": self.security.evidence_timeline,
                "evidence_graph": self.security.evidence_graph,
            },
            "maturity": self.maturity,
            "notes": self.notes,
        }


# ── Canonical provider matrix ─────────────────────────────────────────────────
#
# Drift maturity legend:
#   drift_snapshots + diff + risk_classification + review_workflow = "complete"
#   Any subset present without all four = "partial"
#   Not yet started = "planned"
#
# Security maturity legend:
#   All eight security capabilities = "complete"
#   Any subset = "partial"
#   Not started = "planned"
#
# The overall ``maturity`` field uses the *minimum* of the two stacks:
#   both complete → "complete"; one partial/planned → "partial"; etc.
#
# NOTE: Stripe, Shopify, Supabase, Firebase, Vercel currently have
# security_rules + full security investigation stack but their drift
# snapshot connector was not the primary focus of those arcs.
# They are recorded as "partial" overall because the drift stack is
# incomplete even though the security stack is complete.

_GITHUB = ProviderCapability(
    provider="github",
    label="GitHub",
    category="devops",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=True,
        drift_remediation_preview=True,
    ),
    security=SecurityCapabilities(
        security_rules=True,
        activity_ingestion=True,
        activity_signals=True,
        risk_activity_correlations=True,
        demo_seed_clear=True,
        case_report=True,
        evidence_timeline=True,
        evidence_graph=True,
    ),
    maturity="complete",
    notes=(
        "GitHub is the most mature dual-stack provider. Drift snapshots cover "
        "webhooks, branch protection, rulesets, deploy keys, and environment "
        "protection. Security investigation covers secret-scanning, "
        "code-scanning, and Dependabot alert correlations. Both stacks are "
        "production-ready."
    ),
)

_AWS = ProviderCapability(
    provider="aws",
    label="AWS",
    category="cloud",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=True,
        drift_remediation_preview=False,
    ),
    security=SecurityCapabilities(
        security_rules=True,
        activity_ingestion=True,
        activity_signals=True,
        risk_activity_correlations=True,
        demo_seed_clear=True,
        case_report=True,
        evidence_timeline=True,
        evidence_graph=True,
    ),
    maturity="complete",
    notes=(
        "AWS drift covers EC2 security groups, S3 bucket policies/ACLs, IAM "
        "policies, and access keys. Security investigation covers GuardDuty, "
        "IAM Access Analyzer, CloudTrail, Security Hub, S3 data events, and "
        "VPC Flow Logs. Remediation preview is a planned next stage."
    ),
)

_CLOUDFLARE = ProviderCapability(
    provider="cloudflare",
    label="Cloudflare",
    category="edge_network",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=True,
        drift_remediation_preview=False,
    ),
    security=SecurityCapabilities(
        security_rules=True,
        activity_ingestion=True,
        activity_signals=True,
        risk_activity_correlations=True,
        demo_seed_clear=True,
        case_report=True,
        evidence_timeline=True,
        evidence_graph=True,
    ),
    maturity="complete",
    notes=(
        "Cloudflare drift covers zone settings, WAF rules, and DNS records. "
        "Security investigation covers audit activity, WAF/security events, "
        "Access policy rules, and zone-setting correlations. Remediation "
        "preview is a planned next stage."
    ),
)

_VERCEL = ProviderCapability(
    provider="vercel",
    label="Vercel",
    category="devops",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=True,
        drift_remediation_preview=False,
    ),
    security=SecurityCapabilities(
        security_rules=True,
        activity_ingestion=True,
        activity_signals=True,
        risk_activity_correlations=True,
        demo_seed_clear=True,
        case_report=True,
        evidence_timeline=True,
        evidence_graph=True,
    ),
    maturity="complete",
    notes=(
        "Vercel drift covers deployment protection, production branch, "
        "sensitive env-var scope, and deploy-hook posture. Security "
        "investigation covers team audit activity, project/domain/env-var/"
        "deploy-hook/deployment events, signals, and correlations."
    ),
)

_SUPABASE = ProviderCapability(
    provider="supabase",
    label="Supabase",
    category="database_backend",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=True,
        drift_remediation_preview=False,
    ),
    security=SecurityCapabilities(
        security_rules=True,
        activity_ingestion=True,
        activity_signals=True,
        risk_activity_correlations=True,
        demo_seed_clear=True,
        case_report=True,
        evidence_timeline=True,
        evidence_graph=True,
    ),
    maturity="complete",
    notes=(
        "Supabase drift covers RLS status, anonymous access, JWT expiry, "
        "public-select policies, and public-write policies. Security "
        "investigation covers organization audit activity, table/RLS/policy/"
        "storage-bucket/Edge Function/auth-config events, signals, and "
        "correlations."
    ),
)

_FIREBASE = ProviderCapability(
    provider="firebase",
    label="Firebase",
    category="database_backend",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=True,
        drift_remediation_preview=False,
    ),
    security=SecurityCapabilities(
        security_rules=True,
        activity_ingestion=True,
        activity_signals=True,
        risk_activity_correlations=True,
        demo_seed_clear=True,
        case_report=True,
        evidence_timeline=True,
        evidence_graph=True,
    ),
    maturity="complete",
    notes=(
        "Firebase drift covers Firestore/Realtime Database/Storage security "
        "rules posture. Security investigation covers Google Cloud Audit Log "
        "control-plane changes, Firestore/Database/Storage rules, auth-config, "
        "Cloud Function, Hosting, and project/app events, signals, and "
        "correlations."
    ),
)

_STRIPE = ProviderCapability(
    provider="stripe",
    label="Stripe",
    category="payments_commerce",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=True,
        drift_remediation_preview=False,
    ),
    security=SecurityCapabilities(
        security_rules=True,
        activity_ingestion=True,
        activity_signals=True,
        risk_activity_correlations=True,
        demo_seed_clear=True,
        case_report=True,
        evidence_timeline=True,
        evidence_graph=True,
    ),
    maturity="complete",
    notes=(
        "Stripe drift covers webhook endpoints, payment links, billing-portal "
        "configuration, and account capability posture. Security investigation "
        "covers Stripe Events API configuration-change activity (webhook / "
        "payment-link / portal / account / capability), signals, and "
        "correlations. Customer / payment / charge / invoice lifecycle events "
        "are deliberately excluded."
    ),
)

_SHOPIFY = ProviderCapability(
    provider="shopify",
    label="Shopify",
    category="ecommerce",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=True,
        drift_remediation_preview=False,
    ),
    security=SecurityCapabilities(
        security_rules=True,
        activity_ingestion=True,
        activity_signals=True,
        risk_activity_correlations=True,
        demo_seed_clear=True,
        case_report=True,
        evidence_timeline=True,
        evidence_graph=True,
    ),
    maturity="complete",
    notes=(
        "Shopify drift covers webhook subscriptions, app-scope posture, "
        "primary domain SSL/verification, and store-policy presence. Security "
        "investigation covers Shopify Events API configuration-change activity "
        "(Webhook / Shop / Domain subject types only; customer / order / "
        "checkout / cart / payment events are deliberately excluded), signals, "
        "and correlations. App-scope and policy activity correlations are "
        "deferred until the ingestion layer emits those event types."
    ),
)


_AZURE = ProviderCapability(
    provider="azure",
    label="Azure",
    category="cloud",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=True,
        drift_remediation_preview=False,
    ),
    security=SecurityCapabilities(
        security_rules=True,
        activity_ingestion=True,
        activity_signals=True,
        risk_activity_correlations=False,
        demo_seed_clear=False,
        case_report=False,
        evidence_timeline=False,
        evidence_graph=False,
    ),
    maturity="partial",
    notes=(
        "Azure drift + expanded security + Activity Log ingestion + signals (M77A–M77E). "
        "Drift snapshots: subscription / RG / NSG / Storage / KV / role assignments / "
        "App Service / SQL Server / AKS. Security rules: 20 rules covering NSG / storage / "
        "KV / role assignment / App Service / SQL / AKS posture. Activity Log ingestion: "
        "WRITE/DELETE management events across all monitored surfaces. Activity signals: "
        "14 signal types (azure_network_exposure_changed, azure_nsg_deleted, "
        "azure_storage_config_changed, azure_storage_account_deleted, "
        "azure_key_vault_config_changed, azure_key_vault_deleted, "
        "azure_role_assignment_changed, azure_app_service_config_changed, "
        "azure_app_service_deleted, azure_sql_network_config_changed, "
        "azure_sql_server_deleted, azure_aks_cluster_config_changed, "
        "azure_aks_cluster_deleted, azure_config_activity). "
        "Correlations and demo follow in M77F–M77G."
    ),
)


# Public ordered list — canonical 8-provider dual-stack matrix (M75A/M75C).
# Azure is tracked separately in PROVIDER_CAPABILITIES_PARTIAL below because
# it has not yet reached dual-stack maturity (security stack not started).
PROVIDER_CAPABILITIES: list[ProviderCapability] = [
    _GITHUB,
    _AWS,
    _CLOUDFLARE,
    _VERCEL,
    _SUPABASE,
    _FIREBASE,
    _STRIPE,
    _SHOPIFY,
]

# Partial / in-progress providers — not counted in the canonical 8-provider matrix.
PROVIDER_CAPABILITIES_PARTIAL: list[ProviderCapability] = [
    _AZURE,
]

# Fast lookup by provider key — includes both complete and partial providers.
_BY_KEY: dict[str, ProviderCapability] = {
    p.provider: p
    for p in PROVIDER_CAPABILITIES + PROVIDER_CAPABILITIES_PARTIAL
}


def get_provider_capability(provider: str) -> ProviderCapability | None:
    """Return the capability record for one provider, or None if unknown."""
    return _BY_KEY.get(provider)


def get_matrix() -> dict[str, object]:
    """Return the full matrix dict ready for JSON serialization."""
    providers = [p.as_dict() for p in PROVIDER_CAPABILITIES]

    security_complete = sum(
        1 for p in PROVIDER_CAPABILITIES
        if p.security.security_rules
        and p.security.activity_ingestion
        and p.security.activity_signals
        and p.security.risk_activity_correlations
        and p.security.demo_seed_clear
        and p.security.case_report
        and p.security.evidence_timeline
        and p.security.evidence_graph
    )
    drift_complete = sum(
        1 for p in PROVIDER_CAPABILITIES
        if p.drift.drift_snapshots
        and p.drift.drift_diff
        and p.drift.drift_risk_classification
        and p.drift.drift_review_workflow
    )
    dual_stack_complete = sum(
        1 for p in PROVIDER_CAPABILITIES
        if p.maturity == "complete"
    )

    return {
        "providers": providers,
        "summary": {
            "total_providers": len(PROVIDER_CAPABILITIES),
            "security_complete_count": security_complete,
            "drift_complete_count": drift_complete,
            "dual_stack_complete_count": dual_stack_complete,
            "planned_next_stage": (
                "M76 dual-stack template: drift foundation → security rules → "
                "activity ingestion → signals → correlations → demo + QA."
            ),
        },
    }
