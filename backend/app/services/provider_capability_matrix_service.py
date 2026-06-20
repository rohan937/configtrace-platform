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
        risk_activity_correlations=True,
        demo_seed_clear=True,
        case_report=True,
        evidence_timeline=True,
        evidence_graph=True,
    ),
    maturity="partial",
    notes=(
        "Azure is demo-ready through drift snapshots, security rules, "
        "Activity Log ingestion, activity signals, risk × activity "
        "correlations, and case evidence (timeline + graph + report). "
        "Drift snapshots cover subscription / resource group / NSG / Storage "
        "/ Key Vault / role assignments / App Service / SQL Server / AKS. "
        "Security rules: 20 rules across Network, Storage, Key Vault, "
        "Identity, App Service, SQL, and AKS. Activity Log ingestion covers "
        "WRITE/DELETE management events on every monitored surface. Activity "
        "signals: 14 signal types. Correlations: 7 correlation types joining "
        "configuration risks to Activity Log evidence on the same Azure "
        "resource (or role + scope for broad role assignments). Demo seeds a "
        "review-safe Azure security flow on a hidden demo integration. Case "
        "report / timeline / graph render with the 'Azure' provider label. "
        "Azure remains in partial maturity pending broader cross-provider "
        "polish and future non-Azure provider arcs; it is not part of the "
        "canonical 8-provider dual-stack-complete set."
    ),
)


_GOOGLE_CLOUD = ProviderCapability(
    provider="google_cloud",
    label="Google Cloud",
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
    maturity="partial",
    notes=(
        "Google Cloud drift + core and expanded security foundation + Audit Log "
        "ingestion + Activity Signals + Risk × Activity Correlations "
        "(M78A–M78F). Drift snapshots cover project "
        "metadata, IAM policy summary (counts only — principal emails and member "
        "identifiers are never stored), VPC networks, firewall rules, Cloud Storage "
        "buckets, Cloud SQL instances, Cloud Run services, GKE clusters, service "
        "account key aggregate summary (counts only — SA emails and key material "
        "are never stored), and Secret Manager aggregate summary (counts only — "
        "secret names and values are never stored). Security rules: 22 rules across "
        "IAM, Firewall, Storage, Cloud SQL, Cloud Run, GKE, Service Account Keys, "
        "and Secret Manager. Activity ingestion: Google Cloud Admin Activity audit "
        "log entries via Cloud Logging — only CREATE/UPDATE/DELETE control-plane "
        "operations on IAM, firewall rules, VPC networks, Cloud Storage, Cloud SQL, "
        "Cloud Run, GKE, and Secret Manager are ingested. Data-plane access, secret "
        "access events, and application logs are deliberately excluded. Principal "
        "emails, caller IPs, raw protoPayload, and request/response objects are "
        "never stored. Activity signals: 11 signal types covering IAM policy, "
        "service accounts, service account keys, firewall rules, VPC networks, "
        "Cloud Storage, Cloud SQL, Cloud Run, GKE clusters, and Secret Manager. "
        "Risk × Activity correlations (M78F): 8 correlation types joining active "
        "Google Cloud configuration risks to Google Cloud Audit Log evidence on "
        "the same resource — exact resource-name matches for firewall rules, "
        "Cloud Storage buckets, Cloud SQL instances, Cloud Run services, and GKE "
        "clusters; project+family aggregate matches for IAM, service-account-key, "
        "and Secret Manager risks. Provider-only and project-only matches for "
        "resource-bearing findings are never produced. M78G demo-ready Google "
        "Cloud security review flow: drift findings, Audit Log evidence, "
        "activity signals, risk × activity correlations, and demo case. Demo "
        "evidence is clearly marked and seeded on a hidden demo integration "
        "with allowlisted metadata only — no service-account private keys, "
        "access tokens, raw payloads, principal emails, service-account "
        "emails, raw caller IPs, secret names/values, database names/users, "
        "connection strings, env-var names/values, kubeconfig, certs, logs, "
        "customer data, or PII are ever stored in the demo chain. M78H "
        "provider-depth QA pinned end-to-end taxonomy parity (record types ↔ "
        "rule keys ↔ ingested method names ↔ event types ↔ signal types ↔ "
        "correlation rules ↔ correlation activity types), privacy denylist "
        "discipline on the live signal/correlation/demo pipeline, claim "
        "discipline across every Google Cloud production module, false-"
        "positive behavior for resource-name / aggregate matching, demo "
        "isolation across providers, and router admin/member guards. "
        "M78I cross-cloud UX polish complete — activity / signals / "
        "correlations / cases / demo-script pages are first-class alongside "
        "AWS and Azure. Maturity remains partial — Google Cloud is not yet "
        "in the canonical 8-provider dual-stack-complete set."
    ),
)


_TWILIO = ProviderCapability(
    provider="twilio",
    label="Twilio",
    category="communications",
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
    maturity="partial",
    notes=(
        "Twilio drift + core security foundation (M79A/M79B) + messaging/webhook "
        "risk expansion (M79C) + Monitor activity ingestion (M79D) + activity signals "
        "(M79E) + risk×activity correlations (M79F) + demo + QA (M79G). Drift snapshots "
        "cover Twilio account metadata, incoming phone numbers (last-4 only — no full "
        "numbers stored), messaging services (webhook configuration as booleans — no "
        "raw URLs stored), Verify services, and API key metadata. No auth tokens, API "
        "secrets, message bodies, call logs, recordings, customer phone numbers, webhook "
        "URLs, or customer data are ever stored. M79B adds 9 security rules covering "
        "webhook/verify/account posture. M79C adds 8 additional rules: API key "
        "staleness (twilio_api_key_stale), messaging service observability gap "
        "(twilio_messaging_service_observability_gap), number-level inbound webhook "
        "delegation (twilio_messaging_service_number_level_inbound_webhook), long "
        "validity period (twilio_messaging_service_long_validity_period), phone number "
        "messaging and voice observability gaps "
        "(twilio_phone_number_messaging_observability_gap, "
        "twilio_phone_number_voice_observability_gap), and Verify PSD2/landline posture "
        "(twilio_verify_psd2_disabled, twilio_verify_sms_to_landlines_allowed). M79D "
        "adds Monitor API activity ingestion — account/phone-number/messaging-service/"
        "Verify-service/API-key create/update/delete events via POST "
        "/security/twilio-activity/sync. M79E adds activity signals — promotes ingested "
        "Monitor events into review-priority Incident Signals via POST "
        "/security/twilio-activity/generate-signals, covering 7 signal types across "
        "phone number, messaging service, sender pool, Verify service, API key, account, "
        "and generic config-change categories. M79F adds risk×activity correlations — "
        "joins active Twilio configuration-risk findings with Twilio activity signals "
        "across 5 correlation families (twilio_phone_number_risk_activity_correlation, "
        "twilio_messaging_service_risk_activity_correlation, "
        "twilio_verify_service_risk_activity_correlation, "
        "twilio_api_key_risk_activity_correlation, "
        "twilio_account_risk_activity_correlation) via POST "
        "/security/twilio-correlations/generate. M79G adds demo seed/clear — a "
        "review-safe synthetic evidence chain (4 findings, 5 activity events, up to 4 "
        "activity signals, up to 4 correlations, and one case) covering phone number "
        "webhook, messaging service observability, Verify service code length, and API "
        "key staleness posture. No auth tokens, API secrets, full account SIDs, full "
        "phone numbers, message bodies, call logs, recordings, or customer data are "
        "ever included in demo evidence. Case report, evidence timeline, and evidence "
        "graph are fully supported via the generic builders (twilio label registered in "
        "all provider-label tables). M79H (provider-depth QA) added durable guardrails "
        "pinning taxonomy parity, privacy/sanitization discipline, false-positive "
        "behavior, demo isolation, and router/frontend consistency across the full "
        "M79A–M79G arc. M79I (cross-cloud UX polish) complete: all 17 Twilio rule "
        "keys documented in the frontend rule catalog with full description/remediation/"
        "falsePositiveGuard copy, demo talk track updated to feature Twilio alongside "
        "Azure and Google Cloud, and Twilio is now first-class in the security UX "
        "alongside all other dual-stack providers. Twilio remains partial (not in the "
        "canonical dual-stack-complete set of 8 providers)."
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

_SENDGRID = ProviderCapability(
    provider="sendgrid",
    label="SendGrid",
    category="communications",
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
        evidence_timeline=False,
        evidence_graph=False,
    ),
    maturity="partial",
    notes=(
        "SendGrid email infrastructure drift foundation (M80A). Drift snapshots "
        "cover 8 safe surfaces: account type and reputation, API key metadata "
        "(never the key value), verified sender identities (email domain only — "
        "full addresses are never stored), domain authentication status and DNS "
        "record count (raw DNS values never stored), mail settings booleans, "
        "tracking settings booleans, event webhook configuration booleans (URL "
        "stored as a presence boolean — never as a string), and suppression group "
        "count (recipient emails never stored). No API key values, bearer tokens, "
        "authorization headers, email bodies, template content, recipient emails, "
        "suppression lists, event payloads, or customer data are ever stored. "
        "M80B adds 15 core security rules across 7 drift surfaces: API key "
        "broad-scope detection, sender identity verification and lock status, "
        "domain authentication validity and automatic-security posture, mail "
        "settings (spam check, sandbox mode, BCC), tracking settings (click, "
        "open, subscription tracking), event webhook configuration (disabled, "
        "missing URL), and suppression group count. "
        "M80C adds 11 mail/webhook risk expansion rules: sender reply-to domain "
        "mismatch, domain DNS records missing, default domain auth invalid, "
        "footer disabled, bounce purge disabled, legacy template engine enabled, "
        "Google Analytics tracking enabled, event webhook broad event stream, "
        "inbound parse enabled/raw-email/spam-check-disabled. Schema safely "
        "expanded to include template_enabled boolean (mail settings) and "
        "inbound parse booleans (webhook settings) — no hostnames, URLs, "
        "email content, or customer data ever stored. "
        "M80D adds configuration activity ingestion: SendGrid has no native "
        "audit/event API, so review-safe config-state events are synthesized "
        "from the existing safe surfaces (account, API key, sender identity, "
        "domain authentication, mail/tracking settings, event webhook, inbound "
        "parse, suppression) and stored as activity events. Mail-delivery events "
        "(bounce/click/open/delivered/dropped/spamreport/unsubscribe) are NEVER "
        "ingested; API key values, email bodies, subjects, recipient emails, "
        "template content, raw webhook URLs, and customer data are NEVER stored. "
        "M80E adds activity signals: config-state events are promoted into "
        "review-priority Incident Signals grouped by resource identity. "
        "M80F adds risk x activity correlations: seven correlation families "
        "(API key, sender identity, domain authentication, mail settings, "
        "tracking settings, webhook/inbound parse, suppression settings) "
        "join active security findings with activity signals. "
        "M80G adds demo + QA: a review-safe SendGrid demo incident chain "
        "(seed/clear/status) with configuration findings, activity events, "
        "signals, correlations, and a linked case. Demo uses only safe "
        "synthetic identifiers — no real API key values, email bodies, "
        "recipient emails, template content, webhook URLs, or customer data. "
        "M80H adds provider-depth QA: durable guardrails covering taxonomy "
        "parity (8 record types, 26 rules, 17 activity event types, 10 signal "
        "types, 7 correlation types), privacy denylist enforcement, claim "
        "discipline, false-positive behavior, demo isolation, router admin "
        "guards, and frontend consistency. Case-report preview allowlist "
        "expanded with SendGrid-safe opaque identifiers (api_key_id, "
        "sender_id, domain_id, suppression_group_count). "
        "M80I completes the SendGrid arc with cross-cloud UX polish: signals "
        "page empty state gains a SendGrid-specific sync-then-generate guidance "
        "branch; securityDemoScript.ts opening pitch names SendGrid; "
        "_TIMELINE_PROVIDER_LABELS adds the 'SendGrid' label for case report "
        "rendering; demo-script page NEXT_PROVIDERS_BRIEF milestone labels "
        "updated to M81 series (Auth0/Datadog/Clerk); securityRuleCatalog "
        "PROVIDER_COVERAGE sendgrid entry gains the inbound parse surface; "
        "provider expansion framework planned_next_stage advances to "
        "M81A: Auth0 Drift Provider Foundation. "
        "SendGrid remains partial (not in the canonical dual-stack-complete set "
        "of 8 providers). evidence_timeline and evidence_graph are intentionally "
        "deferred to a later arc."
    ),
)


_AUTH0 = ProviderCapability(
    provider="auth0",
    label="Auth0",
    category="auth",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=False,
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
    maturity="partial",
    notes=(
        "Auth0 identity infrastructure drift foundation (M81A). Drift snapshots "
        "cover 8 safe surfaces from the Auth0 Management API v2: tenant settings "
        "(boolean flags and session categories — never support email, error page "
        "HTML, or raw settings payload), applications/clients (client_id, name, "
        "app_type, grant types, URL counts — never client_secret, raw callback "
        "URLs, JWKS, or certificate material), connections (strategy, enabled "
        "clients count — never credentials, passwords, or user data), resource "
        "servers (signing algorithm, scopes count — never audience URI or signing "
        "secret), rules (name, enabled, order, script_present — never script "
        "content), actions (name, status, runtime, trigger — never code or secret "
        "values), MFA/Guardian factors (factor name and enabled status — never "
        "enrollment data, recovery codes, or phone numbers), and custom domains "
        "(status, type, tls_policy — never domain name string or verification "
        "tokens). "
        "Authentication: OAuth2 client_credentials grant OR direct "
        "management_api_token; neither the minted access token nor the "
        "client_secret is ever stored on the connector instance or logged. "
        "URL fields (callback URLs, logout URLs, allowed origins, web origins) "
        "are stored as integer counts only. The resource server identifier "
        "(audience URI) is stored as a boolean presence flag only. Custom domain "
        "names are never stored. Rule and action code are stored as a boolean "
        "presence flag and a length category only. "
        "M81B adds 22 core security rules across 8 drift surfaces: tenant "
        "session lifetime (extended login/idle session categories) and dynamic "
        "client registration posture; application configuration (no callbacks, "
        "many callbacks, many allowed/web origins, OIDC non-conformance, weak "
        "JWT signing algorithm); refresh token posture (rotation disabled, "
        "extended lifetime); connection configuration (no enabled clients, weak "
        "database password policy); resource server posture (offline access "
        "enabled, extended token lifetime, RBAC disabled); auth pipeline rule "
        "and action posture (disabled rule with script, large script, action "
        "not deployed, action secrets present); MFA factor posture (strong "
        "factors disabled); custom domain posture (not ready, weak/compatible "
        "TLS policy). "
        "M81C adds 15 OAuth/application risk rules: password grant enabled, "
        "implicit grant enabled, client credentials on public client, refresh "
        "grant without rotation, broad grant type surface, device code grant, "
        "wildcard callback/origin/logout URL, localhost callback/origin, "
        "callback/origin missing HTTPS, public client with refresh tokens, "
        "token endpoint auth method none. M81C adds safe grant type booleans "
        "(grant_password_enabled, grant_implicit_enabled, etc.) and URL posture "
        "booleans (wildcard_callback_present, localhost_callback_present, "
        "callbacks_missing_https, etc.) to the auth0_application record. "
        "M81D adds configuration activity ingestion. Auth0 Management API logs "
        "(/api/v2/logs) are NEVER ingested because they include user_id, email, "
        "IP address, and device data. Instead, activity events are synthesized "
        "from the same 8 safe drift surfaces (tenant settings, applications, "
        "connections, resource servers, rules, actions, MFA factors, custom "
        "domains). Events are date-scoped for idempotency. POST "
        "/security/auth0-activity/sync (admin-only). Login, authentication, "
        "session, token-exchange, MFA enrollment, profile, and org-member "
        "events are never ingested. Client secrets, JWTs, raw URLs, script "
        "content, action secrets, user data, IP addresses, and raw Auth0 log "
        "entries are never stored. "
        "M81E adds configuration activity signals. Auth0 activity events "
        "(provider=auth0, source=auth0_activity_event) are promoted into 9 "
        "signal types: auth0_tenant_config_changed, auth0_application_config_changed, "
        "auth0_connection_config_changed, auth0_resource_server_config_changed, "
        "auth0_rule_config_changed, auth0_action_config_changed, "
        "auth0_mfa_factor_config_changed, auth0_custom_domain_config_changed, "
        "auth0_config_activity. Signals group by safe resource identity (client_id, "
        "connection_id, resource_server_id, rule_id, action_id, custom_domain_id, "
        "factor_name). POST /security/auth0-activity/generate-signals (admin-only). "
        "Idempotent. "
        "M81F adds Risk × Activity correlations. Eight correlation families "
        "join Auth0 findings to Auth0 activity signals: tenant, application "
        "(client_id exact match), connection (connection_id exact match), "
        "resource_server (resource_server_id exact match), rule (rule_id exact "
        "match), action (action_id exact match), mfa_factor (factor_name exact "
        "match), custom_domain (custom_domain_id exact match). Falls back to "
        "provider+family aggregate when no per-resource identity is available. "
        "POST /security/auth0-correlations/generate (admin-only). Idempotent. "
        "M81G adds demo + QA: a review-safe Auth0 demo incident chain seeds 8 "
        "configuration risks (one per drift surface), 8 activity events, 8 "
        "activity signals, 8 risk x activity correlations, and a case via "
        "POST /security/incident-demo/seed?provider=auth0. No client secrets, "
        "management tokens, JWTs, raw URLs, rule/action code, user emails, "
        "user IDs, login history, IP addresses, raw Auth0 logs, or customer "
        "data are stored. evidence_timeline and evidence_graph supported via "
        "the generic case evidence builders. "
        "M81H adds provider-depth QA: durable guardrails covering taxonomy "
        "parity (8 record types, 37 rule keys, 23 activity event types, 9 "
        "signal types, 8 correlation types), privacy sanitization (allowlist "
        "verified for activity/signal/correlation/case-report layers), claim "
        "discipline (forbidden-phrase scan across all Auth0 modules), "
        "false-positive behavior pins (per-surface positive and negative cases "
        "for the evaluator, signal builder, and correlation matcher), demo "
        "isolation (seed/clear idempotency, no cross-provider contamination), "
        "router admin guards, frontend consistency (activity page, signals page, "
        "correlations page, rule catalog, demo card, API unions), and regression "
        "smoke (evaluator dispatch, allowlist shape, correlation rule structure). "
        "Auth0 remains partial (not in the canonical dual-stack-complete "
        "set of 8 providers). M81I completes the Auth0 arc with cross-cloud "
        "UX polish: signals and correlations empty states gain Auth0-specific "
        "guidance; the demo-script page description updated from 'drift-only' "
        "to reflect the full Auth0 arc (M81A–M81I); stale milestone references "
        "removed from frontend copy. "
        "M82-pre surfaces Auth0 on /integrations as a security-preview card "
        "linking to the security demo (no credential connect form yet — the "
        "Auth0 connector requires domain + client_id + client_secret (or "
        "management_api_token) which the integrations API allowlist does not "
        "yet accept). "
        "M82-pre.1 retires the security-preview routing and adds real "
        "credential-connect parity: POST /integrations now accepts "
        "provider='auth0' (and azure, google_cloud, twilio, sendgrid), the "
        "schema requires either auth0_client_id + auth0_client_secret OR "
        "auth0_management_api_token alongside auth0_domain, credentials are "
        "encrypted via the existing AES-256-GCM pattern, and the integrations "
        "page renders a real Auth0 credential form (with mode toggle) instead "
        "of routing to /security/cases."
    ),
)


_DATADOG = ProviderCapability(
    provider="datadog",
    label="Datadog",
    category="observability",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=False,
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
    maturity="partial",
    notes=(
        "Datadog observability infrastructure drift foundation (M82A). "
        "Drift snapshots cover 10 safe surfaces from the Datadog API: "
        "monitor metadata (type, status, priority category, query/message "
        "presence booleans and length categories — raw query strings and raw "
        "message text are NEVER stored), SLOs (type, target categories, "
        "timeframe/monitor/group counts — raw descriptions never stored), "
        "dashboards (layout type, widget count, template variable count — "
        "raw dashboard JSON and widget queries never stored), webhook "
        "integrations (presence booleans — URL, headers, payload templates, "
        "and secrets never stored), notification integrations (type, "
        "handle/channel counts — destination handles, service keys, and "
        "channel names never stored), API key metadata (ID, name, created/"
        "modified presence, last4_present boolean — key value and last4 digits "
        "never stored), application key metadata (ID, name, scope count — "
        "key value never stored), roles (name, permission/user/team counts — "
        "user identities never stored), teams (name, member count, "
        "handle_present boolean — member identities and handles never stored), "
        "and cloud integrations (cloud_provider, collection enabled flags, "
        "account_id_present boolean — account IDs never stored). "
        "Logs, traces, metric values, incident content, and all raw Datadog "
        "API response payloads are NEVER fetched or stored. "
        "Pagination is bounded with conservative per-surface caps. "
        "M82B adds 17 core security rules across 10 record types. "
        "M82C adds 14 monitor/webhook risk expansion rules. "
        "Total Datadog rules after M82C: 31. "
        "M82D adds Datadog configuration activity ingestion. Activity events "
        "are synthesized from the same 10 safe drift surfaces — Datadog's "
        "audit/audit-trail API is never used because it contains actor "
        "email, actor UUID, and IP-level request metadata. Ingestion scope: "
        "monitor, SLO, dashboard, webhook integration, notification "
        "integration, API key metadata, application key metadata, role, team, "
        "and cloud integration posture observations. Raw audit payloads, "
        "actor identities, IP addresses, user agents, raw Datadog API "
        "response dicts, raw monitor queries/messages, raw dashboard JSON, "
        "webhook URLs/headers/payloads/secrets, notification handles, "
        "emails, user IDs, team member identities, logs, traces, metric "
        "values, and incident content are NEVER stored. "
        "M82E adds Datadog activity signals. 11 signal types covering all 10 drift "
        "surfaces plus a generic config activity type. Idempotent. No API key values, "
        "application key values, raw queries, raw messages, webhook URLs, headers, "
        "payloads, notification handles, emails, user IDs, or PII stored. "
        "M82F adds Datadog risk × activity correlations. 10 specialized correlation "
        "families (monitor/SLO/dashboard/webhook/notification integration/API key/"
        "application key/role/team/cloud integration) plus a generic resource_type/"
        "resource_id fallback. Matches on safe opaque resource IDs from finding "
        "evidence and signal metadata. Confidence: high (exact ID + same integration), "
        "medium (exact ID, different integration), low (family aggregate or generic). "
        "API key values, application key values, raw queries/messages, webhook URLs, "
        "notification handles, emails, user IDs, team member identities, IP addresses, "
        "user agents, and raw Datadog audit payloads are never used or stored. Does "
        "not confirm compromise, unauthorized access, or data exposure. Idempotent. "
        "M82G adds Datadog demo + QA. Demo seeds a Datadog webhook integration "
        "review story: three webhook posture findings (missing secret headers, "
        "non-HTTPS endpoint, auth material in custom headers) → config-state "
        "activity event → webhook activity signal → risk × activity correlation "
        "→ case. Marked demo — no real Datadog sync, no API keys, no webhook "
        "URLs, no header names/values, no payload templates, no notification "
        "handles, no email addresses, no user IDs, no IP addresses, no raw "
        "Datadog audit payloads, no customer data. Evidence for review. "
        "M82H adds provider-depth QA: durable guardrails covering taxonomy "
        "parity (10 record types, 31 rule keys, 32 activity event types, 11 "
        "signal types, 11 correlation types), privacy sanitization (allowlist "
        "verified for activity/signal/correlation/case-report layers), claim "
        "discipline (forbidden-phrase scan across all Datadog modules), "
        "false-positive behavior pins (healthy-record no-fire for all 10 "
        "surfaces, positive-fire for all risk postures), demo isolation "
        "(seed/clear idempotency, no cross-provider contamination, demo "
        "severity correctness), router admin guards, frontend consistency "
        "(activity page, signals page, correlations page, rule catalog, demo "
        "card, API unions), and regression smoke. Three code fixes applied: "
        "(1) datadog added to sync_service._SUPPORTED_PROVIDERS so scheduled "
        "syncs enqueue Datadog integrations; (2) evidence_timeline and "
        "evidence_graph flipped to True per Stage-6 spec and parity with "
        "other demo-ready providers; (3) datadog_webhook_auth_material_present "
        "demo severity corrected from high to medium to match rule pack. "
        "Datadog remains partial (not in the canonical dual-stack-complete "
        "set of 8 providers). M82I completes the Datadog arc with cross-cloud "
        "UX polish: demo-script description updated to reflect the full "
        "M82A–M82I arc; capability matrix notes updated; provider expansion "
        "framework planned_next_stage advances to M83A: Clerk Drift Provider "
        "Foundation. Clerk is now the head of the recommended provider queue."
    ),
)


_CLERK = ProviderCapability(
    provider="clerk",
    label="Clerk",
    category="identity",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=False,
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
    maturity="partial",
    notes=(
        "Clerk identity infrastructure drift, core security, auth/application risk "
        "expansion, activity ingestion, activity signals, and risk × activity correlations "
        "(M83A–M83G). Drift snapshots "
        "cover 10 safe configuration surfaces from the Clerk Backend API v1. M83B adds 21 "
        "core security rules. M83C adds 19 auth/application risk expansion rules. M83D adds "
        "configuration-state activity ingestion synthesized from the same 10 safe drift "
        "surfaces — never Clerk audit logs which contain user emails, user IDs, IP "
        "addresses, and session data. M83E adds activity signals: ingested Clerk "
        "configuration-state events are promoted into review-priority Incident Signals. "
        "M83F adds risk × activity correlations: active Clerk configuration-risk findings "
        "are joined with Clerk activity signals across correlation families keyed by safe "
        "resource identity. "
        "M83G adds demo + QA: a review-safe Clerk demo incident chain (seed/clear/status) "
        "with configuration findings, activity events, signals, correlations, and a linked "
        "case. Case report, evidence timeline, and evidence graph are fully supported. "
        "M83H provider-depth QA complete: taxonomy parity, privacy guardrails, claim "
        "discipline, false-positive behavior, demo isolation, router admin guards, and "
        "frontend consistency verified. Signal-type map orphan entries removed. "
        "M83I cross-cloud UX polish complete: Clerk is a first-class completed provider "
        "across all internal security UX surfaces, demo script, provider capability "
        "table, case report / timeline labels, and roadmap handoff. Clerk arc "
        "(M83A–M83I) complete. "
        "Privacy contract: Clerk secret key values, "
        "publishable key values, session tokens, JWTs, OAuth tokens, bearer tokens, "
        "webhook secrets, raw webhook/redirect URLs, raw domain names, JWT template "
        "bodies, custom claims, audience URIs, user emails, user IDs, phone numbers, "
        "names, member identities, session history, login history, IP addresses, user "
        "agents, raw audit payloads, and customer PII are NEVER fetched or stored."
    ),
)

_PAGERDUTY = ProviderCapability(
    provider="pagerduty",
    label="PagerDuty",
    category="incident_management",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=False,
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
    maturity="partial",
    notes=(
        "PagerDuty incident-management configuration drift, security rules, "
        "activity ingestion, activity signals, risk x activity correlations, "
        "demo + QA, provider depth QA, and cross-cloud UX polish (M84A-M84I). "
        "Drift snapshots cover 8 safe configuration surfaces from the PagerDuty REST "
        "API v2: services, escalation policies, schedules, service integrations, "
        "webhook subscriptions, event orchestrations, business services, and response "
        "plays. M84B adds 22 core security rules; M84C adds 18 expanded rules (40 "
        "total across all 8 record types). M84D adds review-safe configuration "
        "activity ingestion from the same 8 drift surfaces (9 activity event types). "
        "M84E promotes activity events into review-priority Incident Signals (9 signal "
        "types). M84F joins findings with signals on the same opaque resource_id, "
        "producing correlations across 8 PagerDuty resource families. M84G adds "
        "demo + QA: a review-safe PagerDuty webhook subscription story "
        "(seed/clear/status) with three webhook posture findings (non-HTTPS delivery, "
        "broad event scope, secret not indicated), a configuration-state activity "
        "event for the same webhook subscription, an activity signal, a risk x "
        "activity correlation, and a linked case. M84H adds provider depth QA: "
        "taxonomy parity, privacy/sanitization discipline, claim discipline, "
        "false-positive behavior, demo isolation, router admin guards, and frontend "
        "consistency. Fixed spurious pagerduty_config_activity_correlation in frontend "
        "correlations page. Added PagerDuty to securityDemoScript.ts talk tracks. "
        "M84I completes the PagerDuty arc with cross-cloud UX polish: PagerDuty is "
        "a first-class completed provider across all internal security UX surfaces, "
        "demo script, provider capability table, case report and timeline labels, and "
        "roadmap handoff. PagerDuty-specific safe opaque IDs registered in the case "
        "report _PREVIEW_ALLOWLIST. Provider expansion framework planned_next_stage "
        "advances to M85A: Linear Drift Provider Foundation. PagerDuty arc "
        "(M84A-M84I) complete. "
        "No PagerDuty API tokens, routing keys, integration keys, "
        "webhook secrets, delivery URLs, custom header values, user emails, user "
        "names, phone numbers, contact methods, on-call user identities, responder "
        "identities, subscriber identities, incident payloads, alert payloads, "
        "conference phone numbers, raw routing expressions, IP addresses, user "
        "agents, or customer PII are stored in the demo chain. Case report, "
        "evidence timeline, and evidence graph are fully supported via the generic "
        "builders (pagerduty label registered in _TIMELINE_PROVIDER_LABELS). "
        "Rules, signals, and correlations are configuration-evidence only and do "
        "not assert breach, compromise, unauthorized access, or data exposure. "
        "Privacy contract: PagerDuty API tokens, routing keys, integration keys, "
        "webhook secrets, delivery URLs, custom header values, user emails, user "
        "names, phone numbers, contact methods, on-call user identities, responder "
        "identities, subscriber identities, incident payloads, alert payloads, "
        "conference phone numbers, raw routing expressions, IP addresses, user "
        "agents, and customer PII are NEVER fetched or stored. "
        "PagerDuty remains partial (not in the canonical dual-stack-complete set of "
        "8 providers) because drift_review_workflow is not yet active."
    ),
)


_LINEAR = ProviderCapability(
    provider="linear",
    label="Linear",
    category="devops",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=False,
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
    maturity="partial",
    notes=(
        "Linear project-management configuration drift with core and expanded security "
        "rules plus activity ingestion and activity signals (M85A + M85B + M85C + M85D + M85E). Drift snapshots "
        "cover 9 safe configuration surfaces from the Linear GraphQL API: workspace "
        "config, teams, projects, workflow states, issue labels, webhook subscriptions, "
        "custom views, active cycles, and integrations. M85B added 24 core "
        "configuration-risk security rules; M85C adds 15 workflow/webhook risk expansion "
        "rules (39 total). M85D adds review-safe activity ingestion synthesized from the "
        "same 9 safe drift surfaces — Linear's audit API is never used because it "
        "contains actor emails, user IDs, and IP addresses. M85E adds Linear activity "
        "signals derived from ingested activity events. M85F adds Linear Risk x Activity "
        "Correlations, linking security rule violations to proximate activity events. "
        "M85G adds Linear demo and QA. "
        "M85H adds Linear provider depth QA. "
        "M85I adds Linear cross-cloud UX polish and completes the Linear arc (M85A-M85I). "
        "Authentication uses a Linear API key (read-only). API key is stored encrypted "
        "and never returned in API responses, never logged, and never copied to resource "
        "metadata. Issue titles, descriptions, comments, attachments, user emails, user "
        "names, member identities, raw URLs, webhook secrets, and customer data are "
        "never fetched or stored. "
        "planned_next_stage: M86B: Jira Core Security Foundation."
    ),
)


_GITLAB = ProviderCapability(
    provider="gitlab",
    label="GitLab",
    category="devops",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=False,
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
    maturity="partial",
    notes=(
        "GitLab DevOps configuration drift foundation (M87A), core security rules (M87B), "
        "branch/webhook/CI risk expansion (M87C), activity ingestion (M87D), activity "
        "signals (M87E), risk × activity correlations (M87F), and demo/QA (M87G). "
        "Drift snapshots cover 9 safe configuration surfaces from the GitLab REST API v4: "
        "instance posture (version/enterprise/settings — never base URL), "
        "projects (visibility, feature flags, per-project posture counts — never project names, "
        "paths, web_url, ssh_url, http_url, or repository content), "
        "groups (visibility, member count category, subgroup counts — never group names or paths), "
        "branch protection rules (access level categories, force-push flag — never branch names), "
        "webhooks (scheme, SSL verification, secret presence — never raw URL or secret), "
        "CI variable summaries (counts only — never variable names or values), "
        "deploy key summaries (counts only — never key titles, fingerprints, or key material), "
        "runner summaries (posture counts — never runner tokens, IPs, or descriptions), "
        "and MR approval summaries (approval posture booleans/counts — never approver identities). "
        "M87B adds 12 core configuration-risk security rules across project visibility, "
        "group visibility, branch protection (force-push, code-owner approval), webhook security "
        "(secret, SSL), CI/CD variable posture, deploy key write access, runner untagged posture, "
        "and MR approval requirements. "
        "M87C adds 13 expanded rules: webhook HTTP scheme (high), webhook broad event scope (medium), "
        "webhook pipeline/job events (medium), branch push access broad (medium), "
        "branch merge access broad (medium), CI variables all unprotected (medium), "
        "CI variables all unmasked (medium), runner shared enabled (medium), "
        "MR approval reset disabled (medium), MR approver override allowed (medium), "
        "project wiki enabled public (low), project packages enabled public (low), "
        "project container registry enabled public (medium). "
        "Total: 25 GitLab security rules (M87B + M87C). "
        "All rule evidence is metadata-only (booleans, counts, categories, opaque IDs). "
        "Never stores access tokens, webhook URLs, CI variable names/values, deploy key "
        "material, runner tokens/IPs, branch names, user emails, or customer PII. "
        "Authentication uses a GitLab personal access token (stored encrypted, never returned). "
        "M87D adds GitLab activity ingestion: review-safe configuration-state activity events "
        "synthesized from the same stored GitLab configuration snapshots (projects, groups, "
        "branch protection rules, webhooks, CI/CD variable summaries, deploy key summaries, "
        "runner summaries, and MR approval summaries), surfaced via "
        "GET /security/activity/events?provider=gitlab and generated via "
        "POST /security/gitlab-activity/sync. GitLab's audit-event APIs are never ingested — "
        "only safe counts, categories, booleans, and opaque resource identifiers are stored, "
        "never access tokens, webhook URLs/secrets, CI variable names/values, deploy key "
        "material, runner tokens/IPs, branch names, user identities, or PII. Events are "
        "configuration evidence for review and never confirm breach, compromise, unauthorized "
        "access, source-code exposure, secret exposure, token exposure, credential exposure, "
        "or data exposure. "
        "M87E adds GitLab activity signals: review-priority Incident Signals synthesized "
        "from M87D config-state activity events covering project visibility, group visibility, "
        "branch protection, webhook security, CI/CD variable posture, deploy key posture, "
        "runner posture, and merge request approval configuration activity, generated via "
        "POST /security/gitlab-activity/generate-signals and read via "
        "GET /security/signals?provider=gitlab. Idempotent; signals are evidence for review "
        "and never confirm breach, compromise, or data exposure. "
        "M87F adds GitLab risk × activity correlations: active GitLab configuration-risk "
        "findings are joined with GitLab activity signals on the same safe opaque resource "
        "identifier within a review window across eleven correlation families — "
        "public visibility, branch protection, webhook secret/auth, webhook transport, "
        "webhook event scope, CI/CD variable, deploy key, runner, merge request approval, "
        "public feature, and a generic config fallback. Generated via "
        "POST /security/gitlab-activity/generate-correlations and read via "
        "GET /security/correlations?provider=gitlab. Idempotent; correlations are evidence "
        "for review only and never confirm compromise, unauthorized access, source-code "
        "exposure, secret exposure, token exposure, credential exposure, or data exposure. "
        "Only safe opaque identifiers, booleans, counts, and category labels are stored — "
        "never access tokens, webhook URLs/secrets, CI variable names/values, deploy key "
        "material, runner tokens/IPs, branch names, user identities, or PII. "
        "M87G adds the GitLab branch protection and CI/CD posture review demo: a "
        "safe synthetic evidence chain (3 findings, 3 activity events, 3 signals, "
        "3 correlations, 1 case) seeded via POST /incident-demo/seed?provider=gitlab "
        "and cleared via POST /incident-demo/clear?provider=gitlab. All demo evidence "
        "uses safe placeholder IDs only — never access tokens, webhook URLs/secrets, "
        "CI variable names/values, branch names, user identities, or PII. Case report "
        "renders the GitLab provider label. Does not confirm compromise, unauthorized "
        "access, source-code exposure, secret exposure, token exposure, credential "
        "exposure, or data exposure. "
        "M87H is the GitLab provider-depth QA pass: all 25 GitLab rule keys are "
        "confirmed present in the rule registry, confidence, pack, coverage, and "
        "frontend catalog; connector normalizer fields are verified to match what "
        "the security rules read; evaluator dispatch routes to gitlab_rules.evaluate; "
        "activity ingestion renames raw connector fields (url_scheme → "
        "webhook_scheme_category, secret_token_present → webhook_secret_present) so "
        "no forbidden substring appears in event metadata keys; signal and correlation "
        "metadata keys are verified against their respective allowlists; demo "
        "seed/clear/status are confirmed idempotent; case report renders GitLab and "
        "includes the required disclaimer; forbidden wording and secret-shape greps "
        "are clean. No production-blocking field mismatches were found. "
        "M87I completes the GitLab arc with cross-cloud UX polish: GitLab-safe keys "
        "added to the case report _PREVIEW_ALLOWLIST (project_resource_id, "
        "owner_resource_id, owner_type, pattern_category, allow_force_push, "
        "code_owner_approval_required, push/merge access level categories, enabled, "
        "ssl_verification_enabled, webhook_scheme_category, CI variable counts, "
        "correlation metadata keys); PROVIDER_CAPABILITY_TABLE and NEXT_PROVIDERS_BRIEF "
        "in demo-script/page.tsx updated to include GitLab and Jira and advance the "
        "next-provider pointer to Terraform Cloud at M88A; securityDemoScript.ts "
        "incident timeline text updated to include Jira and GitLab in provider lists. "
        "GitLab arc M87A–M87I complete. "
        "planned_next_stage: M88A: Terraform Cloud Drift Provider Foundation."
    ),
)


_JIRA = ProviderCapability(
    provider="jira",
    label="Jira",
    category="devops",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=False,
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
    maturity="partial",
    notes=(
        "Jira project management configuration drift foundation (M86A–M86I). "
        "Drift snapshots cover Jira Cloud configuration surfaces: projects, boards, "
        "workflows, workflow schemes, permission schemes, notification schemes, "
        "issue type schemes, field configuration schemes, screen schemes, webhook "
        "subscriptions, and automation rules. "
        "M86A adds the connector, schema, and provider registration. "
        "M86B adds Jira core security rules (configuration posture findings for site, "
        "project, board, workflow, workflow scheme, permission scheme, notification "
        "scheme, issue type scheme, field configuration scheme, screen scheme, webhook, "
        "and automation rule surfaces). "
        "M86C adds the Jira workflow/webhook risk expansion: 39 additional "
        "configuration-risk rules across workflow structure (done/in-progress status "
        "presence, transition-rule/validator/condition/post-function counts, orphan "
        "statuses), workflow scheme mapping (unmapped issue types, low workflow count, "
        "high issue-type mapping count), permission scheme public/high-privilege grant "
        "posture (public browse/administer/manage-sprints/create/transition grants, "
        "unknown holder types, high-privilege and public grant counts), notification "
        "scheme recipient posture (unknown recipients, high event count), webhook "
        "event-scope posture (comment/attachment/sprint/worklog scopes, all-issue "
        "events), automation rule action posture (web request, email, external, "
        "comment actions, high action/branch counts, multi-project and unknown scope), "
        "board scope posture (no filter indicator, broad filter, high quick-filter "
        "count, unknown swimlane strategy, no columns), and screen scheme mapping "
        "(unmapped operation slots). All evidence is metadata-only — categories, "
        "counts, and derived booleans, never raw JQL, filter/screen/workflow names, "
        "webhook URLs, or grant holder identities. "
        "Issue keys, issue titles, issue descriptions, comments, attachments, user names, "
        "user emails, account IDs, and customer data are never fetched or stored. "
        "M86D adds Jira activity ingestion: review-safe configuration-state activity "
        "events synthesized from the same stored Jira configuration snapshots (site, "
        "project, board, workflow, workflow scheme, permission scheme, notification "
        "scheme, issue type scheme, field configuration scheme, screen scheme, webhook, "
        "and automation rule surfaces), surfaced via "
        "GET /security/activity/events?provider=jira. Jira's audit log / issue / user "
        "activity APIs are never ingested — only safe counts, categories, booleans, and "
        "opaque resource identifiers are stored. "
        "M86E adds Jira activity signals: ingested Jira configuration-state activity "
        "events are promoted into review-priority Incident Signals grouped by safe "
        "resource identity via POST /security/jira-activity/generate-signals and read "
        "via GET /security/signals?provider=jira. Idempotent; review signals only — "
        "never confirms breach, compromise, or unauthorized access. Only safe counts, "
        "categories, booleans, and opaque resource identifiers are stored. "
        "M86F adds Jira risk × activity correlations: active Jira configuration-risk "
        "findings are joined with Jira activity signals on the same safe opaque "
        "resource identifier within a review window (falling back to record-type / "
        "signal-type family matching) across thirteen correlation families — "
        "permission scheme, webhook, workflow, workflow scheme, automation rule, board, "
        "notification scheme, screen scheme, field configuration scheme, issue type "
        "scheme, project, site, and a generic config fallback. Generated via "
        "POST /security/jira-activity/generate-correlations and read via "
        "GET /security/correlations?provider=jira. Idempotent; correlations are evidence "
        "for review only and never confirm compromise, unauthorized access, or data "
        "exposure. Only safe counts, categories, booleans, and opaque resource "
        "identifiers are stored — never API tokens, OAuth tokens, webhook secrets, raw "
        "URLs, JQL text, issue content, comments, attachments, user identities, IP "
        "addresses, user agents, raw audit payloads, or PII. "
        "M86G adds the Jira incident demo (seed/clear/status) and Jira case-report "
        "support: a hidden demo integration seeds a review-safe 'Jira permission "
        "scheme review' chain (permission scheme broad-access, webhook no-secret, and "
        "automation external-action configuration findings → permission-scheme and "
        "webhook configuration activity events → permission-scheme activity signal → "
        "permission-scheme risk × activity correlation → human-reviewed case), all "
        "anchored on synthetic placeholder IDs so clearing removes only the demo "
        "objects. The case report labels Jira and surfaces Jira opaque resource "
        "identifiers, safe counts, posture booleans, and category labels only. "
        "M86H is the Jira provider depth QA pass: the connector normalizers now emit "
        "the canonical schema field names consumed by the security rules, so all 82 "
        "configuration-risk rules (including the M86B base site/project/board/workflow/"
        "scheme/permission/notification/issue-type/field-config/screen/webhook/automation "
        "rules) fire on real connector output; the risk × activity correlation families "
        "were realigned to the canonical 82 rule keys so findings route to their "
        "resource-specific family instead of the generic fallback; and the non-HTTPS "
        "webhook rule now matches the connector's URL scheme category domain. All "
        "evidence remains metadata-only — counts, categories, and derived booleans, "
        "never raw URLs, JQL, identities, secrets, or PII. "
        "M86I adds Jira cross-cloud UX polish and completes the Jira arc (M86A–M86I): "
        "Jira is a first-class completed provider across the internal security UX "
        "surfaces (activity, signals, correlations, cases, rules), the provider "
        "capability table, case-report / timeline labels, and the demo script, with "
        "the roadmap handoff advancing to GitLab (M87A). "
        "Authentication uses Jira email + API token (stored encrypted, never returned). "
        "Jira remains partial (not in the canonical dual-stack-complete set of 8 "
        "providers) because drift_review_workflow is not yet active. "
        "planned_next_stage: M87A: GitLab Drift Provider Foundation."
    ),
)


# Partial / in-progress providers — not counted in the canonical 8-provider matrix.
_TERRAFORM_CLOUD = ProviderCapability(
    provider="terraform_cloud",
    label="Terraform Cloud",
    category="devops",
    drift=DriftCapabilities(
        drift_snapshots=True,
        drift_diff=True,
        drift_risk_classification=True,
        drift_review_workflow=False,
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
    maturity="partial",
    notes=(
        "Terraform Cloud DevOps configuration drift foundation (M88A), core security "
        "rules (M88B), workspace/variable/policy risk expansion (M88C), "
        "configuration activity ingestion (M88D), activity signals (M88E), "
        "risk x activity correlations (M88F), and demo + QA (M88G). "
        "Drift snapshots cover 10 safe configuration surfaces from the Terraform Cloud API v2: "
        "organization posture (workspace/project/policy-set/variable-set counts, SSO, 2FA, "
        "cost estimation, collaborator auth policy — never organization name), "
        "workspaces (execution mode, auto-apply, VCS connection presence, variable counts, "
        "notification/team-access counts, run status category — never workspace name, variable "
        "names/values, VCS URLs, branch names, state file content, plan/apply logs), "
        "projects (workspace count, team access count — never project name), "
        "variable sets (scope, counts only — never variable set name, variable names or values), "
        "workspace variable summaries (counts only — never variable names or values), "
        "policy sets (global scope, policy count, enforcement level, VCS connection presence — "
        "never policy names, code, or VCS details), "
        "notification configurations (enabled status, destination type, trigger count, URL scheme — "
        "never webhook URLs, tokens, or email recipients), "
        "team access summaries (access-level counts per workspace — never team names), "
        "run triggers (sourceable type category — never source workspace name), "
        "state version summaries (presence boolean only — raw state file NEVER fetched or stored). "
        "M88B adds 18 configuration-risk security rules across 8 record types: organization "
        "2FA/SSO posture (medium/low); workspace auto-apply (high), global remote state (high), "
        "local execution mode (medium), VCS connection missing (medium), queue-all-runs (medium), "
        "unpinned Terraform version (low); workspace variable non-sensitive present (medium), "
        "no sensitive variables (low); notification webhook HTTP (high), token missing (medium); "
        "policy set advisory enforcement (medium), policy set empty (low); team admin access (high), "
        "team apply access (medium); variable set global scope (medium); state version present (low). "
        "M88C adds 18 additional rules: workspace agent execution mode (medium), file triggers "
        "disabled (medium), speculative plans disabled (low), run triggers present (medium), "
        "many trigger prefixes (low), latest run failed (medium); workspace env vars non-sensitive "
        "(medium), Terraform vars non-sensitive (low); variable set non-sensitive variables (medium), "
        "variable set broad scope (medium); policy set global scope (medium), broad scope advisory "
        "(medium), no workspace or project scope (low); notification broad trigger scope (medium), "
        "notification disabled (low); run trigger enabled (medium); team write access (medium), "
        "team custom permissions (low). Total: 36 Terraform Cloud security rules (M88B + M88C). "
        "All rule evidence is metadata-only (booleans, counts, categories, opaque IDs). "
        "Never stores: organization names, workspace names, variable names/values, state files, "
        "plan/apply logs, VCS URLs, team names, user emails, webhook URLs, or customer PII. "
        "M88D adds configuration activity ingestion: synthesizes safe config-state events "
        "from drift records across 9 Terraform Cloud record surfaces. Events use only "
        "opaque IDs, booleans, counts, and category labels — never variable values, "
        "state files, tokens, URLs, names, or customer data. "
        "M88E adds activity signal generation: promotes M88D config-state events into "
        "17 review-priority Incident Signal types covering organization access posture, "
        "workspace execution, VCS, run control, variable posture, variable set scope, "
        "policy set enforcement, notification transport, run triggers, team access, and "
        "state version metadata. All signal metadata is allowlisted and flat. "
        "M88F adds risk x activity correlations: joins 36 Terraform Cloud "
        "configuration-risk findings (M88B/M88C) with 17 activity signal types (M88E) "
        "across 15 specialized correlation families. Correlation metadata is allowlisted "
        "and flat. "
        "M88G adds demo + QA: a review-safe Terraform Cloud demo incident chain "
        "(seed/clear/status) with 3 configuration findings (workspace auto-apply, global "
        "remote state, non-sensitive variables), 3 activity events, 3 activity signals, "
        "3 risk x activity correlations, and a linked case. No Terraform Cloud API tokens, "
        "variable names or values, state files, state outputs, VCS URLs, webhook URLs, "
        "team names, user identities, or PII are stored in the demo chain. Case report, "
        "evidence timeline, and evidence graph are fully supported. "
        "M88H adds provider-depth QA: durable guardrails covering taxonomy parity "
        "(10 record types, 36 rule keys, 25+ activity event types, 17 signal types, "
        "15 correlation types), privacy sanitization (allowlist verified for activity/ "
        "signal/correlation/case-report layers), claim discipline (forbidden-phrase scan "
        "across all TC modules), false-positive behavior pins, demo isolation "
        "(seed/clear idempotency), router admin guards, and frontend consistency. "
        "M88I completes the Terraform Cloud arc with cross-cloud UX polish: Terraform "
        "Cloud is a first-class completed provider across the internal security UX "
        "surfaces (activity, signals, correlations, cases, rules), the provider "
        "capability table, case-report/timeline labels, and the demo script, with "
        "the roadmap handoff advancing to Kubernetes (M89A). Terraform Cloud arc "
        "M88A–M88I complete. "
        "planned_next_stage: M89A: Kubernetes Drift Provider Foundation."
    ),
)


PROVIDER_CAPABILITIES_PARTIAL: list[ProviderCapability] = [
    _AZURE,
    _GOOGLE_CLOUD,
    _TWILIO,
    _SENDGRID,
    _AUTH0,
    _DATADOG,
    _CLERK,
    _PAGERDUTY,
    _LINEAR,
    _JIRA,
    _GITLAB,
    _TERRAFORM_CLOUD,
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
