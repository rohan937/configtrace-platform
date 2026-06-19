"use client";

/**
 * Correlations (M66.6).
 *
 * Configuration Risk × GitHub audit activity — the core differentiator. Links a
 * Configuration Risk finding to GitHub audit activity on the same repository
 * within a review window.
 *
 * CLAIM DISCIPLINE: correlations are evidence for review. Never state that a
 * breach, attacker, compromise, or unauthorized access has been confirmed.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import type {
  SecuritySignalCorrelation,
  SecurityCorrelationGenerateResponse,
  TwilioCorrelationGenerateResponse,
  Auth0CorrelationGenerateResponse,
  DatadogCorrelationGenerateResponse,
  ClerkCorrelationGenerateResponse,
  PagerDutyCorrelationGenerateResponse,
} from "@/types";
import { getSecurityCorrelations, generateSecurityCorrelations, generateTwilioCorrelations, generateSendGridCorrelations, generateAuth0Correlations, generateDatadogCorrelations, generateClerkCorrelations, generatePagerDutyCorrelations } from "@/lib/api";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { formatRelativeTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";
import { SeverityBadge, ConfidenceBadge } from "@/components/security/findingDisplay";
import { SignalStatusBadge } from "@/components/security/signalDisplay";

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];
const STATUS_OPTIONS = ["open", "acknowledged", "dismissed", "resolved"];
const PROVIDER_OPTIONS = ["github", "aws", "cloudflare", "vercel", "supabase", "firebase", "stripe", "shopify", "azure", "google_cloud", "twilio", "sendgrid", "auth0", "datadog", "clerk", "pagerduty"];
const TYPE_OPTIONS_BY_PROVIDER: Record<string, string[]> = {
  github: [
    "webhook_change",
    "branch_protection_change",
    "deploy_key_added",
    // M69.4C — Configuration Risk × secret-scanning alert evidence.
    "github_repo_protection_secret_alert",
    "github_automation_secret_alert",
    "github_repo_risk_secret_alert",
    // M69.4F — Configuration Risk × code-scanning alert evidence.
    "github_repo_protection_code_alert",
    "github_automation_code_alert",
    "github_environment_code_alert",
    // M69.4I — Configuration Risk × Dependabot alert evidence.
    "github_repo_protection_dependabot_alert",
    "github_automation_dependabot_alert",
    "github_environment_dependabot_alert",
    // M69.5C — Ruleset / automation-permission risk × evidence.
    "github_ruleset_risk_activity",
    "github_ruleset_risk_security_alert",
    "github_automation_permission_activity",
    "github_automation_permission_security_alert",
  ],
  aws: [
    "aws_s3_public_access_alert",
    "aws_iam_credential_alert",
    // M69.2A — S3 exposure × S3 object-level activity.
    "aws_s3_public_getobject_activity",
    "aws_s3_public_listbucket_activity",
    "aws_s3_public_access_spike_activity",
    // M69.2B — SG exposure × VPC Flow Log network activity.
    "aws_sg_public_admin_port_flow",
    "aws_sg_public_database_port_flow",
    "aws_sg_public_rejected_flow_activity",
    // M69.3B — IAM configuration risk × IAM privilege-chain activity.
    "aws_iam_admin_risk_privilege_chain",
    "aws_iam_access_key_risk_privilege_chain",
  ],
  cloudflare: [
    "cloudflare_dns_change",
    "cloudflare_waf_change",
    "cloudflare_tls_change",
    "cloudflare_access_policy_change",
    "cloudflare_zone_setting_change",
    // M68.6 — Configuration Risk × WAF/security-event activity.
    "cloudflare_waf_risk_activity",
    "cloudflare_zone_security_activity",
    "cloudflare_dns_origin_activity",
    "cloudflare_access_policy_activity",
    "cloudflare_tls_activity",
  ],
  vercel: [
    // M70D — Vercel Configuration Risk × Vercel audit activity.
    "vercel_project_branch_activity",
    "vercel_domain_risk_activity",
    "vercel_env_var_risk_activity",
    "vercel_deploy_hook_risk_activity",
    "vercel_deployment_protection_activity",
  ],
  supabase: [
    // M71D — Supabase Configuration Risk × Supabase audit activity.
    "supabase_rls_risk_activity",
    "supabase_public_select_risk_activity",
    "supabase_public_write_risk_activity",
    "supabase_edge_function_risk_activity",
    "supabase_auth_protection_risk_activity",
  ],
  firebase: [
    // M72D — Firebase Configuration Risk × Firebase audit activity.
    "firebase_firestore_rules_risk_activity",
    "firebase_database_rules_risk_activity",
    "firebase_storage_rules_risk_activity",
    "firebase_anonymous_auth_risk_activity",
    "firebase_auth_protection_risk_activity",
  ],
  stripe: [
    // M73D — Stripe Configuration Risk × Stripe configuration activity.
    "stripe_webhook_insecure_risk_activity",
    "stripe_webhook_disabled_risk_activity",
    "stripe_webhook_broad_events_risk_activity",
    "stripe_payment_link_tax_risk_activity",
    "stripe_payment_link_promo_risk_activity",
    "stripe_portal_cancel_risk_activity",
    "stripe_portal_login_risk_activity",
    "stripe_account_capability_risk_activity",
  ],
  shopify: [
    // M74D — Shopify Configuration Risk × Shopify configuration activity.
    // App-scope / customer-scope / policy correlations are intentionally
    // deferred until Shopify activity ingestion emits the matching event
    // types.
    "shopify_webhook_insecure_risk_activity",
    "shopify_webhook_topic_risk_activity",
    "shopify_domain_ssl_risk_activity",
    "shopify_domain_verification_risk_activity",
  ],
  azure: [
    // M77F — Azure Configuration Risk × Azure Activity Log evidence.
    // Resource-name-scoped matching for NSG / Storage / Key Vault / App Service
    // / SQL / AKS; role-assignment match for broad-privilege role assignments.
    "azure_nsg_exposure_activity_correlation",
    "azure_storage_risk_activity_correlation",
    "azure_key_vault_risk_activity_correlation",
    "azure_role_assignment_risk_activity_correlation",
    "azure_app_service_risk_activity_correlation",
    "azure_sql_risk_activity_correlation",
    "azure_aks_risk_activity_correlation",
  ],
  google_cloud: [
    // M78F — Google Cloud Configuration Risk × Google Cloud Audit Log evidence.
    // Resource-name-scoped matching for firewall rules / Cloud Storage buckets /
    // Cloud SQL instances / Cloud Run services / GKE clusters; project+family
    // aggregate matching for IAM / service-account-key / Secret Manager risks.
    "google_cloud_iam_risk_activity_correlation",
    "google_cloud_firewall_risk_activity_correlation",
    "google_cloud_storage_risk_activity_correlation",
    "google_cloud_sql_risk_activity_correlation",
    "google_cloud_run_risk_activity_correlation",
    "google_cloud_gke_risk_activity_correlation",
    "google_cloud_service_account_key_risk_activity_correlation",
    "google_cloud_secret_manager_risk_activity_correlation",
  ],
  twilio: [
    // M79F — Twilio Configuration Risk × Twilio Activity evidence.
    // Resource-identity-scoped matching for phone numbers / messaging services /
    // Verify services / API keys; account-level match for account risks.
    "twilio_phone_number_risk_activity_correlation",
    "twilio_messaging_service_risk_activity_correlation",
    "twilio_verify_service_risk_activity_correlation",
    "twilio_api_key_risk_activity_correlation",
    "twilio_account_risk_activity_correlation",
  ],
  sendgrid: [
    // M80F — SendGrid Configuration Risk × SendGrid Activity evidence.
    // Resource-identity-scoped matching for API keys / sender identities /
    // domain authentication; account-level match for mail settings, tracking
    // settings, webhook/inbound parse, and suppression settings.
    "sendgrid_api_key_risk_activity_correlation",
    "sendgrid_sender_identity_risk_activity_correlation",
    "sendgrid_domain_authentication_risk_activity_correlation",
    "sendgrid_mail_settings_risk_activity_correlation",
    "sendgrid_tracking_settings_risk_activity_correlation",
    "sendgrid_webhook_risk_activity_correlation",
    "sendgrid_suppression_settings_risk_activity_correlation",
  ],
  auth0: [
    // M81F — Auth0 Configuration Risk × Auth0 Activity evidence.
    // Resource-identity-scoped matching for applications (client_id) /
    // connections (connection_id) / resource servers (resource_server_id) /
    // rules (rule_id) / actions (action_id) / MFA factors (factor_name) /
    // custom domains (custom_domain_id); tenant-level match for tenant risks.
    "auth0_tenant_risk_activity_correlation",
    "auth0_application_risk_activity_correlation",
    "auth0_connection_risk_activity_correlation",
    "auth0_resource_server_risk_activity_correlation",
    "auth0_rule_risk_activity_correlation",
    "auth0_action_risk_activity_correlation",
    "auth0_mfa_factor_risk_activity_correlation",
    "auth0_custom_domain_risk_activity_correlation",
  ],
  datadog: [
    // M82F — Datadog Configuration Risk × Datadog Activity evidence.
    // Resource-identity-scoped matching on monitor_id / slo_id / dashboard_id /
    // webhook_id / notification_integration_id / api_key_id / application_key_id /
    // role_id / team_id / cloud_integration_id; family aggregate fallback when
    // specific IDs are absent; generic resource_type/resource_id fallback last.
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
  ],
  clerk: [
    "clerk_instance_settings_risk_activity_correlation",
    "clerk_application_risk_activity_correlation",
    "clerk_domain_risk_activity_correlation",
    "clerk_redirect_url_risk_activity_correlation",
    "clerk_jwt_template_risk_activity_correlation",
    "clerk_webhook_endpoint_risk_activity_correlation",
    "clerk_email_sms_settings_risk_activity_correlation",
    "clerk_auth_strategy_risk_activity_correlation",
    "clerk_organization_settings_risk_activity_correlation",
    "clerk_session_policy_risk_activity_correlation",
  ],
  // M84F — PagerDuty Risk × PagerDuty Activity evidence.
  pagerduty: [
    "pagerduty_service_risk_activity_correlation",
    "pagerduty_escalation_policy_risk_activity_correlation",
    "pagerduty_schedule_risk_activity_correlation",
    "pagerduty_service_integration_risk_activity_correlation",
    "pagerduty_webhook_subscription_risk_activity_correlation",
    "pagerduty_event_orchestration_risk_activity_correlation",
    "pagerduty_business_service_risk_activity_correlation",
    "pagerduty_response_play_risk_activity_correlation",
    "pagerduty_config_activity_correlation",
  ],
};
const HIGH = new Set(["critical", "high"]);

export default function CorrelationsPage() {
  const { getToken } = useAuth();
  const { isAdmin, roleLoaded } = useWorkspace();

  const [rows, setRows] = useState<SecuritySignalCorrelation[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [provider, setProvider] = useState("github");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [type, setType] = useState("");

  const typeOptions = TYPE_OPTIONS_BY_PROVIDER[provider] ?? [];

  const [generating, setGenerating] = useState(false);
  const [genResult, setGenResult] = useState<(SecurityCorrelationGenerateResponse | TwilioCorrelationGenerateResponse | Auth0CorrelationGenerateResponse | DatadogCorrelationGenerateResponse | ClerkCorrelationGenerateResponse | PagerDutyCorrelationGenerateResponse) | null>(null);
  const [genError, setGenError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const res = await getSecurityCorrelations(
        {
          provider,
          severity: severity || undefined,
          status: status || undefined,
          correlation_type: type || undefined,
          page_size: 100,
        },
        token,
      );
      setRows(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch {
      setError("Could not load correlations. Please try again.");
    } finally {
      setLoading(false);
    }
  }, [getToken, provider, severity, status, type]);

  useEffect(() => {
    void load();
  }, [load]);

  const onGenerate = useCallback(async () => {
    setGenerating(true);
    setGenError(null);
    setGenResult(null);
    try {
      const token = await getToken();
      if (provider === "twilio") {
        const res = await generateTwilioCorrelations(token);
        setGenResult(res);
      } else if (provider === "sendgrid") {
        const res = await generateSendGridCorrelations(token);
        setGenResult(res);
      } else if (provider === "auth0") {
        const res = await generateAuth0Correlations(token);
        setGenResult(res);
      } else if (provider === "datadog") {
        const res = await generateDatadogCorrelations(token);
        setGenResult(res);
      } else if (provider === "clerk") {
        const res = await generateClerkCorrelations(token);
        setGenResult(res);
      } else if (provider === "pagerduty") {
        const res = await generatePagerDutyCorrelations(token);
        setGenResult(res);
      } else {
        const res = await generateSecurityCorrelations({ provider }, token);
        setGenResult(res);
      }
      await load();
    } catch {
      setGenError("Could not generate correlations. Please try again.");
    } finally {
      setGenerating(false);
    }
  }, [getToken, provider, load]);

  // Switching provider invalidates a provider-specific type filter.
  const onProviderChange = useCallback((next: string) => {
    setProvider(next);
    setType("");
  }, []);

  const metrics = useMemo(() => {
    const open = rows.filter((r) => r.status === "open").length;
    const high = rows.filter((r) => HIGH.has(r.severity)).length;
    const latest = rows.reduce<string | null>((acc, r) => {
      const t = r.last_seen_at ?? r.first_seen_at ?? r.created_at;
      if (!t) return acc;
      if (!acc || Date.parse(t) > Date.parse(acc)) return t;
      return acc;
    }, null);
    return { open, high, latest };
  }, [rows]);

  return (
    <div>
      <Hero />

      <GenerateBar
        provider={provider}
        isAdmin={isAdmin}
        roleLoaded={roleLoaded}
        generating={generating}
        genResult={genResult}
        genError={genError}
        onGenerate={onGenerate}
      />

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
          gap: "14px",
          marginBottom: "24px",
        }}
      >
        <Metric label="Open correlations" value={metrics.open} accent="#f5632a" />
        <Metric label="High severity" value={metrics.high} accent="#e84040" />
        <Metric label="Total correlations" value={rows.length} accent="#6b9cf8" />
        <Metric
          label="Latest"
          text={metrics.latest ? formatRelativeTime(metrics.latest) : "—"}
          accent="#3ccf7e"
        />
      </div>

      <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center", marginBottom: "18px" }}>
        <Select label="Provider" value={provider} onChange={onProviderChange} options={PROVIDER_OPTIONS} includeAll={false} />
        <Select label="Severity" value={severity} onChange={setSeverity} options={SEVERITY_OPTIONS} />
        <Select label="Status" value={status} onChange={setStatus} options={STATUS_OPTIONS} />
        <Select label="Type" value={type} onChange={setType} options={typeOptions} />
      </div>

      {loading ? (
        <LoadingState />
      ) : error ? (
        <ErrorState message={error} />
      ) : rows.length === 0 ? (
        <EmptyState isAdmin={isAdmin} provider={provider} />
      ) : (
        <>
          <SectionLabel>
            {total} correlation{total === 1 ? "" : "s"}
          </SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {rows.map((c) => (
              <Row key={c.id} c={c} />
            ))}
          </div>
        </>
      )}

      <p style={{ margin: "26px 0 0", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
        A correlation means a configuration risk and provider activity were
        observed for the same resource within a review window — a GitHub
        repository, an AWS bucket / IAM principal matched to a GuardDuty or
        Access Analyzer finding, or a Cloudflare zone matched to DNS / WAF / TLS
        audit activity. Correlations are evidence for review. They do not by
        themselves confirm compromise or unauthorized access.
      </p>
    </div>
  );
}

function Hero() {
  return (
    <>
      <PageHeader title="Correlations" description="Configuration risks connected to provider activity and alerts." />
      <div
        className="bg-surface1 border border-border"
        style={{ borderRadius: "12px", padding: "16px 18px", marginBottom: "20px" }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>GitHub + AWS + Cloudflare beta</span>
          <Badge>Beta</Badge>
        </div>
        <p style={{ margin: 0, fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
          Correlations are evidence for review. They do not by themselves confirm
          compromise.
        </p>
      </div>
    </>
  );
}

function GenerateBar({
  provider,
  isAdmin,
  roleLoaded,
  generating,
  genResult,
  genError,
  onGenerate,
}: {
  provider: string;
  isAdmin: boolean;
  roleLoaded: boolean;
  generating: boolean;
  genResult: (SecurityCorrelationGenerateResponse | TwilioCorrelationGenerateResponse | Auth0CorrelationGenerateResponse | DatadogCorrelationGenerateResponse | ClerkCorrelationGenerateResponse | PagerDutyCorrelationGenerateResponse) | null;
  genError: string | null;
  onGenerate: () => void;
}) {
  const blurb =
    provider === "cloudflare"
      ? "Correlate Cloudflare configuration risks with Cloudflare audit activity and WAF/security activity for the same zone, host, or risk area (DNS, WAF, TLS, Access, zone settings)."
      : provider === "aws"
        ? "Correlate AWS configuration risks with GuardDuty and Access Analyzer findings for the same bucket or IAM principal."
        : provider === "vercel"
          ? "Correlate Vercel configuration risks with Vercel activity evidence (project, domain, environment-variable, deploy-hook, and deployment activity) for the same project within the review window."
          : provider === "supabase"
            ? "Correlate Supabase configuration risks with Supabase activity evidence (table/RLS, access policy, Edge Function, and auth-configuration activity) for the same table/function/project within the review window."
            : provider === "firebase"
              ? "Correlate Firebase configuration risks with Firebase activity evidence (Firestore/Realtime Database/Storage rules and auth-configuration activity) for the same project within the review window."
              : provider === "stripe"
                ? "Correlate Stripe configuration risks with Stripe configuration activity evidence (webhook endpoint, payment link, customer portal, and account / capability changes) for the same Stripe object within the review window."
                : provider === "shopify"
                  ? "Correlate Shopify configuration risks with Shopify configuration activity evidence (webhook subscription and shop-domain changes) for the same Shopify webhook or domain within the review window."
                  : provider === "azure"
                    ? "Correlate Azure configuration risks with recent Azure Activity Log signals across NSGs, Storage, Key Vault, role assignments, App Service, SQL, and AKS — matching on the same resource (and resource group when both sides agree) within the review window."
                    : provider === "google_cloud"
                      ? "Correlate Google Cloud configuration risks with recent Audit Log signals across IAM, firewall rules, Storage, Cloud SQL, Cloud Run, GKE, service accounts, and Secret Manager. Resource-name matches for firewall / Storage / SQL / Cloud Run / GKE; project + family aggregate matches for IAM / service-account-key / Secret Manager. Provider-only matches are never produced."
                      : provider === "twilio"
                        ? "Correlate Twilio configuration risks with Twilio activity signals across phone numbers, messaging services, Verify services, API keys, and account configuration. Matches on safe resource identifiers (phone_number_last4, messaging_service_sid, verify_service_sid, api_key_sid) or provider+family aggregate. Message bodies, call logs, recordings, full phone numbers, auth tokens, and API secrets are never used."
                        : provider === "sendgrid"
                          ? "Correlate SendGrid configuration risks with SendGrid activity signals across API keys, sender identities, domain authentication, mail settings, tracking settings, event webhook, inbound parse, and suppression settings. Matches on safe resource identifiers (api_key_id, sender_id, domain_id) or provider+family aggregate for account-level surfaces. Email bodies, subject lines, recipient emails, mail event payloads, raw webhook URLs, API key values, and customer data are never used."
                          : provider === "auth0"
                            ? "Generate Auth0 risk × activity correlations from safe configuration findings and activity signals. ConfigTrace stores resource identifiers, OAuth/application posture, tenant settings, and activity summaries only — never user emails, login history, IP addresses, sessions, tokens, callback URLs, raw Auth0 logs, or client secrets. Matches on client_id (applications), connection_id, resource_server_id, rule_id, action_id, factor_name, or custom_domain_id."
                            : provider === "datadog"
                              ? "Generate review-safe Datadog correlations between configuration findings and recent Datadog configuration activity. ConfigTrace stores only rule keys, signal types, opaque resource IDs, counts, categories, and timing evidence — never API keys, application keys, raw monitor queries, raw monitor messages, webhook URLs, headers, payloads, logs, traces, metric values, incident text, emails, destination handles, raw audit payloads, or PII."
                              : provider === "clerk"
                                ? "Generate review-safe Clerk correlations between configuration findings and recent Clerk configuration activity. Stores rule keys, signal types, opaque resource IDs, counts, and timing evidence only — never Clerk secret keys, session tokens, JWTs, OAuth tokens, webhook secrets, raw redirect URLs, raw callback URLs, raw webhook URLs, raw domain names, user emails, user IDs, phone numbers, names, session history, login history, IP addresses, user agents, raw audit payloads, customer data, or PII."
                                : provider === "pagerduty"
                                  ? "Generate review-safe PagerDuty correlations between configuration findings and recent PagerDuty configuration activity. ConfigTrace stores only rule keys, signal types, opaque resource IDs, counts, categories, and timing evidence — never API tokens, routing keys, integration keys, webhook secrets, raw URLs, user contact data, incident payloads, alert payloads, IP addresses, user agents, or PII."
                                  : "Matches GitHub configuration risks — including ruleset and automation-permission risks — to audit activity, secret-scanning, code-scanning, and Dependabot alert evidence on the same repository within the review window.";
  return (
    <div
      className="bg-surface1 border border-border"
      style={{
        borderRadius: "12px",
        padding: "14px 16px",
        marginBottom: "20px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "12px",
        flexWrap: "wrap",
      }}
    >
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          Generate correlations
        </div>
        <div style={{ fontSize: "12px", color: "#8b90a0", marginTop: "2px" }}>
          {blurb}
          {!isAdmin && roleLoaded && " Only workspace admins can generate correlations."}
        </div>
        {genResult && (
          <div style={{ fontSize: "12px", color: "#3ccf7e", marginTop: "6px" }}>
            Scanned {genResult.findings_scanned} risks ·{" "}
            {"signals_scanned" in genResult
              ? `${genResult.signals_scanned} signals`
              : `${"events_scanned" in genResult ? genResult.events_scanned : 0} events`}{" "}
            · {genResult.correlations_created} created · {genResult.correlations_skipped} skipped.
          </div>
        )}
        {genError && <div style={{ fontSize: "12px", color: "#e84040", marginTop: "6px" }}>{genError}</div>}
      </div>
      <button
        onClick={onGenerate}
        disabled={!isAdmin || generating}
        title={!isAdmin ? "Only workspace admins can generate correlations." : undefined}
        style={{
          fontSize: "13px",
          fontWeight: 500,
          color: isAdmin ? "#0b0d12" : "#565b6e",
          background: isAdmin ? "#6b9cf8" : "#1e2030",
          border: "none",
          padding: "8px 16px",
          borderRadius: "8px",
          cursor: !isAdmin || generating ? "not-allowed" : "pointer",
          opacity: generating ? 0.7 : 1,
          whiteSpace: "nowrap",
        }}
      >
        {generating ? "Generating…" : "Generate correlations"}
      </button>
    </div>
  );
}

function Row({ c }: { c: SecuritySignalCorrelation }) {
  const when = c.last_seen_at ?? c.first_seen_at ?? c.created_at;
  return (
    <Link
      href={`/security/correlations/${c.id}`}
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", textDecoration: "none", display: "block", padding: "14px 16px" }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
        <SeverityBadge severity={c.severity} />
        <span style={{ fontSize: "14px", fontWeight: 600, color: "#e8eaf0", flex: 1, minWidth: 0 }}>
          {c.title}
        </span>
        <span style={{ fontSize: "12px", color: "#6b9cf8" }}>View correlation →</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap", marginTop: "9px" }}>
        <SignalStatusBadge status={c.status} />
        <ConfidenceBadge confidence={c.confidence} />
        <span style={{ fontSize: "12px", color: "#8b90a0" }}>{c.provider}</span>
        <span style={{ color: "#3a3d48" }}>·</span>
        <span style={{ fontSize: "12px", color: "#8b90a0" }}>{c.correlation_type}</span>
        {c.linked_finding_id && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <span style={{ fontSize: "12px", color: "#8b90a0" }}>linked risk</span>
          </>
        )}
        {c.linked_activity_event_id && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <span style={{ fontSize: "12px", color: "#8b90a0" }}>linked activity</span>
          </>
        )}
        {when && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <span style={{ fontSize: "12px", color: "#8b90a0" }}>{formatRelativeTime(when)}</span>
          </>
        )}
      </div>
    </Link>
  );
}

function Metric({ label, value, text, accent }: { label: string; value?: number; text?: string; accent: string }) {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px" }}>
      <div style={{ fontSize: "12px", color: "#8b90a0", fontWeight: 500 }}>{label}</div>
      <div style={{ fontSize: text ? "16px" : "28px", fontWeight: 700, color: accent, marginTop: "8px", letterSpacing: "-0.02em" }}>
        {text ?? value ?? 0}
      </div>
    </div>
  );
}

function Select({
  label,
  value,
  onChange,
  options,
  includeAll = true,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: string[];
  includeAll?: boolean;
}) {
  return (
    <label style={{ fontSize: "12px", color: "#8b90a0", display: "flex", alignItems: "center", gap: "6px" }}>
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="bg-surface1 border border-border"
        style={{ fontSize: "12px", color: "#c4c8d4", borderRadius: "6px", padding: "5px 8px" }}
      >
        {includeAll && <option value="">All</option>}
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

function Badge({ children }: { children: React.ReactNode }) {
  return (
    <span
      style={{
        fontSize: "9px",
        fontWeight: 700,
        letterSpacing: "0.05em",
        textTransform: "uppercase",
        color: "#6b9cf8",
        border: "1px solid rgba(107,156,248,0.4)",
        borderRadius: "5px",
        padding: "1px 6px",
      }}
    >
      {children}
    </span>
  );
}

function EmptyState({ isAdmin, provider }: { isAdmin: boolean; provider: string }) {
  const scope =
    provider === "aws"
      ? "the same AWS resource (bucket / IAM principal)"
      : provider === "cloudflare"
        ? "the same Cloudflare zone, host, or risk area"
        : provider === "vercel"
          ? "the same Vercel project"
          : provider === "supabase"
            ? "the same Supabase table, function, or project"
            : provider === "firebase"
              ? "the same Firebase project"
              : provider === "stripe"
                ? "the same Stripe webhook endpoint, payment link, portal configuration, or account"
                : provider === "shopify"
                  ? "the same Shopify webhook or shop-domain"
                  : provider === "azure"
                    ? "the same Azure resource (NSG / Storage account / Key Vault / App Service / SQL Server / AKS cluster), or the same role + scope for role-assignment risks. Sync Azure activity, generate Azure signals, then generate Azure correlations to align configuration risks with Activity Log evidence on the same resource."
                    : provider === "google_cloud"
                      ? "the same Google Cloud resource (firewall rule / Cloud Storage bucket / Cloud SQL instance / Cloud Run service / GKE cluster), or the same project + family for IAM, service-account-key, and Secret Manager risks. Sync Google Cloud activity, generate Google Cloud signals, then generate Google Cloud correlations."
                      : provider === "twilio"
                        ? "the same Twilio resource (phone number / messaging service / Verify service / API key), or the same account + family for account and config-level risks. Sync Twilio activity, generate Twilio signals, then generate Twilio correlations."
                        : provider === "sendgrid"
                          ? "the same SendGrid resource (API key / sender identity / domain), or the same account + family for mail settings, tracking settings, webhook, and suppression risks. Sync SendGrid activity, generate SendGrid signals, then generate SendGrid correlations."
                          : provider === "auth0"
                            ? "the same Auth0 resource (application / connection / resource server / rule / action / MFA factor / custom domain), or the same tenant for tenant-level risks. Sync Auth0 activity, generate Auth0 signals, then generate Auth0 correlations to align configuration risks with control-plane activity evidence on the same Auth0 surface."
                            : provider === "datadog"
                              ? "the same Datadog resource (monitor / SLO / dashboard / webhook integration / notification integration / API key / application key / role / team / cloud integration). Sync Datadog activity, generate Datadog signals, then generate Datadog correlations to align configuration risks with configuration activity evidence on the same Datadog surface. API keys, application keys, raw monitor queries, raw messages, webhook URLs, notification handles, emails, user IDs, and raw audit payloads are never stored."
                              : provider === "clerk"
                                ? "the same Clerk resource (instance / application / domain / redirect URL / JWT template / webhook endpoint / email-SMS settings / auth strategy / organization settings / session policy). Sync Clerk activity, generate Clerk signals, then generate Clerk correlations to align configuration risks with Clerk configuration activity evidence on the same Clerk surface."
                                : provider === "pagerduty"
                                  ? "the same PagerDuty resource (service / escalation policy / schedule / service integration / webhook subscription / event orchestration / business service / response play). Sync PagerDuty activity, generate PagerDuty signals, then generate PagerDuty correlations to align incident-response configuration risks with activity evidence on the same PagerDuty surface."
                                  : "the same GitHub repository";
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "32px 24px", textAlign: "center" }}>
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#e8eaf0" }}>No correlations yet.</div>
      <p style={{ margin: "8px auto 0", maxWidth: "480px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
        Correlations appear once you have both Configuration Risks and related
        activity for {scope}.
        {isAdmin
          ? " Use “Generate correlations” above once both exist."
          : " A workspace admin can generate correlations once both exist."}
      </p>
    </div>
  );
}
