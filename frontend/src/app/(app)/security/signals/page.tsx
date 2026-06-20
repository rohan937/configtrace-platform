"use client";

/**
 * Incident Signals (M66.4).
 *
 * Frontend for the M66.3 backend signal layer. Shows control-plane REVIEW
 * signals generated from normalized GitHub audit activity.
 *
 * CLAIM DISCIPLINE: signals are review cues from audit activity. This page must
 * never state that a breach, attacker, compromise, or unauthorized access has
 * been confirmed. Severity = review priority; evidence_level = "activity".
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import type {
  SecurityIncidentSignal,
  SecuritySignalGenerateResponse,
} from "@/types";
import {
  getSecurityIncidentSignals,
  generateSecurityIncidentSignals,
  generateAwsIncidentSignals,
  generateAwsIamBehaviorSignals,
  generateAwsIamChainSignals,
  generateAwsSecurityHubSignals,
  generateAwsS3AccessSignals,
  generateAwsVpcFlowSignals,
  generateCloudflareSignals,
  generateCloudflareWafSignals,
  generateGitHubSecretScanningSignals,
  generateGitHubCodeScanningSignals,
  generateGitHubDependabotSignals,
  generateVercelActivitySignals,
  generateSupabaseActivitySignals,
  generateFirebaseActivitySignals,
  generateStripeActivitySignals,
  generateShopifyActivitySignals,
  generateAzureActivitySignals,
  generateGoogleCloudActivitySignals,
  generateTwilioActivitySignals,
  generateSendGridActivitySignals,
  generateAuth0ActivitySignals,
  generateDatadogActivitySignals,
  generateClerkActivitySignals,
  generatePagerDutyActivitySignals,
  generateLinearActivitySignals,
  generateJiraActivitySignals,
  generateGitlabActivitySignals,
  generateTerraformCloudActivitySignals,
} from "@/lib/api";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { formatRelativeTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";
import {
  SeverityBadge,
  ConfidenceBadge,
} from "@/components/security/findingDisplay";
import { SignalStatusBadge } from "@/components/security/signalDisplay";

type Provider = "github" | "aws" | "cloudflare" | "vercel" | "supabase" | "firebase" | "stripe" | "shopify" | "azure" | "google_cloud" | "twilio" | "sendgrid" | "auth0" | "datadog" | "clerk" | "pagerduty" | "linear" | "jira" | "gitlab" | "terraform_cloud";

const CLOUDFLARE_SIGNAL_TYPES = ["cloudflare_audit_activity", "cloudflare_waf_activity_signal"];
const VERCEL_SIGNAL_TYPES = ["vercel_activity_signal"];
const SUPABASE_SIGNAL_TYPES = ["supabase_activity_signal"];
const FIREBASE_SIGNAL_TYPES = ["firebase_activity_signal"];
const STRIPE_SIGNAL_TYPES = ["stripe_activity_signal"];
const SHOPIFY_SIGNAL_TYPES = ["shopify_activity_signal"];
const AZURE_SIGNAL_TYPES = [
  "azure_network_exposure_changed",
  "azure_nsg_deleted",
  "azure_storage_config_changed",
  "azure_storage_account_deleted",
  "azure_key_vault_config_changed",
  "azure_key_vault_deleted",
  "azure_role_assignment_changed",
  "azure_app_service_config_changed",
  "azure_app_service_deleted",
  "azure_sql_network_config_changed",
  "azure_sql_server_deleted",
  "azure_aks_cluster_config_changed",
  "azure_aks_cluster_deleted",
  "azure_config_activity",
];
// M78E — Google Cloud Admin Activity audit log signal types.
const GOOGLE_CLOUD_SIGNAL_TYPES = [
  "google_cloud_iam_policy_changed",
  "google_cloud_service_account_changed",
  "google_cloud_service_account_key_changed",
  "google_cloud_firewall_config_changed",
  "google_cloud_vpc_network_changed",
  "google_cloud_storage_bucket_changed",
  "google_cloud_sql_instance_changed",
  "google_cloud_run_service_changed",
  "google_cloud_gke_cluster_changed",
  "google_cloud_secret_config_changed",
  "google_cloud_config_activity",
];
// M79E — Twilio Monitor activity signal types.
const TWILIO_SIGNAL_TYPES = [
  "twilio_phone_number_config_changed",
  "twilio_messaging_service_config_changed",
  "twilio_messaging_sender_pool_changed",
  "twilio_verify_service_config_changed",
  "twilio_api_key_config_changed",
  "twilio_account_config_changed",
  "twilio_config_activity",
];
// M82E — Datadog configuration activity signal types.
const DATADOG_SIGNAL_TYPES = [
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
];
// M83E — Clerk configuration-state activity signals.
const CLERK_SIGNAL_TYPES = [
  "clerk_instance_settings_config_changed",
  "clerk_application_config_changed",
  "clerk_domain_config_changed",
  "clerk_redirect_url_config_changed",
  "clerk_jwt_template_config_changed",
  "clerk_webhook_endpoint_config_changed",
  "clerk_email_sms_settings_config_changed",
  "clerk_auth_strategy_config_changed",
  "clerk_organization_settings_config_changed",
  "clerk_session_policy_config_changed",
  "clerk_config_activity",
];
// M84E — PagerDuty configuration-state activity signals.
const PAGERDUTY_SIGNAL_TYPES = [
  "pagerduty_service_config_changed",
  "pagerduty_escalation_policy_config_changed",
  "pagerduty_schedule_config_changed",
  "pagerduty_service_integration_config_changed",
  "pagerduty_webhook_subscription_config_changed",
  "pagerduty_event_orchestration_config_changed",
  "pagerduty_business_service_config_changed",
  "pagerduty_response_play_config_changed",
  "pagerduty_config_activity",
];
// M85E — Linear configuration activity signal types.
const LINEAR_SIGNAL_TYPES = [
  "linear_workspace_config_changed",
  "linear_team_config_changed",
  "linear_project_config_changed",
  "linear_workflow_state_config_changed",
  "linear_label_config_changed",
  "linear_webhook_config_changed",
  "linear_view_config_changed",
  "linear_cycle_config_changed",
  "linear_integration_config_changed",
  "linear_config_activity",
];
// M87E — GitLab configuration activity signal types.
const GITLAB_SIGNAL_TYPES = [
  "gitlab_project_visibility_signal",
  "gitlab_project_public_feature_signal",
  "gitlab_group_visibility_signal",
  "gitlab_force_push_enabled_signal",
  "gitlab_branch_protection_weakened",
  "gitlab_webhook_secret_removed_signal",
  "gitlab_webhook_ssl_disabled_signal",
  "gitlab_webhook_http_scheme_signal",
  "gitlab_webhook_broad_event_scope_signal",
  "gitlab_ci_unprotected_unmasked_variables_signal",
  "gitlab_ci_variable_posture_signal",
  "gitlab_deploy_key_write_enabled_signal",
  "gitlab_deploy_key_posture_signal",
  "gitlab_shared_runner_enabled_signal",
  "gitlab_runner_posture_signal",
  "gitlab_merge_request_approval_weakened",
  "gitlab_configuration_activity_signal",
];
// M86E — Jira configuration activity signal types.
const JIRA_SIGNAL_TYPES = [
  "jira_site_config_changed",
  "jira_project_config_changed",
  "jira_board_config_changed",
  "jira_workflow_config_changed",
  "jira_workflow_scheme_config_changed",
  "jira_permission_scheme_config_changed",
  "jira_notification_scheme_config_changed",
  "jira_issue_type_scheme_config_changed",
  "jira_field_configuration_scheme_config_changed",
  "jira_screen_scheme_config_changed",
  "jira_webhook_config_changed",
  "jira_automation_rule_config_changed",
  "jira_config_activity",
];
// M81E — Auth0 configuration activity signal types.
const AUTH0_SIGNAL_TYPES = [
  "auth0_tenant_config_changed",
  "auth0_application_config_changed",
  "auth0_connection_config_changed",
  "auth0_resource_server_config_changed",
  "auth0_rule_config_changed",
  "auth0_action_config_changed",
  "auth0_mfa_factor_config_changed",
  "auth0_custom_domain_config_changed",
  "auth0_config_activity",
];

// M88E — Terraform Cloud configuration activity signal types.
const TERRAFORM_CLOUD_SIGNAL_TYPES = [
  "terraform_cloud_organization_access_posture_signal",
  "terraform_cloud_workspace_auto_apply_signal",
  "terraform_cloud_workspace_global_remote_state_signal",
  "terraform_cloud_workspace_execution_mode_signal",
  "terraform_cloud_workspace_vcs_posture_signal",
  "terraform_cloud_workspace_run_control_signal",
  "terraform_cloud_workspace_version_posture_signal",
  "terraform_cloud_variable_posture_signal",
  "terraform_cloud_variable_set_scope_signal",
  "terraform_cloud_policy_set_enforcement_signal",
  "terraform_cloud_policy_set_scope_signal",
  "terraform_cloud_notification_transport_signal",
  "terraform_cloud_notification_posture_signal",
  "terraform_cloud_run_trigger_signal",
  "terraform_cloud_team_access_posture_signal",
  "terraform_cloud_state_version_metadata_signal",
  "terraform_cloud_configuration_activity_signal",
];

const PROVIDER_LABEL: Record<Provider, string> = { github: "GitHub", aws: "AWS", cloudflare: "Cloudflare", vercel: "Vercel", supabase: "Supabase", firebase: "Firebase", stripe: "Stripe", shopify: "Shopify", azure: "Azure", google_cloud: "Google Cloud", twilio: "Twilio", sendgrid: "SendGrid", auth0: "Auth0", datadog: "Datadog", clerk: "Clerk", pagerduty: "PagerDuty", linear: "Linear", jira: "Jira", gitlab: "GitLab", terraform_cloud: "Terraform Cloud" };

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];
const STATUS_OPTIONS = ["open", "acknowledged", "dismissed", "resolved"];
// M80E — SendGrid configuration activity signal types.
const SENDGRID_SIGNAL_TYPES = [
  "sendgrid_account_config_changed",
  "sendgrid_api_key_config_changed",
  "sendgrid_sender_identity_config_changed",
  "sendgrid_domain_authentication_config_changed",
  "sendgrid_mail_settings_config_changed",
  "sendgrid_tracking_settings_config_changed",
  "sendgrid_event_webhook_config_changed",
  "sendgrid_inbound_parse_config_changed",
  "sendgrid_suppression_settings_config_changed",
  "sendgrid_config_activity",
];
const GITHUB_SIGNAL_TYPES = [
  "branch_protection_change",
  "deploy_key_added",
  "webhook_change",
  "collaborator_change",
  "app_install",
  "app_permissions_change",
  "ruleset_change",
  "secret_scanning_alert",
  "github_secret_scanning_alert",
  "github_code_scanning_alert",
  "github_dependabot_alert",
];
const AWS_SIGNAL_TYPES = [
  "aws_guardduty",
  "aws_access_analyzer",
  "aws_security_hub_finding",
  "iam_behavior_timeline",
  "aws_iam_privilege_chain",
  "s3_object_access_spike",
  "vpc_flow_activity_signal",
];

const HIGH_SEVERITIES = new Set(["critical", "high"]);

export default function IncidentSignalsPage() {
  const { getToken } = useAuth();
  const { isAdmin, roleLoaded } = useWorkspace();

  const [provider, setProvider] = useState<Provider>("github");
  const [signals, setSignals] = useState<SecurityIncidentSignal[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [signalType, setSignalType] = useState("");

  // Generate action
  const [generating, setGenerating] = useState(false);
  const [genResult, setGenResult] = useState<SecuritySignalGenerateResponse | null>(null);
  const [genError, setGenError] = useState<string | null>(null);
  const [behaviorNote, setBehaviorNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const res = await getSecurityIncidentSignals(
        {
          provider,
          severity: severity || undefined,
          status: status || undefined,
          signal_type: signalType || undefined,
          page_size: 100,
        },
        token,
      );
      setSignals(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch {
      setError("Could not load incident signals. Please try again.");
    } finally {
      setLoading(false);
    }
  }, [getToken, provider, severity, status, signalType]);

  useEffect(() => {
    void load();
  }, [load]);

  const onProviderChange = useCallback((p: string) => {
    setProvider(p as Provider);
    setSignalType("");
    setGenResult(null);
    setGenError(null);
    setBehaviorNote(null);
  }, []);

  const onGenerate = useCallback(async () => {
    setGenerating(true);
    setGenError(null);
    setGenResult(null);
    try {
      const token = await getToken();
      let res;
      if (provider === "vercel") {
        const v = await generateVercelActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "supabase") {
        const v = await generateSupabaseActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "firebase") {
        const v = await generateFirebaseActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "stripe") {
        const v = await generateStripeActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "shopify") {
        const v = await generateShopifyActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "azure") {
        const v = await generateAzureActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "google_cloud") {
        const v = await generateGoogleCloudActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "twilio") {
        const v = await generateTwilioActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "sendgrid") {
        const v = await generateSendGridActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "auth0") {
        const v = await generateAuth0ActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "datadog") {
        const v = await generateDatadogActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "clerk") {
        const v = await generateClerkActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "pagerduty") {
        const v = await generatePagerDutyActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "linear") {
        const r = await generateLinearActivitySignals(token);
        res = {
          provider: r.provider,
          activity_events_scanned: r.events_scanned,
          signals_created: r.signals_created,
          signals_skipped: r.signals_skipped,
        };
      } else if (provider === "jira") {
        const v = await generateJiraActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "gitlab") {
        const v = await generateGitlabActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else if (provider === "terraform_cloud") {
        const v = await generateTerraformCloudActivitySignals(token);
        res = {
          provider: v.provider,
          activity_events_scanned: v.events_scanned,
          signals_created: v.signals_created,
          signals_skipped: v.signals_skipped,
        };
      } else {
        res =
          provider === "cloudflare"
            ? await generateCloudflareSignals(token)
            : provider === "aws"
              ? await generateAwsIncidentSignals(token)
              : await generateSecurityIncidentSignals({ provider: "github" }, token);
      }
      setGenResult(res);
      await load();
    } catch {
      setGenError("Could not generate signals. Please try again.");
    } finally {
      setGenerating(false);
    }
  }, [getToken, provider, load]);

  const onGenerateBehavior = useCallback(async () => {
    setGenerating(true);
    setGenError(null);
    setBehaviorNote(null);
    try {
      const token = await getToken();
      const res = await generateAwsIamBehaviorSignals(token);
      setBehaviorNote(
        `IAM behavior: scanned ${res.events_scanned} CloudTrail events across ${res.principals_scanned} principal(s) · ${res.signals_created} signal(s) created · ${res.signals_skipped} skipped.`,
      );
      await load();
    } catch {
      setGenError("Could not generate IAM behavior signals. Please try again.");
    } finally {
      setGenerating(false);
    }
  }, [getToken, load]);

  const onGenerateIamChain = useCallback(async () => {
    setGenerating(true);
    setGenError(null);
    setBehaviorNote(null);
    try {
      const token = await getToken();
      const res = await generateAwsIamChainSignals(token);
      setBehaviorNote(
        `IAM chain: scanned ${res.events_scanned} CloudTrail events across ${res.chains_scanned} target entity chain(s) · ${res.signals_created} signal(s) created · ${res.signals_skipped} skipped.`,
      );
      await load();
    } catch {
      setGenError("Could not generate AWS IAM chain signals. Please try again.");
    } finally {
      setGenerating(false);
    }
  }, [getToken, load]);

  const onGenerateSecurityHub = useCallback(async () => {
    setGenerating(true);
    setGenError(null);
    setBehaviorNote(null);
    try {
      const token = await getToken();
      const res = await generateAwsSecurityHubSignals(token);
      setBehaviorNote(
        `Security Hub: scanned ${res.activity_events_scanned} finding event(s) · ${res.signals_created} signal(s) created · ${res.signals_skipped} skipped.`,
      );
      await load();
    } catch {
      setGenError("Could not generate Security Hub signals. Please try again.");
    } finally {
      setGenerating(false);
    }
  }, [getToken, load]);

  const onGenerateS3Access = useCallback(async () => {
    setGenerating(true);
    setGenError(null);
    setBehaviorNote(null);
    try {
      const token = await getToken();
      const res = await generateAwsS3AccessSignals(token);
      setBehaviorNote(
        `S3 access: scanned ${res.events_scanned} data event(s) across ${res.buckets_scanned} bucket(s) / ${res.actors_scanned} principal(s) · ${res.signals_created} signal(s) created · ${res.signals_skipped} skipped.`,
      );
      await load();
    } catch {
      setGenError("Could not generate S3 access signals. Please try again.");
    } finally {
      setGenerating(false);
    }
  }, [getToken, load]);

  const onGenerateVpcFlow = useCallback(async () => {
    setGenerating(true);
    setGenError(null);
    setBehaviorNote(null);
    try {
      const token = await getToken();
      const res = await generateAwsVpcFlowSignals(token);
      setBehaviorNote(
        `VPC flow: scanned ${res.events_scanned} flow event(s) across ${res.interfaces_scanned} interface(s) · ${res.signals_created} signal(s) created · ${res.signals_skipped} skipped.`,
      );
      await load();
    } catch {
      setGenError("Could not generate VPC flow signals. Please try again.");
    } finally {
      setGenerating(false);
    }
  }, [getToken, load]);

  const onGenerateWaf = useCallback(async () => {
    setGenerating(true);
    setGenError(null);
    setBehaviorNote(null);
    try {
      const token = await getToken();
      const res = await generateCloudflareWafSignals(token);
      setBehaviorNote(
        `Cloudflare WAF: scanned ${res.events_scanned} WAF/security event(s) across ${res.groups_scanned} group(s) · ${res.signals_created} signal(s) created · ${res.signals_skipped} skipped.`,
      );
      await load();
    } catch {
      setGenError("Could not generate Cloudflare WAF signals. Please try again.");
    } finally {
      setGenerating(false);
    }
  }, [getToken, load]);

  const onGenerateSecretScanning = useCallback(async () => {
    setGenerating(true);
    setGenError(null);
    setBehaviorNote(null);
    try {
      const token = await getToken();
      const res = await generateGitHubSecretScanningSignals(token);
      setBehaviorNote(
        `GitHub secret scanning: scanned ${res.events_scanned} alert event(s) across ${res.groups_scanned} alert group(s) · ${res.signals_created} signal(s) created · ${res.signals_skipped} skipped.`,
      );
      await load();
    } catch {
      setGenError("Could not generate GitHub secret scanning signals. Please try again.");
    } finally {
      setGenerating(false);
    }
  }, [getToken, load]);

  const onGenerateCodeScanning = useCallback(async () => {
    setGenerating(true);
    setGenError(null);
    setBehaviorNote(null);
    try {
      const token = await getToken();
      const res = await generateGitHubCodeScanningSignals(token);
      setBehaviorNote(
        `GitHub code scanning: scanned ${res.events_scanned} alert event(s) across ${res.groups_scanned} alert group(s) · ${res.signals_created} signal(s) created · ${res.signals_skipped} skipped.`,
      );
      await load();
    } catch {
      setGenError("Could not generate GitHub code scanning signals. Please try again.");
    } finally {
      setGenerating(false);
    }
  }, [getToken, load]);

  const onGenerateDependabot = useCallback(async () => {
    setGenerating(true);
    setGenError(null);
    setBehaviorNote(null);
    try {
      const token = await getToken();
      const res = await generateGitHubDependabotSignals(token);
      setBehaviorNote(
        `GitHub Dependabot: scanned ${res.events_scanned} alert event(s) across ${res.groups_scanned} alert group(s) · ${res.signals_created} signal(s) created · ${res.signals_skipped} skipped.`,
      );
      await load();
    } catch {
      setGenError("Could not generate GitHub Dependabot signals. Please try again.");
    } finally {
      setGenerating(false);
    }
  }, [getToken, load]);

  const metrics = useMemo(() => {
    const open = signals.filter((s) => s.status === "open").length;
    const high = signals.filter((s) => HIGH_SEVERITIES.has(s.severity)).length;
    const github = signals.filter((s) => s.provider === "github").length;
    const latest = signals.reduce<string | null>((acc, s) => {
      const t = s.last_seen_at ?? s.first_seen_at ?? s.created_at;
      if (!t) return acc;
      if (!acc || Date.parse(t) > Date.parse(acc)) return t;
      return acc;
    }, null);
    return { open, high, github, latest };
  }, [signals]);

  return (
    <div>
      <Hero />

      {/* Generate (admin/owner) */}
      <GenerateBar
        provider={provider}
        isAdmin={isAdmin}
        roleLoaded={roleLoaded}
        generating={generating}
        genResult={genResult}
        genError={genError}
        onGenerate={onGenerate}
        behaviorNote={behaviorNote}
        onGenerateBehavior={onGenerateBehavior}
        onGenerateSecurityHub={onGenerateSecurityHub}
        onGenerateS3Access={onGenerateS3Access}
        onGenerateVpcFlow={onGenerateVpcFlow}
        onGenerateWaf={onGenerateWaf}
        onGenerateIamChain={onGenerateIamChain}
        onGenerateSecretScanning={onGenerateSecretScanning}
        onGenerateCodeScanning={onGenerateCodeScanning}
        onGenerateDependabot={onGenerateDependabot}
      />

      {/* Summary cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
          gap: "14px",
          marginBottom: "24px",
        }}
      >
        <Metric label="Open signals" value={metrics.open} accent="#f5632a" />
        <Metric label="High severity" value={metrics.high} accent="#e84040" />
        <Metric label={`${PROVIDER_LABEL[provider]} signals`} value={signals.length} accent="#6b9cf8" />
        <Metric
          label="Latest signal"
          text={metrics.latest ? formatRelativeTime(metrics.latest) : "—"}
          accent="#3ccf7e"
        />
      </div>

      {/* Filters */}
      <div
        style={{
          display: "flex",
          gap: "10px",
          flexWrap: "wrap",
          alignItems: "center",
          marginBottom: "18px",
        }}
      >
        <Select label="Provider" value={provider} onChange={onProviderChange} options={["github", "aws", "cloudflare", "vercel", "supabase", "firebase", "stripe", "shopify", "azure", "google_cloud", "twilio", "sendgrid", "auth0", "datadog", "clerk", "pagerduty", "linear", "jira", "gitlab", "terraform_cloud"]} allowAll={false} />
        <Select label="Severity" value={severity} onChange={setSeverity} options={SEVERITY_OPTIONS} />
        <Select label="Status" value={status} onChange={setStatus} options={STATUS_OPTIONS} />
        <Select
          label="Signal type"
          value={signalType}
          onChange={setSignalType}
          options={provider === "aws" ? AWS_SIGNAL_TYPES : provider === "cloudflare" ? CLOUDFLARE_SIGNAL_TYPES : provider === "vercel" ? VERCEL_SIGNAL_TYPES : provider === "supabase" ? SUPABASE_SIGNAL_TYPES : provider === "firebase" ? FIREBASE_SIGNAL_TYPES : provider === "stripe" ? STRIPE_SIGNAL_TYPES : provider === "shopify" ? SHOPIFY_SIGNAL_TYPES : provider === "azure" ? AZURE_SIGNAL_TYPES : provider === "google_cloud" ? GOOGLE_CLOUD_SIGNAL_TYPES : provider === "twilio" ? TWILIO_SIGNAL_TYPES : provider === "sendgrid" ? SENDGRID_SIGNAL_TYPES : provider === "auth0" ? AUTH0_SIGNAL_TYPES : provider === "datadog" ? DATADOG_SIGNAL_TYPES : provider === "clerk" ? CLERK_SIGNAL_TYPES : provider === "pagerduty" ? PAGERDUTY_SIGNAL_TYPES : provider === "linear" ? LINEAR_SIGNAL_TYPES : provider === "jira" ? JIRA_SIGNAL_TYPES : provider === "gitlab" ? GITLAB_SIGNAL_TYPES : provider === "terraform_cloud" ? TERRAFORM_CLOUD_SIGNAL_TYPES : GITHUB_SIGNAL_TYPES}
        />
      </div>

      {loading ? (
        <LoadingState />
      ) : error ? (
        <ErrorState message={error} />
      ) : signals.length === 0 ? (
        <EmptyState provider={provider} isAdmin={isAdmin} />
      ) : (
        <>
          <SectionLabel>
            {total} signal{total === 1 ? "" : "s"}
          </SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {signals.map((s) => (
              <SignalRow key={s.id} signal={s} />
            ))}
          </div>
        </>
      )}

      <p style={{ margin: "26px 0 0", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
        GitHub signals come from normalized audit activity; AWS signals come from
        provider-reported GuardDuty / Access Analyzer findings; Cloudflare signals
        come from audit activity and WAF/security events. ConfigTrace does not
        automatically confirm breaches, attacker presence, or unauthorized access.
        Signals can be correlated with Configuration Risks and grouped into
        human-reviewed cases.
      </p>
    </div>
  );
}

// ── Hero ────────────────────────────────────────────────────────────────────

function Hero() {
  return (
    <>
      <PageHeader
        title="Incident Signals"
        description="Review security signals from GitHub audit activity, AWS provider security findings, and Cloudflare audit/WAF activity."
      />
      <div
        className="bg-surface1 border border-border"
        style={{ borderRadius: "12px", padding: "16px 18px", marginBottom: "20px" }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
            GitHub + AWS + Cloudflare beta
          </span>
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
            Beta
          </span>
        </div>
        <p style={{ margin: 0, fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
          Signals are review cues from audit activity and provider-reported AWS
          findings. ConfigTrace does not automatically confirm breaches, attacker
          presence, or unauthorized access.
        </p>
      </div>
    </>
  );
}

// ── Generate bar ──────────────────────────────────────────────────────────────

function GenerateBar({
  provider,
  isAdmin,
  roleLoaded,
  generating,
  genResult,
  genError,
  onGenerate,
  behaviorNote,
  onGenerateBehavior,
  onGenerateSecurityHub,
  onGenerateS3Access,
  onGenerateVpcFlow,
  onGenerateWaf,
  onGenerateIamChain,
  onGenerateSecretScanning,
  onGenerateCodeScanning,
  onGenerateDependabot,
}: {
  provider: Provider;
  isAdmin: boolean;
  roleLoaded: boolean;
  generating: boolean;
  genResult: SecuritySignalGenerateResponse | null;
  genError: string | null;
  onGenerate: () => void;
  behaviorNote: string | null;
  onGenerateBehavior: () => void;
  onGenerateSecurityHub: () => void;
  onGenerateS3Access: () => void;
  onGenerateVpcFlow: () => void;
  onGenerateWaf: () => void;
  onGenerateIamChain: () => void;
  onGenerateSecretScanning: () => void;
  onGenerateCodeScanning: () => void;
  onGenerateDependabot: () => void;
}) {
  const isAws = provider === "aws";
  const isCloudflare = provider === "cloudflare";
  const isGithub = provider === "github";
  const isVercel = provider === "vercel";
  const isSupabase = provider === "supabase";
  const isFirebase = provider === "firebase";
  const isStripe = provider === "stripe";
  const isShopify = provider === "shopify";
  const isAzure = provider === "azure";
  const isGoogleCloud = provider === "google_cloud";
  const isTwilio = provider === "twilio";
  const isSendGrid = provider === "sendgrid";
  const isAuth0 = provider === "auth0";
  const isDatadog = provider === "datadog";
  const isClerk = provider === "clerk";
  const isPagerDuty = provider === "pagerduty";
  const isLinear = provider === "linear";
  const isJira = provider === "jira";
  const isGitlab = provider === "gitlab";
  const label = isCloudflare ? "Generate Cloudflare signals"
    : isAws ? "Generate AWS signals"
    : isVercel ? "Generate Vercel activity signals"
    : isSupabase ? "Generate Supabase activity signals"
    : isFirebase ? "Generate Firebase activity signals"
    : isStripe ? "Generate Stripe activity signals"
    : isShopify ? "Generate Shopify activity signals"
    : isAzure ? "Generate Azure signals"
    : isGoogleCloud ? "Generate Google Cloud signals"
    : isTwilio ? "Generate Twilio signals"
    : isSendGrid ? "Generate SendGrid signals"
    : isAuth0 ? "Generate Auth0 signals"
    : isDatadog ? "Generate Datadog signals"
    : isClerk ? "Generate Clerk signals"
    : isPagerDuty ? "Generate PagerDuty signals"
    : isLinear ? "Generate Linear signals"
    : isJira ? "Generate Jira signals"
    : isGitlab ? "Generate GitLab signals"
    : "Generate signals";
  const desc = isCloudflare
    ? "Generate review signals from Cloudflare audit activity (DNS, WAF/firewall, SSL/TLS, Access, zone settings, API-token activity)."
    : isAws
      ? "Generate Incident Signals from provider-reported AWS security findings (GuardDuty / Access Analyzer / Security Hub), or review signals from CloudTrail IAM/KMS/S3 management activity, S3 object-level data events, or VPC Flow Log network activity."
      : isVercel
        ? "Generate review signals from Vercel activity evidence (project, domain, environment-variable, deploy-hook, and deployment changes)."
        : isSupabase
          ? "Generate review signals from Supabase activity evidence (table/RLS, access policy, storage bucket, Edge Function, auth configuration, and project changes)."
          : isFirebase
            ? "Generate review signals from Firebase activity evidence (Firestore/Realtime Database/Storage rules, auth configuration, Cloud Function, Hosting, and project/app changes)."
            : isStripe
              ? "Generate review signals from Stripe configuration activity evidence (webhook endpoint, payment link, customer portal, account, and capability changes)."
              : isShopify
                ? "Generate review signals from Shopify configuration activity evidence."
                : isAzure
                  ? "Generate review-safe signals from Azure Activity Log evidence for NSG, Storage, Key Vault, role assignment, App Service, SQL, and AKS configuration changes. Sync Azure activity first, then generate signals."
                  : isGoogleCloud
                    ? "Generate review-safe signals from Google Cloud Audit Log evidence for IAM, firewall rules, Storage, Cloud SQL, Cloud Run, GKE, service accounts, and Secret Manager configuration changes. Sync Google Cloud activity first, then generate signals."
                    : isTwilio
                      ? "Generate review signals from safe Twilio configuration activity. Stores resource identifiers and activity summaries only — never message bodies, call logs, recordings, or full phone numbers."
                      : isSendGrid
                        ? "Generate review signals from safe SendGrid configuration activity. ConfigTrace stores resource identifiers, configuration status, webhook-presence metadata, and activity summaries only — never email bodies, subject lines, recipient emails, mail event payloads, raw webhook URLs, or API keys."
                        : isAuth0
                          ? "Generate review signals from safe Auth0 configuration activity. ConfigTrace stores resource identifiers, OAuth/application posture, tenant settings, and activity summaries only — never user emails, login history, IP addresses, sessions, tokens, callback URLs, raw Auth0 logs, or client secrets."
                          : isDatadog
                            ? "Generate review signals from safe Datadog configuration activity. ConfigTrace stores monitor, SLO, dashboard, webhook, key, role, team, and cloud-integration posture summaries only — never API keys, application keys, raw monitor queries, raw monitor messages, webhook URLs, headers, payloads, logs, traces, metric values, incident text, emails, destination handles, raw audit payloads, or PII."
                            : isClerk
                              ? "Generate review signals from safe Clerk configuration activity. ConfigTrace stores instance, application, domain, redirect URL, JWT template, webhook, email/SMS, auth strategy, organization, and session-policy posture summaries only — never Clerk secret keys, session tokens, JWTs, OAuth tokens, webhook secrets, raw redirect URLs, raw callback URLs, raw webhook URLs, user emails, user IDs, phone numbers, names, session history, login history, IP addresses, user agents, raw audit payloads, customer data, or PII."
                              : isPagerDuty
                                ? "Generate review signals from safe PagerDuty configuration activity derived from service, escalation policy, schedule, integration, webhook, orchestration, business service, and response play configuration state. ConfigTrace stores only opaque IDs, booleans, counts, and categories — never API tokens, routing keys, integration keys, webhook secrets, raw URLs, user contact data, incident payloads, alert payloads, IP addresses, user agents, or PII."
                                : isLinear
                                  ? "Generate review signals from safe Linear configuration activity derived from workspace, team, project, workflow state, label, webhook, view, cycle, and integration configuration state. ConfigTrace stores only opaque IDs, booleans, counts, and categories — never API keys, OAuth tokens, webhook secrets, raw URLs, issue titles, issue descriptions, comment bodies, user identities, or PII."
                                  : isJira
                                    ? "Generate review-safe Jira signals from existing Jira configuration activity. ConfigTrace stores only safe counts, categories, booleans, and opaque resource identifiers, not Jira issue content, comments, attachments, user identities, tokens, raw URLs, JQL text, audit payloads, IP addresses, user agents, or PII."
                                    : isGitlab
                                      ? "Generate GitLab activity signals from safe GitLab configuration activity events. No GitLab issue content, merge request titles, commit messages, branch names, CI variable names/values, webhook URLs, tokens, user identities, logs, artifacts, or PII are stored."
                                      : "Scans recent GitHub audit activity events and creates review signals.";
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
        <div style={{ fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>{label}</div>
        <div style={{ fontSize: "12px", color: "#8b90a0", marginTop: "2px" }}>
          {desc}
          {!isAdmin && roleLoaded && " Only workspace admins can generate signals."}
        </div>
        {genResult && (
          <div style={{ fontSize: "12px", color: "#3ccf7e", marginTop: "6px" }}>
            Scanned {genResult.activity_events_scanned} activity events ·{" "}
            {genResult.signals_created} created · {genResult.signals_skipped} skipped.
          </div>
        )}
        {behaviorNote && (
          <div style={{ fontSize: "12px", color: "#3ccf7e", marginTop: "6px" }}>{behaviorNote}</div>
        )}
        {genError && (
          <div style={{ fontSize: "12px", color: "#e84040", marginTop: "6px" }}>{genError}</div>
        )}
      </div>
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
        <button
          onClick={onGenerate}
          disabled={!isAdmin || generating}
          title={!isAdmin ? "Only workspace admins can generate signals." : undefined}
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
          {generating ? "Generating…" : label}
        </button>
        {isAws && (
          <button
            onClick={onGenerateBehavior}
            disabled={!isAdmin || generating}
            title={!isAdmin ? "Only workspace admins can generate signals." : undefined}
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || generating ? "not-allowed" : "pointer",
              opacity: generating ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Generate IAM behavior signals
          </button>
        )}
        {isAws && (
          <button
            onClick={onGenerateIamChain}
            disabled={!isAdmin || generating}
            title={!isAdmin ? "Only workspace admins can generate signals." : undefined}
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || generating ? "not-allowed" : "pointer",
              opacity: generating ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Generate IAM chain signals
          </button>
        )}
        {isAws && (
          <button
            onClick={onGenerateSecurityHub}
            disabled={!isAdmin || generating}
            title={!isAdmin ? "Only workspace admins can generate signals." : undefined}
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || generating ? "not-allowed" : "pointer",
              opacity: generating ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Generate Security Hub signals
          </button>
        )}
        {isAws && (
          <button
            onClick={onGenerateS3Access}
            disabled={!isAdmin || generating}
            title={!isAdmin ? "Only workspace admins can generate signals." : undefined}
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || generating ? "not-allowed" : "pointer",
              opacity: generating ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Generate S3 access signals
          </button>
        )}
        {isAws && (
          <button
            onClick={onGenerateVpcFlow}
            disabled={!isAdmin || generating}
            title={!isAdmin ? "Only workspace admins can generate signals." : undefined}
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || generating ? "not-allowed" : "pointer",
              opacity: generating ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Generate VPC flow signals
          </button>
        )}
        {isCloudflare && (
          <button
            onClick={onGenerateWaf}
            disabled={!isAdmin || generating}
            title={!isAdmin ? "Only workspace admins can generate signals." : undefined}
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || generating ? "not-allowed" : "pointer",
              opacity: generating ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Generate Cloudflare WAF signals
          </button>
        )}
        {isGithub && (
          <button
            onClick={onGenerateSecretScanning}
            disabled={!isAdmin || generating}
            title={
              !isAdmin
                ? "Only workspace admins can generate signals."
                : "Generate review signals from GitHub secret-scanning alert evidence."
            }
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || generating ? "not-allowed" : "pointer",
              opacity: generating ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Generate GitHub secret scanning signals
          </button>
        )}
        {isGithub && (
          <button
            onClick={onGenerateCodeScanning}
            disabled={!isAdmin || generating}
            title={
              !isAdmin
                ? "Only workspace admins can generate signals."
                : "Generate review signals from GitHub code-scanning alert evidence."
            }
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || generating ? "not-allowed" : "pointer",
              opacity: generating ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Generate GitHub code scanning signals
          </button>
        )}
        {isGithub && (
          <button
            onClick={onGenerateDependabot}
            disabled={!isAdmin || generating}
            title={
              !isAdmin
                ? "Only workspace admins can generate signals."
                : "Generate review signals from GitHub Dependabot alert evidence."
            }
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || generating ? "not-allowed" : "pointer",
              opacity: generating ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Generate GitHub Dependabot signals
          </button>
        )}
      </div>
    </div>
  );
}

// ── Signal row ────────────────────────────────────────────────────────────────

function SignalRow({ signal }: { signal: SecurityIncidentSignal }) {
  const when = signal.last_seen_at ?? signal.first_seen_at ?? signal.created_at;
  return (
    <Link
      href={`/security/signals/${signal.id}`}
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", textDecoration: "none", display: "block", padding: "14px 16px" }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
        <SeverityBadge severity={signal.severity} />
        <span style={{ fontSize: "14px", fontWeight: 600, color: "#e8eaf0", flex: 1, minWidth: 0 }}>
          {signal.title}
        </span>
        <span style={{ fontSize: "12px", color: "#6b9cf8" }}>View signal →</span>
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          flexWrap: "wrap",
          marginTop: "9px",
        }}
      >
        <SignalStatusBadge status={signal.status} />
        <ConfidenceBadge confidence={signal.confidence} />
        <Chip>evidence: {signal.evidence_level}</Chip>
        <span style={{ color: "#3a3d48" }}>·</span>
        <span style={{ fontSize: "12px", color: "#8b90a0" }}>{signal.provider}</span>
        <span style={{ color: "#3a3d48" }}>·</span>
        <span style={{ fontSize: "12px", color: "#8b90a0" }}>{signal.signal_type}</span>
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

// ── Small UI helpers ──────────────────────────────────────────────────────────

function Metric({
  label,
  value,
  text,
  accent,
}: {
  label: string;
  value?: number;
  text?: string;
  accent: string;
}) {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px" }}>
      <div style={{ fontSize: "12px", color: "#8b90a0", fontWeight: 500 }}>{label}</div>
      <div
        style={{
          fontSize: text ? "16px" : "28px",
          fontWeight: 700,
          color: accent,
          marginTop: "8px",
          letterSpacing: "-0.02em",
        }}
      >
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
  allowAll = true,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: string[];
  allowAll?: boolean;
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
        {allowAll && <option value="">All</option>}
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

function Chip({ children }: { children: React.ReactNode }) {
  return (
    <span
      style={{
        fontSize: "11px",
        fontWeight: 600,
        color: "#8b90a0",
        background: "rgba(139,144,160,0.12)",
        borderRadius: "6px",
        padding: "2px 8px",
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

function EmptyState({ provider, isAdmin }: { provider: Provider; isAdmin: boolean }) {
  const body =
    provider === "aws"
      ? "Sync AWS security alerts first, then generate AWS Incident Signals." +
        (isAdmin
          ? " Use “Generate AWS signals” above once AWS alerts have been ingested."
          : " A workspace admin can sync AWS alerts and generate AWS signals.")
      : provider === "cloudflare"
        ? "Sync Cloudflare audit and WAF/security events first, then generate Cloudflare signals." +
          (isAdmin
            ? " Use “Generate Cloudflare signals” / “Generate Cloudflare WAF signals” above once events have been ingested."
            : " A workspace admin can sync Cloudflare events and generate Cloudflare signals.")
        : provider === "vercel"
          ? "Sync Vercel activity first, then generate Vercel activity signals." +
            (isAdmin
              ? " Use “Generate Vercel activity signals” above once activity has been ingested."
              : " A workspace admin can sync Vercel activity and generate signals.")
          : provider === "supabase"
            ? "Sync Supabase activity first, then generate Supabase activity signals." +
              (isAdmin
                ? " Use “Generate Supabase activity signals” above once activity has been ingested."
                : " A workspace admin can sync Supabase activity and generate signals.")
          : provider === "firebase"
            ? "Sync Firebase activity first, then generate Firebase activity signals." +
              (isAdmin
                ? " Use “Generate Firebase activity signals” above once activity has been ingested."
                : " A workspace admin can sync Firebase activity and generate signals.")
          : provider === "stripe"
            ? "Sync Stripe activity first, then generate Stripe activity signals." +
              (isAdmin
                ? " Use “Generate Stripe activity signals” above once activity has been ingested."
                : " A workspace admin can sync Stripe activity and generate signals.")
          : provider === "shopify"
            ? "Sync Shopify activity first, then generate Shopify activity signals." +
              (isAdmin
                ? " Use \”Generate Shopify activity signals\” above once activity has been ingested."
                : " A workspace admin can sync Shopify activity and generate signals.")
          : provider === "azure"
            ? "Sync Azure activity, then generate Azure signals." +
              (isAdmin
                ? " Use \"Generate Azure signals\" above once Azure Activity Log events have been ingested via the Activity page. Each signal corresponds to a review-worthy configuration change on a specific Azure resource (NSG, Storage, Key Vault, role assignment, App Service, SQL, or AKS)."
                : " A workspace admin can sync Azure Activity Log events and generate Azure signals.")
          : provider === "google_cloud"
            ? "Sync Google Cloud activity first, then generate Google Cloud signals." +
              (isAdmin
                ? " Use \"Generate Google Cloud signals\" above once Google Cloud Audit Log events have been ingested via the Activity page. Signals correspond to review-worthy configuration changes on IAM, firewall rules, Storage, Cloud SQL, Cloud Run, GKE, and Secret Manager."
                : " A workspace admin can sync Google Cloud activity and generate Google Cloud signals.")
          : provider === "twilio"
            ? "Sync Twilio activity, then generate Twilio signals." +
              (isAdmin
                ? " Use \"Generate Twilio signals\" above once Twilio Monitor events have been ingested via the Activity page. Signals correspond to review-worthy configuration changes on phone numbers, messaging services, Verify services, and API keys."
                : " A workspace admin can sync Twilio activity and generate Twilio signals.")
          : provider === "sendgrid"
            ? "Sync SendGrid activity first, then generate SendGrid activity signals." +
              (isAdmin
                ? " Use \"Generate SendGrid signals\" above once SendGrid configuration-state events have been ingested via the Activity page. Signals summarize review-worthy configuration activity patterns across API keys, sender identities, domain authentication, mail/tracking settings, event webhook, inbound parse, and suppression settings. Email bodies, subject lines, recipient emails, mail event payloads, raw webhook URLs, and API key values are never stored."
                : " A workspace admin can sync SendGrid activity and generate SendGrid activity signals.")
          : provider === "auth0"
            ? "Sync Auth0 activity first, then generate Auth0 signals." +
              (isAdmin
                ? " Use \"Generate Auth0 signals\" above once Auth0 configuration-state events have been ingested via the Activity page. Signals summarize review-worthy configuration activity patterns across tenant settings, applications, connections, resource servers, rules, actions, MFA factors, and custom domains. User emails, login history, IP addresses, sessions, tokens, callback URLs, rule/action code, and raw Auth0 logs are never stored."
                : " A workspace admin can sync Auth0 activity and generate Auth0 signals.")
          : provider === "datadog"
            ? "Sync Datadog activity first, then generate Datadog signals." +
              (isAdmin
                ? " Use \"Generate Datadog signals\" above once Datadog configuration-state events have been ingested via the Activity page. Signals summarize review-worthy configuration activity patterns across monitors, SLOs, dashboards, webhook integrations, notification integrations, API keys, application keys, roles, teams, and cloud integrations. API key values, application key values, raw monitor queries, raw monitor messages, webhook URLs, notification handles, emails, user IDs, and raw audit payloads are never stored."
                : " A workspace admin can sync Datadog activity and generate Datadog signals.")
          : provider === "clerk"
            ? "Sync Clerk activity first, then generate Clerk signals." +
              (isAdmin
                ? " Use \"Generate Clerk signals\" above once Clerk configuration-state events have been ingested via the Activity page. Signals summarize review-worthy configuration activity patterns across instance settings, applications, domains, redirect URLs, JWT templates, webhooks, email/SMS settings, auth strategies, organization settings, and session policies. Secret keys, session tokens, JWTs, raw URLs, user emails, user IDs, and PII are never stored."
                : " A workspace admin can sync Clerk activity and generate Clerk signals.")
          : provider === "linear"
            ? "Sync Linear activity first, then generate Linear signals." +
              (isAdmin
                ? " Use \"Generate Linear signals\" above once Linear configuration-state events have been ingested via the Activity page. Signals summarize review-worthy configuration activity patterns across workspace, team, project, workflow state, label, webhook, view, cycle, and integration settings. API keys, OAuth tokens, webhook secrets, raw URLs, issue titles, issue descriptions, comment bodies, user identities, and PII are never stored."
                : " A workspace admin can sync Linear activity and generate Linear signals.")
          : provider === "jira"
            ? "Sync Jira activity first, then generate Jira signals." +
              (isAdmin
                ? " Use \"Generate Jira signals\" above once Jira configuration-state events have been ingested via the Activity page. Signals summarize review-worthy configuration activity patterns across site, project, board, workflow, workflow scheme, permission scheme, notification scheme, issue type scheme, field configuration scheme, screen scheme, webhook, and automation rule settings. ConfigTrace stores only safe counts, categories, booleans, and opaque resource identifiers, not Jira issue content, comments, attachments, user identities, tokens, raw URLs, JQL text, audit payloads, IP addresses, user agents, or PII."
                : " A workspace admin can sync Jira activity and generate Jira signals.")
          : provider === "gitlab"
            ? "Sync GitLab activity first, then generate GitLab signals." +
              (isAdmin
                ? " Use \"Generate GitLab signals\" above once GitLab configuration-state events have been ingested via the Activity page. Signals summarize review-worthy GitLab configuration activity across project visibility, group visibility, branch protection, webhook security, CI/CD variable posture, deploy key posture, runner posture, and merge request approval configuration. No GitLab issue content, merge request titles, commit messages, branch names, CI variable names/values, webhook URLs, tokens, user identities, logs, artifacts, or PII are stored."
                : " A workspace admin can sync GitLab activity and generate GitLab configuration signals.")
          : "Run GitHub activity sync first, then generate signals." +
            (isAdmin
              ? " Use “Generate signals” above once activity has been ingested."
              : " A workspace admin can ingest activity and generate signals.");
  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", padding: "32px 24px", textAlign: "center" }}
    >
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#e8eaf0" }}>
        No incident signals yet.
      </div>
      <p style={{ margin: "8px auto 0", maxWidth: "460px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
        {body}
      </p>
    </div>
  );
}
