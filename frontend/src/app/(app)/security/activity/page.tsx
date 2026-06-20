"use client";

/**
 * Activity Events (M66.5 + M67.2 AWS).
 *
 * Evidence viewer for normalized activity:
 *   • GitHub control-plane audit activity (M66.2)
 *   • AWS provider security findings — GuardDuty / Access Analyzer (M67.1)
 * — the events that power Incident Signals.
 *
 * CLAIM DISCIPLINE: these are activity / provider-reported findings. This page
 * must never state that a breach, attacker, compromise, or unauthorized access
 * has been confirmed.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import type { SecurityActivityEvent } from "@/types";
import {
  getSecurityActivityEvents,
  syncSecurityActivity,
  syncAwsSecurityAlerts,
  syncAwsCloudTrail,
  syncAwsSecurityHub,
  syncCloudflareActivity,
  syncCloudflareWafEvents,
  syncGitHubSecretScanning,
  syncGitHubCodeScanning,
  syncGitHubDependabot,
  syncVercelActivity,
  syncSupabaseActivity,
  syncFirebaseActivity,
  syncStripeActivity,
  syncShopifyActivity,
  syncAzureActivity,
  syncGoogleCloudActivity,
  syncTwilioActivity,
  syncSendGridActivity,
  syncAuth0Activity,
  syncDatadogActivity,
  syncClerkActivity,
  syncPagerDutyActivity,
  syncLinearActivity,
  syncJiraActivity,
} from "@/lib/api";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { formatRelativeTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";

type Provider = "github" | "aws" | "cloudflare" | "vercel" | "supabase" | "firebase" | "stripe" | "shopify" | "azure" | "google_cloud" | "twilio" | "sendgrid" | "auth0" | "datadog" | "clerk" | "pagerduty" | "linear" | "jira";

// M73B — Stripe Events API configuration-change events (strict allowlist).
const STRIPE_EVENT_TYPES = [
  "stripe.webhook_endpoint.created",
  "stripe.webhook_endpoint.updated",
  "stripe.webhook_endpoint.deleted",
  "stripe.payment_link.created",
  "stripe.payment_link.updated",
  "stripe.portal_config.created",
  "stripe.portal_config.updated",
  "stripe.account.updated",
  "stripe.capability.updated",
];

// M74B — Shopify Events API configuration-change events (strict subject-type allowlist).
const SHOPIFY_EVENT_TYPES = [
  "shopify.webhook.created",
  "shopify.webhook.updated",
  "shopify.webhook.deleted",
  "shopify.shop.updated",
  "shopify.domain.created",
  "shopify.domain.updated",
  "shopify.domain.deleted",
];

// M72B — Firebase / Google Cloud Audit Log control-plane change events.
const FIREBASE_EVENT_TYPES = [
  "firebase.project.updated",
  "firebase.project.event",
  "firebase.firestore_rules.updated",
  "firebase.database_rules.updated",
  "firebase.storage_rules.updated",
  "firebase.auth_config.updated",
  "firebase.hosting.updated",
  "firebase.function.created",
  "firebase.function.updated",
  "firebase.function.deleted",
  "firebase.app.updated",
];

// M71B — Supabase organization audit-log activity (control-plane config change events).
const SUPABASE_EVENT_TYPES = [
  "supabase.project.updated",
  "supabase.project.event",
  "supabase.table.updated",
  "supabase.rls.updated",
  "supabase.policy.created",
  "supabase.policy.updated",
  "supabase.policy.deleted",
  "supabase.storage_bucket.created",
  "supabase.storage_bucket.updated",
  "supabase.storage_bucket.deleted",
  "supabase.edge_function.created",
  "supabase.edge_function.updated",
  "supabase.edge_function.deleted",
  "supabase.auth_config.updated",
];

// M70B — Vercel team audit-log activity (control-plane change events).
const VERCEL_EVENT_TYPES = [
  "vercel.project.updated",
  "vercel.project.event",
  "vercel.domain.added",
  "vercel.domain.removed",
  "vercel.env_var.created",
  "vercel.env_var.updated",
  "vercel.env_var.deleted",
  "vercel.deploy_hook.created",
  "vercel.deploy_hook.deleted",
  "vercel.deployment.created",
  "vercel.deployment.promoted",
];

const CLOUDFLARE_EVENT_TYPES = [
  "cloudflare.dns_record.changed",
  "cloudflare.waf_rule.changed",
  "cloudflare.ssl_tls.changed",
  "cloudflare.access_policy.changed",
  "cloudflare.api_token.activity",
  "cloudflare.zone_setting.changed",
  "cloudflare.audit_event",
  // WAF / security events (M68.4)
  "cloudflare.waf_event.block",
  "cloudflare.waf_event.challenge",
  "cloudflare.waf_event.managed_challenge",
  "cloudflare.waf_event.js_challenge",
  "cloudflare.waf_event.log",
  "cloudflare.waf_event.skip",
  "cloudflare.waf_event.allow",
  "cloudflare.waf_event.event",
];

const GITHUB_EVENT_TYPES = [
  "github.branch_protection.disabled",
  "github.branch_protection.updated",
  "github.deploy_key.added",
  "github.webhook.created",
  "github.webhook.updated",
  "github.webhook.deleted",
  "github.collaborator.added",
  "github.app.installed",
  "github.app.permissions_changed",
  "github.ruleset.changed",
  "github.secret_scanning_alert.created",
  // M69.4A — GitHub secret-scanning alert evidence (provider-reported alerts).
  "github.secret_scanning.alert.open",
  "github.secret_scanning.alert.resolved",
  "github.secret_scanning.alert.revoked",
  "github.secret_scanning.alert.false_positive",
  "github.secret_scanning.alert.used_in_tests",
  // M69.4D — GitHub code-scanning (SAST) alert evidence (provider-reported alerts).
  "github.code_scanning.alert.open",
  "github.code_scanning.alert.fixed",
  "github.code_scanning.alert.dismissed",
  "github.code_scanning.alert.reopened",
  // M69.4G — GitHub Dependabot (vulnerable-dependency) alert evidence.
  "github.dependabot.alert.open",
  "github.dependabot.alert.fixed",
  "github.dependabot.alert.dismissed",
  "github.dependabot.alert.reopened",
  "github.dependabot.alert.auto_dismissed",
];
const AWS_EVENT_TYPES = [
  "aws.guardduty.unauthorized_access",
  "aws.guardduty.credential_access",
  "aws.guardduty.persistence",
  "aws.guardduty.discovery",
  "aws.guardduty.exfiltration",
  "aws.guardduty.privilege_escalation",
  "aws.guardduty.defense_evasion",
  "aws.guardduty.impact",
  "aws.guardduty.execution",
  "aws.guardduty.finding",
  "aws.access_analyzer.finding",
  // CloudTrail management events (M67.5)
  "aws.cloudtrail.console_login",
  "aws.iam.create_access_key",
  "aws.iam.delete_access_key",
  "aws.iam.attach_user_policy",
  "aws.iam.attach_role_policy",
  "aws.iam.create_user",
  "aws.iam.create_role",
  "aws.iam.update_assume_role_policy",
  "aws.s3.put_bucket_policy",
  "aws.s3.put_public_access_block",
  "aws.ec2.authorize_security_group_ingress",
  "aws.kms.disable_key",
  "aws.kms.schedule_key_deletion",
  "aws.cloudtrail.event",
  // Security Hub findings (M67.7)
  "aws.security_hub.iam_finding",
  "aws.security_hub.s3_finding",
  "aws.security_hub.ec2_finding",
  "aws.security_hub.kms_finding",
  "aws.security_hub.guardduty_finding",
  "aws.security_hub.inspector_finding",
  "aws.security_hub.macie_finding",
  "aws.security_hub.finding",
  // S3 object-level data events (M67.8)
  "aws.s3.data.get_object",
  "aws.s3.data.put_object",
  "aws.s3.data.delete_object",
  "aws.s3.data.copy_object",
  "aws.s3.data.list_bucket",
  "aws.s3.data.head_object",
  "aws.s3.data.put_object_acl",
  "aws.s3.data.event",
  // VPC Flow Logs (M67.10)
  "aws.vpc.flow.accept",
  "aws.vpc.flow.reject",
  "aws.vpc.flow.event",
];
// M77D — Azure Activity Log control-plane management events.
const AZURE_EVENT_TYPES = [
  "azure.nsg.updated",
  "azure.nsg.deleted",
  "azure.nsg_rule.updated",
  "azure.nsg_rule.deleted",
  "azure.storage_account.updated",
  "azure.storage_account.deleted",
  "azure.key_vault.updated",
  "azure.key_vault.deleted",
  "azure.role_assignment.created",
  "azure.role_assignment.deleted",
  "azure.app_service.updated",
  "azure.app_service.deleted",
  "azure.app_service_config.updated",
  "azure.sql_server.updated",
  "azure.sql_server.deleted",
  "azure.sql_firewall_rule.updated",
  "azure.sql_firewall_rule.deleted",
  "azure.aks_cluster.updated",
  "azure.aks_cluster.deleted",
  "azure.config.event",
];

// M78D — Google Cloud Admin Activity audit log control-plane events.
const GOOGLE_CLOUD_EVENT_TYPES = [
  "google_cloud.iam_policy.updated",
  "google_cloud.service_account.created",
  "google_cloud.service_account.deleted",
  "google_cloud.service_account.updated",
  "google_cloud.service_account_key.created",
  "google_cloud.service_account_key.deleted",
  "google_cloud.firewall_rule.created",
  "google_cloud.firewall_rule.updated",
  "google_cloud.firewall_rule.deleted",
  "google_cloud.vpc_network.created",
  "google_cloud.vpc_network.updated",
  "google_cloud.vpc_network.deleted",
  "google_cloud.storage_bucket.created",
  "google_cloud.storage_bucket.updated",
  "google_cloud.storage_bucket.deleted",
  "google_cloud.storage_iam.updated",
  "google_cloud.sql_instance.created",
  "google_cloud.sql_instance.updated",
  "google_cloud.sql_instance.deleted",
  "google_cloud.run_service.created",
  "google_cloud.run_service.updated",
  "google_cloud.run_service.deleted",
  "google_cloud.gke_cluster.created",
  "google_cloud.gke_cluster.updated",
  "google_cloud.gke_cluster.deleted",
  "google_cloud.gke_network_policy.updated",
  "google_cloud.gke_master_auth.updated",
  "google_cloud.secret.created",
  "google_cloud.secret.updated",
  "google_cloud.secret.deleted",
];

// M79D — Twilio Monitor event log control-plane configuration change events.
const TWILIO_EVENT_TYPES = [
  "twilio.account.updated",
  "twilio.phone_number.created",
  "twilio.phone_number.updated",
  "twilio.phone_number.deleted",
  "twilio.messaging_service.created",
  "twilio.messaging_service.updated",
  "twilio.messaging_service.deleted",
  "twilio.verify_service.created",
  "twilio.verify_service.updated",
  "twilio.verify_service.deleted",
  "twilio.api_key.created",
  "twilio.api_key.updated",
  "twilio.api_key.deleted",
  "twilio.config.event",
];

// M81D — Auth0 configuration-state events (synthesized from safe drift surfaces;
// Auth0 Management API logs are never ingested due to user_id/email/IP content).
const AUTH0_EVENT_TYPES = [
  "auth0.tenant.updated",
  "auth0.application.created",
  "auth0.application.updated",
  "auth0.application.deleted",
  "auth0.connection.created",
  "auth0.connection.updated",
  "auth0.connection.deleted",
  "auth0.resource_server.created",
  "auth0.resource_server.updated",
  "auth0.resource_server.deleted",
  "auth0.rule.created",
  "auth0.rule.updated",
  "auth0.rule.deleted",
  "auth0.action.created",
  "auth0.action.updated",
  "auth0.action.deployed",
  "auth0.action.deleted",
  "auth0.mfa_factor.updated",
  "auth0.custom_domain.created",
  "auth0.custom_domain.updated",
  "auth0.custom_domain.verified",
  "auth0.custom_domain.deleted",
  "auth0.config.event",
];

// M80D — SendGrid configuration-state events (synthesized; no native audit API).
const SENDGRID_EVENT_TYPES = [
  "sendgrid.account.updated",
  "sendgrid.api_key.created",
  "sendgrid.api_key.updated",
  "sendgrid.api_key.deleted",
  "sendgrid.sender_identity.created",
  "sendgrid.sender_identity.updated",
  "sendgrid.sender_identity.verified",
  "sendgrid.sender_identity.deleted",
  "sendgrid.domain_authentication.created",
  "sendgrid.domain_authentication.updated",
  "sendgrid.domain_authentication.deleted",
  "sendgrid.mail_settings.updated",
  "sendgrid.tracking_settings.updated",
  "sendgrid.event_webhook.updated",
  "sendgrid.inbound_parse.updated",
  "sendgrid.suppression_settings.updated",
  "sendgrid.config.event",
];

// M82D — Datadog configuration-state events (synthesized from safe drift surfaces;
// Datadog audit API is never ingested due to actor email/UUID and IP content).
const DATADOG_EVENT_TYPES = [
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
];

// M83D — Clerk configuration-state events (synthesized from safe drift surfaces;
// Clerk audit APIs are never ingested due to actor email/ID, session, and IP content).
const CLERK_EVENT_TYPES = [
  "clerk.instance_settings.updated",
  "clerk.auth_strategy.updated",
  "clerk.organization_settings.updated",
  "clerk.session_policy.updated",
  "clerk.email_sms_settings.updated",
  "clerk.domain.created",
  "clerk.domain.updated",
  "clerk.domain.deleted",
  "clerk.redirect_url_config.created",
  "clerk.redirect_url_config.updated",
  "clerk.redirect_url_config.deleted",
  "clerk.jwt_template.created",
  "clerk.jwt_template.updated",
  "clerk.jwt_template.deleted",
  "clerk.webhook_endpoint.created",
  "clerk.webhook_endpoint.updated",
  "clerk.webhook_endpoint.deleted",
  "clerk.config.event",
];

// M84D — PagerDuty configuration-state events (synthesized from safe drift surfaces;
// PagerDuty audit API is never ingested due to actor email/ID, IP, and payload content).
const PAGERDUTY_EVENT_TYPES = [
  "pagerduty.service.updated",
  "pagerduty.escalation_policy.updated",
  "pagerduty.schedule.updated",
  "pagerduty.service_integration.updated",
  "pagerduty.webhook_subscription.updated",
  "pagerduty.event_orchestration.updated",
  "pagerduty.business_service.updated",
  "pagerduty.response_play.updated",
  "pagerduty.config.event",
];

const LINEAR_EVENT_TYPES = [
  "linear.workspace.updated",
  "linear.team.updated",
  "linear.project.updated",
  "linear.workflow_state.updated",
  "linear.label.updated",
  "linear.webhook.updated",
  "linear.view.updated",
  "linear.cycle.updated",
  "linear.integration.updated",
  "linear.config.event",
];

// M86D — Jira configuration-state events (synthesized from safe drift surfaces;
// Jira audit/issue/user APIs are never ingested due to actor emails, account
// IDs, IP addresses, and issue content).
const JIRA_EVENT_TYPES = [
  "jira.site.updated",
  "jira.project.updated",
  "jira.board.updated",
  "jira.workflow.updated",
  "jira.workflow_scheme.updated",
  "jira.permission_scheme.updated",
  "jira.notification_scheme.updated",
  "jira.issue_type_scheme.updated",
  "jira.field_configuration_scheme.updated",
  "jira.screen_scheme.updated",
  "jira.webhook.updated",
  "jira.automation_rule.updated",
  "jira.config.event",
];

const LIMIT_OPTIONS = [25, 50, 100];

const PROVIDER_LABEL: Record<Provider, string> = { github: "GitHub", aws: "AWS", cloudflare: "Cloudflare", vercel: "Vercel", supabase: "Supabase", firebase: "Firebase", stripe: "Stripe", shopify: "Shopify", azure: "Azure", google_cloud: "Google Cloud", twilio: "Twilio", sendgrid: "SendGrid", auth0: "Auth0", datadog: "Datadog", clerk: "Clerk", pagerduty: "PagerDuty", linear: "Linear", jira: "Jira" };

export default function ActivityEventsPage() {
  const { getToken } = useAuth();
  const { isAdmin, roleLoaded } = useWorkspace();

  const [provider, setProvider] = useState<Provider>("github");
  const [events, setEvents] = useState<SecurityActivityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [eventType, setEventType] = useState("");
  const [limit, setLimit] = useState(50);

  const [syncing, setSyncing] = useState(false);
  const [syncNote, setSyncNote] = useState<string | null>(null);
  const [syncWarn, setSyncWarn] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const res = await getSecurityActivityEvents(
        { provider, event_type: eventType || undefined, page_size: limit },
        token,
      );
      setEvents(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch {
      setError("Could not load activity events. Please try again.");
    } finally {
      setLoading(false);
    }
  }, [getToken, provider, eventType, limit]);

  useEffect(() => {
    void load();
  }, [load]);

  const onProviderChange = useCallback((p: string) => {
    setProvider(p as Provider);
    setEventType("");
    setSyncNote(null);
    setSyncError(null);
  }, []);

  const onSync = useCallback(async () => {
    setSyncing(true);
    setSyncError(null);
    setSyncNote(null);
    try {
      const token = await getToken();
      if (provider === "cloudflare") {
        const r = await syncCloudflareActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "Cloudflare audit-log access is limited for this token. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "aws") {
        const r = await syncAwsSecurityAlerts(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "AWS security-alert access is limited for these credentials. " : ""}` +
            `Seen ${r.findings_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "vercel") {
        const r = await syncVercelActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "Vercel audit-log access is limited for this token/team. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "supabase") {
        const r = await syncSupabaseActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "Supabase audit-log access is limited for this token/project. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "firebase") {
        const r = await syncFirebaseActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "Firebase audit-log access is limited for these credentials. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "stripe") {
        const r = await syncStripeActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "Stripe Events API access is limited for this key. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "shopify") {
        const r = await syncShopifyActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "Shopify Events API access is limited for this token. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "azure") {
        const r = await syncAzureActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "Azure Activity Log access is limited for these credentials. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "google_cloud") {
        const r = await syncGoogleCloudActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "Google Cloud Audit Log access is limited for these credentials. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "twilio") {
        const r = await syncTwilioActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "Twilio Monitor event access is limited for these credentials. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "sendgrid") {
        const r = await syncSendGridActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "SendGrid configuration access is limited for these credentials. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "auth0") {
        const r = await syncAuth0Activity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "Auth0 Management API access is limited for these credentials. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "datadog") {
        const r = await syncDatadogActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "Datadog API access is limited for these credentials. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "clerk") {
        const r = await syncClerkActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "Clerk Backend API access is limited for these credentials. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "pagerduty") {
        const r = await syncPagerDutyActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "PagerDuty API access is limited for these credentials. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "linear") {
        const r = await syncLinearActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "Linear API access is limited for these credentials. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      } else if (provider === "jira") {
        const r = await syncJiraActivity(token);
        setSyncWarn(false);
        setSyncNote(
          `Scanned ${r.events_scanned} · created ${r.events_created} · skipped ${r.events_skipped}.`,
        );
      } else {
        const r = await syncSecurityActivity(token);
        setSyncWarn(r.permission_limited);
        setSyncNote(
          `${r.permission_limited ? "GitHub audit-log access is limited for this account/plan. " : ""}` +
            `Seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_updated_or_skipped}.` +
            `${r.error_message ? ` (${r.error_message})` : ""}`,
        );
      }
      await load();
    } catch {
      setSyncError(
        provider === "cloudflare"
          ? "Could not sync Cloudflare security activity. Please try again."
          : provider === "aws"
            ? "Could not sync AWS security alerts. Please try again."
            : provider === "vercel"
              ? "Could not sync Vercel activity. Please try again."
              : provider === "supabase"
                ? "Could not sync Supabase activity. Please try again."
                : provider === "firebase"
                  ? "Could not sync Firebase activity. Please try again."
                  : provider === "stripe"
                    ? "Could not sync Stripe activity. Please try again."
                    : provider === "shopify"
                      ? "Could not sync Shopify activity. Please try again."
                      : provider === "azure"
                        ? "Could not sync Azure Activity Log. Please try again."
                        : provider === "google_cloud"
                          ? "Could not sync Google Cloud activity. Please try again."
                          : provider === "twilio"
                            ? "Could not sync Twilio activity. Please try again."
                            : provider === "sendgrid"
                              ? "Could not sync SendGrid activity. Please try again."
                              : provider === "auth0"
                                ? "Could not sync Auth0 activity. Please try again."
                                : provider === "datadog"
                                  ? "Could not sync Datadog activity. Please try again."
                                  : provider === "clerk"
                                    ? "Could not sync Clerk activity. Please try again."
                                    : provider === "pagerduty"
                                      ? "Could not sync PagerDuty activity. Please try again."
                                      : provider === "linear"
                                        ? "Could not sync Linear activity. Please try again."
                                        : provider === "jira"
                                          ? "Could not sync Jira activity. Please try again."
                                          : "Could not sync GitHub activity. Please try again.",
      );
    } finally {
      setSyncing(false);
    }
  }, [getToken, provider, load]);

  const onSyncCloudTrail = useCallback(async () => {
    setSyncing(true);
    setSyncError(null);
    setSyncNote(null);
    try {
      const token = await getToken();
      const r = await syncAwsCloudTrail(token);
      setSyncWarn(r.permission_limited);
      setSyncNote(
        `${r.permission_limited ? "AWS CloudTrail access is limited for these credentials. " : ""}` +
          `CloudTrail: seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
          `${r.error_message ? ` (${r.error_message})` : ""}`,
      );
      await load();
    } catch {
      setSyncError("Could not sync AWS CloudTrail. Please try again.");
    } finally {
      setSyncing(false);
    }
  }, [getToken, load]);

  const onSyncSecurityHub = useCallback(async () => {
    setSyncing(true);
    setSyncError(null);
    setSyncNote(null);
    try {
      const token = await getToken();
      const r = await syncAwsSecurityHub(token);
      setSyncWarn(r.permission_limited);
      setSyncNote(
        `${r.permission_limited ? "AWS Security Hub access is limited for these credentials. " : ""}` +
          `Security Hub: seen ${r.findings_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
          `${r.error_message ? ` (${r.error_message})` : ""}`,
      );
      await load();
    } catch {
      setSyncError("Could not sync AWS Security Hub. Please try again.");
    } finally {
      setSyncing(false);
    }
  }, [getToken, load]);

  const onSyncCloudflareWaf = useCallback(async () => {
    setSyncing(true);
    setSyncError(null);
    setSyncNote(null);
    try {
      const token = await getToken();
      const r = await syncCloudflareWafEvents(token);
      setSyncWarn(r.permission_limited);
      setSyncNote(
        `${r.permission_limited ? "Cloudflare WAF/security events are unavailable for this token/plan. " : ""}` +
          `WAF events: seen ${r.events_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
          `${r.error_message ? ` (${r.error_message})` : ""}`,
      );
      await load();
    } catch {
      setSyncError("Could not sync Cloudflare WAF events. Please try again.");
    } finally {
      setSyncing(false);
    }
  }, [getToken, load]);

  const onSyncGithubSecretScanning = useCallback(async () => {
    setSyncing(true);
    setSyncError(null);
    setSyncNote(null);
    try {
      const token = await getToken();
      const r = await syncGitHubSecretScanning(token);
      setSyncWarn(r.permission_limited);
      setSyncNote(
        `${r.permission_limited ? "GitHub secret scanning is unavailable for this token/repo. " : ""}` +
          `Secret-scanning alerts: seen ${r.alerts_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
          `${r.error_message ? ` (${r.error_message})` : ""}`,
      );
      await load();
    } catch {
      setSyncError("Could not sync GitHub secret scanning alerts. Please try again.");
    } finally {
      setSyncing(false);
    }
  }, [getToken, load]);

  const onSyncGithubCodeScanning = useCallback(async () => {
    setSyncing(true);
    setSyncError(null);
    setSyncNote(null);
    try {
      const token = await getToken();
      const r = await syncGitHubCodeScanning(token);
      setSyncWarn(r.permission_limited);
      setSyncNote(
        `${r.permission_limited ? "GitHub code scanning is unavailable for this token/repo. " : ""}` +
          `Code-scanning alerts: seen ${r.alerts_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
          `${r.error_message ? ` (${r.error_message})` : ""}`,
      );
      await load();
    } catch {
      setSyncError("Could not sync GitHub code scanning alerts. Please try again.");
    } finally {
      setSyncing(false);
    }
  }, [getToken, load]);

  const onSyncGithubDependabot = useCallback(async () => {
    setSyncing(true);
    setSyncError(null);
    setSyncNote(null);
    try {
      const token = await getToken();
      const r = await syncGitHubDependabot(token);
      setSyncWarn(r.permission_limited);
      setSyncNote(
        `${r.permission_limited ? "GitHub Dependabot alerts are unavailable for this token/repo. " : ""}` +
          `Dependabot alerts: seen ${r.alerts_seen} · inserted ${r.events_inserted} · skipped ${r.events_skipped}.` +
          `${r.error_message ? ` (${r.error_message})` : ""}`,
      );
      await load();
    } catch {
      setSyncError("Could not sync GitHub Dependabot alerts. Please try again.");
    } finally {
      setSyncing(false);
    }
  }, [getToken, load]);

  const metrics = useMemo(() => {
    const types = new Set(events.map((e) => e.event_type)).size;
    const latest = events.reduce<string | null>((acc, e) => {
      const t = e.occurred_at ?? e.ingested_at;
      if (!t) return acc;
      if (!acc || Date.parse(t) > Date.parse(acc)) return t;
      return acc;
    }, null);
    return { types, latest };
  }, [events]);

  const eventTypeOptions =
    provider === "aws" ? AWS_EVENT_TYPES
    : provider === "vercel" ? VERCEL_EVENT_TYPES
    : provider === "supabase" ? SUPABASE_EVENT_TYPES
    : provider === "firebase" ? FIREBASE_EVENT_TYPES
    : provider === "stripe" ? STRIPE_EVENT_TYPES
    : provider === "shopify" ? SHOPIFY_EVENT_TYPES
    : provider === "cloudflare" ? CLOUDFLARE_EVENT_TYPES
    : provider === "azure" ? AZURE_EVENT_TYPES
    : provider === "google_cloud" ? GOOGLE_CLOUD_EVENT_TYPES
    : provider === "twilio" ? TWILIO_EVENT_TYPES
    : provider === "sendgrid" ? SENDGRID_EVENT_TYPES
    : provider === "auth0" ? AUTH0_EVENT_TYPES
    : provider === "datadog" ? DATADOG_EVENT_TYPES
    : provider === "clerk" ? CLERK_EVENT_TYPES
    : provider === "pagerduty" ? PAGERDUTY_EVENT_TYPES
    : provider === "linear" ? LINEAR_EVENT_TYPES
    : provider === "jira" ? JIRA_EVENT_TYPES
    : GITHUB_EVENT_TYPES;

  return (
    <div>
      <Hero />

      <SyncBar
        provider={provider}
        isAdmin={isAdmin}
        roleLoaded={roleLoaded}
        syncing={syncing}
        syncNote={syncNote}
        syncWarn={syncWarn}
        syncError={syncError}
        onSync={onSync}
        onSyncCloudTrail={onSyncCloudTrail}
        onSyncSecurityHub={onSyncSecurityHub}
        onSyncCloudflareWaf={onSyncCloudflareWaf}
        onSyncGithubSecretScanning={onSyncGithubSecretScanning}
        onSyncGithubCodeScanning={onSyncGithubCodeScanning}
        onSyncGithubDependabot={onSyncGithubDependabot}
      />

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
          gap: "14px",
          marginBottom: "24px",
        }}
      >
        <Metric label="Visible events" value={events.length} accent="#6b9cf8" />
        <Metric label={`${PROVIDER_LABEL[provider]} events`} value={events.length} accent="#6b9cf8" />
        <Metric label="Event types" value={metrics.types} accent="#f5a623" />
        <Metric
          label="Latest activity"
          text={metrics.latest ? formatRelativeTime(metrics.latest) : "—"}
          accent="#3ccf7e"
        />
      </div>

      <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center", marginBottom: "18px" }}>
        <Select label="Provider" value={provider} onChange={onProviderChange} options={["github", "aws", "cloudflare", "vercel", "supabase", "firebase", "stripe", "shopify", "azure", "google_cloud", "twilio", "sendgrid", "auth0", "datadog", "clerk", "pagerduty", "linear", "jira"]} allowAll={false} />
        <Select label="Event type" value={eventType} onChange={setEventType} options={eventTypeOptions} />
        <label style={{ fontSize: "12px", color: "#8b90a0", display: "flex", alignItems: "center", gap: "6px" }}>
          Limit
          <select
            value={String(limit)}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="bg-surface1 border border-border"
            style={{ fontSize: "12px", color: "#c4c8d4", borderRadius: "6px", padding: "5px 8px" }}
          >
            {LIMIT_OPTIONS.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
      </div>

      {loading ? (
        <LoadingState />
      ) : error ? (
        <ErrorState message={error} />
      ) : events.length === 0 ? (
        <EmptyState provider={provider} isAdmin={isAdmin} />
      ) : (
        <>
          <SectionLabel>
            {total} event{total === 1 ? "" : "s"}
          </SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {events.map((e) => (
              <EventRow key={e.id} event={e} />
            ))}
          </div>
        </>
      )}

      <p style={{ margin: "26px 0 0", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
        These are control-plane audit events, provider-reported findings, and
        Cloudflare audit/WAF security events. They do not by themselves confirm
        breach, attacker presence, or unauthorized access. They are evidence for
        review and the basis for Incident Signals and Configuration Risk
        correlations.
      </p>
    </div>
  );
}

// ── Hero ────────────────────────────────────────────────────────────────────

function Hero() {
  return (
    <>
      <PageHeader
        title="Activity Events"
        description="Normalized GitHub audit activity, AWS provider security findings, and Cloudflare audit/WAF events, used as evidence for Incident Signals."
      />
      <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px", marginBottom: "20px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>GitHub + AWS + Cloudflare beta</span>
          <Badge>Beta</Badge>
        </div>
        <p style={{ margin: 0, fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
          GitHub events are control-plane audit activity; AWS events are
          provider-reported security findings (GuardDuty / Access Analyzer). They
          do not by themselves confirm breach, attacker presence, or unauthorized
          access.
        </p>
      </div>
    </>
  );
}

// ── Sync bar ──────────────────────────────────────────────────────────────────

function SyncBar({
  provider,
  isAdmin,
  roleLoaded,
  syncing,
  syncNote,
  syncWarn,
  syncError,
  onSync,
  onSyncCloudTrail,
  onSyncSecurityHub,
  onSyncCloudflareWaf,
  onSyncGithubSecretScanning,
  onSyncGithubCodeScanning,
  onSyncGithubDependabot,
}: {
  provider: Provider;
  isAdmin: boolean;
  roleLoaded: boolean;
  syncing: boolean;
  syncNote: string | null;
  syncWarn: boolean;
  syncError: string | null;
  onSync: () => void;
  onSyncCloudTrail: () => void;
  onSyncSecurityHub: () => void;
  onSyncCloudflareWaf: () => void;
  onSyncGithubSecretScanning: () => void;
  onSyncGithubCodeScanning: () => void;
  onSyncGithubDependabot: () => void;
}) {
  const isAws = provider === "aws";
  const isCloudflare = provider === "cloudflare";
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
  const label = isCloudflare
    ? "Sync Cloudflare security activity"
    : isAws ? "Sync AWS security alerts"
    : isVercel ? "Sync Vercel activity"
    : isSupabase ? "Sync Supabase activity"
    : isFirebase ? "Sync Firebase activity"
    : isStripe ? "Sync Stripe activity"
    : isShopify ? "Sync Shopify activity"
    : isAzure ? "Sync Azure activity"
    : isGoogleCloud ? "Sync Google Cloud activity"
    : isTwilio ? "Sync Twilio activity"
    : isSendGrid ? "Sync SendGrid activity"
    : isAuth0 ? "Sync Auth0 activity"
    : isDatadog ? "Sync Datadog activity"
    : isClerk ? "Sync Clerk activity"
    : isPagerDuty ? "Sync PagerDuty activity"
    : isLinear ? "Sync Linear activity"
    : isJira ? "Sync Jira activity"
    : "Sync GitHub activity";
  const desc = isCloudflare
    ? "Sync Cloudflare audit activity (DNS, WAF/firewall, SSL/TLS, Access, zone settings) and WAF/security events when available. Audit logs need a token with Audit Logs Read; WAF/security events need GraphQL Analytics access and an eligible plan."
    : isAws
      ? "AWS events may include GuardDuty, Access Analyzer, CloudTrail management events, Security Hub findings, S3 data events, and VPC Flow Logs when configured. Sync provider-reported security findings, CloudTrail control-plane activity, or Security Hub findings as normalized activity events."
      : isVercel
        ? "Sync Vercel team audit activity (project, domain, environment-variable, deploy-hook, and deployment events) into normalized events. Available when the Vercel token/team supports activity or audit-log access."
        : isSupabase
          ? "Sync Supabase organization audit activity (project, table, RLS, policy, storage-bucket, Edge Function, and auth-config change events) into normalized events. Available when the Supabase token/project supports activity or audit-log access."
          : isFirebase
            ? "Sync Firebase control-plane change activity (Firestore/Realtime Database/Storage rules, auth-config, Cloud Function, Hosting, and project/app changes) into normalized events. Available when the Firebase credentials/project supports audit-log access."
            : isStripe
              ? "Sync review-safe Stripe configuration activity such as webhook, payment link, portal, and account setting changes. Available when the Stripe key has Events read access. Customer / payment / charge / invoice events are deliberately excluded."
              : isShopify
                ? "Sync review-safe Shopify configuration activity such as webhook, app scope, domain, policy, and shop setting changes. Available when the Shopify Admin API token has Events read scope. Customer / order / checkout / cart / payment / fulfillment events are deliberately excluded."
                : isAzure
                  ? "Sync review-safe Azure Activity Log evidence for configuration changes across NSGs, Storage, Key Vault, role assignments, App Service, SQL, and AKS. Requires the service principal to have the Reader role on the subscription. Only WRITE/DELETE management events are ingested — READ/LIST, data-plane, diagnostic, VM, and application logs are excluded."
                  : isGoogleCloud
                    ? "Sync review-safe Google Cloud Audit Log evidence for configuration changes across IAM, firewall rules, Storage, Cloud SQL, Cloud Run, GKE, and Secret Manager. Requires the service account to have the roles/logging.viewer role on the project. Only Admin Activity audit log entries for control-plane CREATE/UPDATE/DELETE operations are ingested — data-plane access, secret access events, storage object reads, VM logs, and application logs are excluded."
                    : isTwilio
                      ? "Sync review-safe Twilio configuration activity — phone number, messaging service, Verify service, and API key create/update/delete events. Message bodies, call logs, recordings, and customer data are never stored."
                      : isSendGrid
                        ? "Sync review-safe SendGrid configuration-state activity — account, API key, sender identity, domain authentication, mail/tracking settings, event webhook, inbound parse, and suppression configuration. SendGrid has no native audit API, so these are config-state observations. Email bodies, subject lines, recipient emails, template content, mail event payloads, raw webhook URLs, and API key values are never stored."
                        : isAuth0
                          ? "Sync review-safe Auth0 configuration activity — tenant settings, applications, connections, resource servers, rules, actions, MFA factors, and custom domains. Auth0 Management API logs are never ingested because they contain user IDs, emails, and IP addresses. ConfigTrace stores resource identifiers, OAuth/application posture, tenant settings, and control-plane summaries only — never user emails, login history, IP addresses, sessions, tokens, callback URLs, raw Auth0 logs, or client secrets."
                          : isDatadog
                            ? "Sync review-safe Datadog configuration activity. ConfigTrace stores monitor, SLO, dashboard, webhook, key, role, team, and cloud-integration posture summaries only — never API keys, application keys, raw monitor queries, raw monitor messages, webhook URLs, headers, payloads, logs, traces, metric values, incident text, emails, destination handles, raw audit payloads, or PII."
                            : isClerk
                              ? "Sync review-safe Clerk configuration activity derived from authentication configuration surfaces. ConfigTrace stores posture summaries only — never Clerk secret keys, session tokens, JWTs, OAuth tokens, webhook secrets, raw redirect URLs, raw callback URLs, raw webhook URLs, user emails, user IDs, phone numbers, names, session history, login history, IP addresses, user agents, raw audit payloads, customer data, or PII."
                              : isPagerDuty
                                ? "Sync review-safe PagerDuty configuration activity from service, escalation policy, schedule, integration, webhook, orchestration, business service, and response play configuration state. ConfigTrace stores only opaque IDs, booleans, counts, and categories — never API tokens, routing keys, integration keys, webhook secrets, raw URLs, user contact data, incident payloads, alert payloads, IP addresses, user agents, or PII."
                                : isLinear
                                  ? "Sync review-safe Linear configuration activity from workspace, team, project, workflow state, label, webhook, view, cycle, and integration configuration state. ConfigTrace stores only opaque IDs, booleans, counts, and categories — never API keys, OAuth tokens, webhook secrets, raw URLs, issue content, comments, attachments, user identities, customer names, IP addresses, user agents, or PII."
                                  : isJira
                                    ? "Sync review-safe Jira configuration activity from existing Jira configuration snapshots. ConfigTrace stores only safe counts, categories, booleans, and opaque resource identifiers, not Jira issue content, comments, attachments, user identities, tokens, raw URLs, JQL text, audit payloads, IP addresses, user agents, or PII."
                                    : "Ingests recent GitHub audit-log activity into normalized events.";
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
          {!isAdmin && roleLoaded && " Only workspace admins can sync."}
        </div>
        {syncNote && (
          <div style={{ fontSize: "12px", color: syncWarn ? "#f5a623" : "#3ccf7e", marginTop: "6px" }}>{syncNote}</div>
        )}
        {syncError && <div style={{ fontSize: "12px", color: "#e84040", marginTop: "6px" }}>{syncError}</div>}
      </div>
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
        <button
          onClick={onSync}
          disabled={!isAdmin || syncing}
          title={!isAdmin ? "Only workspace admins can sync." : undefined}
          style={{
            fontSize: "13px",
            fontWeight: 500,
            color: isAdmin ? "#0b0d12" : "#565b6e",
            background: isAdmin ? "#6b9cf8" : "#1e2030",
            border: "none",
            padding: "8px 16px",
            borderRadius: "8px",
            cursor: !isAdmin || syncing ? "not-allowed" : "pointer",
            opacity: syncing ? 0.7 : 1,
            whiteSpace: "nowrap",
          }}
        >
          {syncing ? "Syncing…" : label}
        </button>
        {isAws && (
          <button
            onClick={onSyncCloudTrail}
            disabled={!isAdmin || syncing}
            title={!isAdmin ? "Only workspace admins can sync." : undefined}
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || syncing ? "not-allowed" : "pointer",
              opacity: syncing ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Sync AWS CloudTrail
          </button>
        )}
        {isAws && (
          <button
            onClick={onSyncSecurityHub}
            disabled={!isAdmin || syncing}
            title={!isAdmin ? "Only workspace admins can sync." : undefined}
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || syncing ? "not-allowed" : "pointer",
              opacity: syncing ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Sync AWS Security Hub
          </button>
        )}
        {isCloudflare && (
          <button
            onClick={onSyncCloudflareWaf}
            disabled={!isAdmin || syncing}
            title={
              !isAdmin
                ? "Only workspace admins can sync."
                : "Available when the Cloudflare plan/token exposes security events."
            }
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || syncing ? "not-allowed" : "pointer",
              opacity: syncing ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Sync Cloudflare WAF events
          </button>
        )}
        {!isAws && !isCloudflare && !isSupabase && !isFirebase && !isGoogleCloud && !isTwilio && !isSendGrid && !isAuth0 && !isDatadog && !isClerk && !isPagerDuty && !isLinear && !isJira && (
          <button
            onClick={onSyncGithubSecretScanning}
            disabled={!isAdmin || syncing}
            title={
              !isAdmin
                ? "Only workspace admins can sync."
                : "Available when the GitHub token and repository support secret scanning alerts."
            }
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || syncing ? "not-allowed" : "pointer",
              opacity: syncing ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Sync GitHub secret scanning alerts
          </button>
        )}
        {!isAws && !isCloudflare && !isSupabase && !isFirebase && !isTwilio && !isSendGrid && !isAuth0 && !isDatadog && !isClerk && !isPagerDuty && !isLinear && !isJira && (
          <button
            onClick={onSyncGithubCodeScanning}
            disabled={!isAdmin || syncing}
            title={
              !isAdmin
                ? "Only workspace admins can sync."
                : "Available when the GitHub token and repository support code scanning alerts."
            }
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || syncing ? "not-allowed" : "pointer",
              opacity: syncing ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Sync GitHub code scanning alerts
          </button>
        )}
        {!isAws && !isCloudflare && !isSupabase && !isFirebase && !isTwilio && !isSendGrid && !isAuth0 && !isDatadog && !isClerk && !isJira && (
          <button
            onClick={onSyncGithubDependabot}
            disabled={!isAdmin || syncing}
            title={
              !isAdmin
                ? "Only workspace admins can sync."
                : "Available when the GitHub token and repository support Dependabot alerts."
            }
            className="bg-surface1 border border-border"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: isAdmin ? "#c4c8d4" : "#565b6e",
              borderRadius: "8px",
              padding: "8px 16px",
              cursor: !isAdmin || syncing ? "not-allowed" : "pointer",
              opacity: syncing ? 0.7 : 1,
              whiteSpace: "nowrap",
            }}
          >
            Sync GitHub Dependabot alerts
          </button>
        )}
      </div>
    </div>
  );
}

// ── Event row ─────────────────────────────────────────────────────────────────

function EventRow({ event }: { event: SecurityActivityEvent }) {
  const when = event.occurred_at ?? event.ingested_at;
  const resource = event.resource_id ?? (event.resource_type ? event.resource_type : null);
  return (
    <Link
      href={`/security/activity/${event.id}`}
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", textDecoration: "none", display: "block", padding: "14px 16px" }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
        <span
          style={{ fontSize: "12.5px", fontWeight: 600, color: "#e8eaf0", fontFamily: "monospace", flex: 1, minWidth: 0 }}
        >
          {event.event_type}
        </span>
        <span style={{ fontSize: "12px", color: "#6b9cf8" }}>View event →</span>
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          flexWrap: "wrap",
          marginTop: "8px",
          fontSize: "12px",
          color: "#8b90a0",
        }}
      >
        <span>{event.provider}</span>
        <span style={{ color: "#3a3d48" }}>·</span>
        <span>{event.source}</span>
        {event.actor_id && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <span>actor: {event.actor_id}</span>
          </>
        )}
        {resource && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <span>{resource}</span>
          </>
        )}
        {when && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <span>{formatRelativeTime(when)}</span>
          </>
        )}
      </div>
    </Link>
  );
}

// ── Small helpers ─────────────────────────────────────────────────────────────

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

function EmptyState({ provider, isAdmin }: { provider: Provider; isAdmin: boolean }) {
  const body =
    provider === "aws"
      ? isAdmin
        ? "Run “Sync AWS security alerts” above to ingest GuardDuty and Access Analyzer findings."
        : "An admin can sync AWS security alerts to ingest GuardDuty and Access Analyzer findings."
      : provider === "cloudflare"
        ? isAdmin
          ? "Run “Sync Cloudflare activity” above to ingest audit activity and WAF/security events."
          : "An admin can sync Cloudflare activity to ingest audit activity and WAF/security events."
        : provider === "vercel"
          ? isAdmin
            ? "Run “Sync Vercel activity” above. Available when the Vercel token/team supports activity or audit-log access."
            : "An admin can sync Vercel activity. Available when the Vercel token/team supports activity or audit-log access."
          : provider === "supabase"
            ? isAdmin
              ? "Run “Sync Supabase activity” above. Available when the Supabase token/project supports activity or audit-log access."
              : "An admin can sync Supabase activity. Available when the Supabase token/project supports activity or audit-log access."
            : provider === "firebase"
              ? isAdmin
                ? "Run “Sync Firebase activity” above. Available when the Firebase credentials/project supports audit-log access."
                : "An admin can sync Firebase activity. Available when the Firebase credentials/project supports audit-log access."
            : provider === "stripe"
              ? isAdmin
                ? "Run “Sync Stripe activity” above. Available when the Stripe key has Events read access. Customer / payment / charge / invoice events are deliberately excluded."
                : "An admin can sync Stripe activity. Available when the Stripe key has Events read access. Customer / payment / charge / invoice events are deliberately excluded."
            : provider === "shopify"
              ? isAdmin
                ? "Run “Sync Shopify activity” above. Available when the Shopify Admin API token has Events read scope. Customer / order / checkout / cart / payment / fulfillment events are deliberately excluded."
                : "An admin can sync Shopify activity. Available when the Shopify Admin API token has Events read scope. Customer / order / checkout / cart / payment / fulfillment events are deliberately excluded."
            : provider === "azure"
              ? isAdmin
                ? "Sync Azure activity first to collect review-safe Activity Log evidence — control-plane WRITE/DELETE events on NSGs, Storage, Key Vault, role assignments, App Service, SQL, and AKS. Requires the service principal to have the Reader role on the subscription."
                : "An admin can sync Azure activity to collect review-safe Activity Log evidence. Requires the service principal to have the Reader role on the subscription."
            : provider === "google_cloud"
              ? isAdmin
                ? "Sync Google Cloud activity first to collect review-safe Audit Log evidence — Admin Activity control-plane CREATE/UPDATE/DELETE events on IAM, firewall rules, Storage, Cloud SQL, Cloud Run, GKE, and Secret Manager. Requires the service account to have roles/logging.viewer on the project."
                : "An admin can sync Google Cloud activity to collect review-safe Audit Log evidence. Requires the service account to have roles/logging.viewer on the project."
            : provider === "twilio"
              ? isAdmin
                ? "Sync Twilio activity first to collect review-safe Monitor event evidence — account, phone number, messaging service, Verify service, and API key configuration changes. Message bodies, call logs, recordings, and customer phone numbers are never stored."
                : "An admin can sync Twilio activity to collect review-safe Monitor event evidence."
            : provider === "sendgrid"
              ? isAdmin
                ? "Sync SendGrid activity first to collect review-safe configuration-state evidence — account, API key, sender identity, domain authentication, mail/tracking settings, event webhook, inbound parse, and suppression configuration. SendGrid has no native audit API, so these are config-state observations. Email bodies, subject lines, recipient emails, template content, raw webhook URLs, and API key values are never stored."
                : "An admin can sync SendGrid activity to collect review-safe configuration-state evidence."
            : provider === "datadog"
              ? isAdmin
                ? "Sync Datadog activity first to collect review-safe configuration-state evidence — monitor, SLO, dashboard, webhook integration, notification integration, API key, application key, role, team, and cloud integration posture summaries. Datadog audit logs are never ingested. API keys, application keys, raw monitor queries, raw messages, webhook URLs, destination handles, emails, user IDs, and raw audit payloads are never stored."
                : "An admin can sync Datadog activity to collect review-safe configuration-state evidence."
            : provider === "clerk"
              ? isAdmin
                ? "Sync Clerk activity first to collect review-safe configuration-state evidence — instance settings, auth strategy, organization settings, session policy, email/SMS settings, domains, redirect URLs, JWT templates, and webhook endpoints. Clerk audit logs are never ingested. Secret keys, session tokens, JWTs, webhook secrets, raw redirect URLs, raw domain names, user emails, user IDs, session history, login history, IP addresses, and raw audit payloads are never stored."
                : "An admin can sync Clerk activity to collect review-safe configuration-state evidence."
            : provider === "pagerduty"
              ? isAdmin
                ? "Sync PagerDuty activity first to collect review-safe configuration-state evidence — service, escalation policy, schedule, service integration, webhook subscription, event orchestration, business service, and response play posture summaries. PagerDuty audit logs are never ingested. API tokens, routing keys, integration keys, webhook secrets, delivery URLs, user identities, incident payloads, alert payloads, IP addresses, and raw audit payloads are never stored."
                : "An admin can sync PagerDuty activity to collect review-safe configuration-state evidence."
            : provider === "linear"
              ? isAdmin
                ? "Sync Linear activity first to collect review-safe configuration-state evidence — workspace, team, project, workflow state, label, webhook, view, cycle, and integration posture summaries. Linear audit logs are never ingested. API keys, OAuth tokens, webhook secrets, raw URLs, issue content, comments, attachments, user identities, customer names, IP addresses, user agents, and raw audit payloads are never stored."
                : "An admin can sync Linear activity to collect review-safe configuration-state evidence."
            : provider === "jira"
              ? isAdmin
                ? "Sync Jira activity first to collect review-safe configuration-state evidence from existing Jira configuration snapshots — site, project, board, workflow, workflow scheme, permission scheme, notification scheme, issue type scheme, field configuration scheme, screen scheme, webhook, and automation rule posture summaries. ConfigTrace stores only safe counts, categories, booleans, and opaque resource identifiers, not Jira issue content, comments, attachments, user identities, tokens, raw URLs, JQL text, audit payloads, IP addresses, user agents, or PII."
                : "An admin can sync Jira activity to collect review-safe configuration-state evidence."
            : isAdmin
              ? "Run GitHub activity sync above to ingest recent audit activity and security-alert evidence."
              : "An admin can run GitHub activity sync to ingest recent audit activity and security-alert evidence.";
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "32px 24px", textAlign: "center" }}>
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#e8eaf0" }}>No activity events yet.</div>
      <p style={{ margin: "8px auto 0", maxWidth: "470px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>{body}</p>
    </div>
  );
}
