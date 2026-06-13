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
} from "@/lib/api";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { formatRelativeTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";

type Provider = "github" | "aws" | "cloudflare";

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
const LIMIT_OPTIONS = [25, 50, 100];

const PROVIDER_LABEL: Record<Provider, string> = { github: "GitHub", aws: "AWS", cloudflare: "Cloudflare" };

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
    : provider === "cloudflare" ? CLOUDFLARE_EVENT_TYPES
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
        <Select label="Provider" value={provider} onChange={onProviderChange} options={["github", "aws", "cloudflare"]} allowAll={false} />
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
}) {
  const isAws = provider === "aws";
  const isCloudflare = provider === "cloudflare";
  const label = isCloudflare
    ? "Sync Cloudflare security activity"
    : isAws ? "Sync AWS security alerts" : "Sync GitHub activity";
  const desc = isCloudflare
    ? "Sync Cloudflare audit activity (DNS, WAF/firewall, SSL/TLS, Access, zone settings) and WAF/security events when available. Audit logs need a token with Audit Logs Read; WAF/security events need GraphQL Analytics access and an eligible plan."
    : isAws
      ? "AWS events may include GuardDuty, Access Analyzer, CloudTrail management events, Security Hub findings, S3 data events, and VPC Flow Logs when configured. Sync provider-reported security findings, CloudTrail control-plane activity, or Security Hub findings as normalized activity events."
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
        {!isAws && !isCloudflare && (
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
      : isAdmin
        ? "Run GitHub activity sync above to ingest recent audit activity."
        : "An admin can run GitHub activity sync to ingest recent audit activity.";
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "32px 24px", textAlign: "center" }}>
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#e8eaf0" }}>No activity events yet.</div>
      <p style={{ margin: "8px auto 0", maxWidth: "470px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>{body}</p>
    </div>
  );
}
