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

type Provider = "github" | "aws" | "cloudflare" | "vercel" | "supabase";

const CLOUDFLARE_SIGNAL_TYPES = ["cloudflare_audit_activity", "cloudflare_waf_activity_signal"];
const VERCEL_SIGNAL_TYPES = ["vercel_activity_signal"];
const SUPABASE_SIGNAL_TYPES = ["supabase_activity_signal"];
const PROVIDER_LABEL: Record<Provider, string> = { github: "GitHub", aws: "AWS", cloudflare: "Cloudflare", vercel: "Vercel", supabase: "Supabase" };

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];
const STATUS_OPTIONS = ["open", "acknowledged", "dismissed", "resolved"];
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
        <Select label="Provider" value={provider} onChange={onProviderChange} options={["github", "aws", "cloudflare", "vercel", "supabase"]} allowAll={false} />
        <Select label="Severity" value={severity} onChange={setSeverity} options={SEVERITY_OPTIONS} />
        <Select label="Status" value={status} onChange={setStatus} options={STATUS_OPTIONS} />
        <Select
          label="Signal type"
          value={signalType}
          onChange={setSignalType}
          options={provider === "aws" ? AWS_SIGNAL_TYPES : provider === "cloudflare" ? CLOUDFLARE_SIGNAL_TYPES : provider === "vercel" ? VERCEL_SIGNAL_TYPES : provider === "supabase" ? SUPABASE_SIGNAL_TYPES : GITHUB_SIGNAL_TYPES}
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
  const label = isCloudflare ? "Generate Cloudflare signals"
    : isAws ? "Generate AWS signals"
    : isVercel ? "Generate Vercel activity signals"
    : isSupabase ? "Generate Supabase activity signals" : "Generate signals";
  const desc = isCloudflare
    ? "Generate review signals from Cloudflare audit activity (DNS, WAF/firewall, SSL/TLS, Access, zone settings, API-token activity)."
    : isAws
      ? "Generate Incident Signals from provider-reported AWS security findings (GuardDuty / Access Analyzer / Security Hub), or review signals from CloudTrail IAM/KMS/S3 management activity, S3 object-level data events, or VPC Flow Log network activity."
      : isVercel
        ? "Generate review signals from Vercel activity evidence (project, domain, environment-variable, deploy-hook, and deployment changes)."
        : isSupabase
          ? "Generate review signals from Supabase activity evidence (table/RLS, access policy, storage bucket, Edge Function, auth configuration, and project changes)."
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
