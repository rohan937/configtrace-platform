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
} from "@/types";
import { getSecurityCorrelations, generateSecurityCorrelations } from "@/lib/api";
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
const PROVIDER_OPTIONS = ["github", "aws", "cloudflare"];
const TYPE_OPTIONS_BY_PROVIDER: Record<string, string[]> = {
  github: ["webhook_change", "branch_protection_change", "deploy_key_added"],
  aws: ["aws_s3_public_access_alert", "aws_iam_credential_alert"],
  cloudflare: [
    "cloudflare_dns_change",
    "cloudflare_waf_change",
    "cloudflare_tls_change",
    "cloudflare_access_policy_change",
    "cloudflare_zone_setting_change",
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
  const [genResult, setGenResult] = useState<SecurityCorrelationGenerateResponse | null>(null);
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
      const res = await generateSecurityCorrelations({ provider }, token);
      setGenResult(res);
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
        <EmptyState isAdmin={isAdmin} />
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
  genResult: SecurityCorrelationGenerateResponse | null;
  genError: string | null;
  onGenerate: () => void;
}) {
  const blurb =
    provider === "cloudflare"
      ? "Correlate Cloudflare configuration risks with Cloudflare audit activity for the same zone and risk area (DNS, WAF, TLS)."
      : provider === "aws"
        ? "Correlate AWS configuration risks with GuardDuty and Access Analyzer findings for the same bucket or IAM principal."
        : "Matches configuration risks to GitHub audit activity on the same repository.";
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
            Scanned {genResult.findings_scanned} risks · {genResult.events_scanned} events ·{" "}
            {genResult.correlations_created} created · {genResult.correlations_skipped} skipped.
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

function EmptyState({ isAdmin }: { isAdmin: boolean }) {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "32px 24px", textAlign: "center" }}>
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#e8eaf0" }}>No correlations yet.</div>
      <p style={{ margin: "8px auto 0", maxWidth: "480px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
        Correlations appear once you have both Configuration Risks and GitHub
        activity for the same repository.
        {isAdmin
          ? " Use “Generate correlations” above once both exist."
          : " A workspace admin can generate correlations once both exist."}
      </p>
    </div>
  );
}
