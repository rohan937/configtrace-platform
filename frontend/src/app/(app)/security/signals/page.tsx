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

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];
const STATUS_OPTIONS = ["open", "acknowledged", "dismissed", "resolved"];
const SIGNAL_TYPE_OPTIONS = [
  "branch_protection_change",
  "deploy_key_added",
  "webhook_change",
  "collaborator_change",
  "app_install",
  "app_permissions_change",
  "ruleset_change",
  "secret_scanning_alert",
];

const HIGH_SEVERITIES = new Set(["critical", "high"]);

export default function IncidentSignalsPage() {
  const { getToken } = useAuth();
  const { isAdmin, roleLoaded } = useWorkspace();

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

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const res = await getSecurityIncidentSignals(
        {
          provider: "github",
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
  }, [getToken, severity, status, signalType]);

  useEffect(() => {
    void load();
  }, [load]);

  const onGenerate = useCallback(async () => {
    setGenerating(true);
    setGenError(null);
    setGenResult(null);
    try {
      const token = await getToken();
      const res = await generateSecurityIncidentSignals({ provider: "github" }, token);
      setGenResult(res);
      await load();
    } catch {
      setGenError("Could not generate signals. Please try again.");
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
        isAdmin={isAdmin}
        roleLoaded={roleLoaded}
        generating={generating}
        genResult={genResult}
        genError={genError}
        onGenerate={onGenerate}
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
        <Metric label="GitHub signals" value={metrics.github} accent="#6b9cf8" />
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
        <Select label="Severity" value={severity} onChange={setSeverity} options={SEVERITY_OPTIONS} />
        <Select label="Status" value={status} onChange={setStatus} options={STATUS_OPTIONS} />
        <Select label="Signal type" value={signalType} onChange={setSignalType} options={SIGNAL_TYPE_OPTIONS} />
        <span style={{ fontSize: "12px", color: "#565b6e" }}>
          Provider: <strong style={{ color: "#8b90a0" }}>GitHub</strong>
        </span>
      </div>

      {loading ? (
        <LoadingState />
      ) : error ? (
        <ErrorState message={error} />
      ) : signals.length === 0 ? (
        <EmptyState isAdmin={isAdmin} />
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
        Signals are generated from normalized GitHub audit activity events.
        ConfigTrace does not automatically confirm breaches, attacker presence, or
        unauthorized access. Correlation with configuration risk is next.
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
        description="Review control-plane security signals generated from GitHub audit activity."
      />
      <div
        className="bg-surface1 border border-border"
        style={{ borderRadius: "12px", padding: "16px 18px", marginBottom: "20px" }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
            GitHub beta
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
          Signals are review cues from audit activity. ConfigTrace does not
          automatically confirm breaches, attacker presence, or unauthorized
          access.
        </p>
      </div>
    </>
  );
}

// ── Generate bar ──────────────────────────────────────────────────────────────

function GenerateBar({
  isAdmin,
  roleLoaded,
  generating,
  genResult,
  genError,
  onGenerate,
}: {
  isAdmin: boolean;
  roleLoaded: boolean;
  generating: boolean;
  genResult: SecuritySignalGenerateResponse | null;
  genError: string | null;
  onGenerate: () => void;
}) {
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
          Generate signals from activity
        </div>
        <div style={{ fontSize: "12px", color: "#8b90a0", marginTop: "2px" }}>
          Scans recent GitHub audit activity events and creates review signals.
          {!isAdmin && roleLoaded && " Only workspace admins can generate signals."}
        </div>
        {genResult && (
          <div style={{ fontSize: "12px", color: "#3ccf7e", marginTop: "6px" }}>
            Scanned {genResult.activity_events_scanned} activity events ·{" "}
            {genResult.signals_created} created · {genResult.signals_skipped} skipped.
          </div>
        )}
        {genError && (
          <div style={{ fontSize: "12px", color: "#e84040", marginTop: "6px" }}>{genError}</div>
        )}
      </div>
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
        {generating ? "Generating…" : "Generate signals"}
      </button>
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
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: string[];
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
        <option value="">All</option>
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

function EmptyState({ isAdmin }: { isAdmin: boolean }) {
  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", padding: "32px 24px", textAlign: "center" }}
    >
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#e8eaf0" }}>
        No incident signals yet.
      </div>
      <p style={{ margin: "8px auto 0", maxWidth: "460px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
        Run GitHub activity sync first, then generate signals.
        {isAdmin
          ? " Use “Generate signals” above once activity has been ingested."
          : " A workspace admin can ingest activity and generate signals."}
      </p>
    </div>
  );
}
