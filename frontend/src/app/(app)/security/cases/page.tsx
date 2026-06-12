"use client";

/**
 * Cases / Investigations (M66.8).
 *
 * A case is a HUMAN-MANAGED investigation container grouping GitHub incident
 * evidence — Incident Signals, Configuration Risks, Activity Events, and
 * Correlations. (Replaces the M61.5 read-only incident-review page.)
 *
 * CLAIM DISCIPLINE: cases are investigation workspaces. This page never states
 * that a breach, attacker, compromise, or unauthorized access has been confirmed.
 * "Confirmed by user" / "Dismissed" are human actions.
 */

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import type { SecurityCase } from "@/types";
import {
  getSecurityCases,
  createSecurityCase,
  seedIncidentDemo,
  clearIncidentDemo,
} from "@/lib/api";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { formatRelativeTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";
import { SeverityBadge } from "@/components/security/findingDisplay";
import { CaseStatusBadge } from "@/components/security/signalDisplay";

const STATUS_OPTIONS = ["open", "investigating", "confirmed_by_user", "dismissed", "resolved"];
const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];

export default function CasesPage() {
  const { getToken } = useAuth();
  const { isAdmin } = useWorkspace();
  const router = useRouter();

  const [demoBusy, setDemoBusy] = useState(false);
  const [demoNote, setDemoNote] = useState<string | null>(null);

  const [cases, setCases] = useState<SecurityCase[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");

  const [creating, setCreating] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const res = await getSecurityCases(
        { status: status || undefined, severity: severity || undefined, page_size: 100 },
        token,
      );
      setCases(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch {
      setError("Could not load cases. Please try again.");
    } finally {
      setLoading(false);
    }
  }, [getToken, status, severity]);

  useEffect(() => {
    void load();
  }, [load]);

  const onCreate = useCallback(async () => {
    if (!newTitle.trim()) return;
    setCreating(true);
    setCreateError(null);
    try {
      const token = await getToken();
      const created = await createSecurityCase({ title: newTitle.trim() }, token);
      router.push(`/security/cases/${created.id}`);
    } catch {
      setCreateError("Could not create case. Please try again.");
      setCreating(false);
    }
  }, [getToken, newTitle, router]);

  const onSeedDemo = useCallback(async (provider: "github" | "aws") => {
    setDemoBusy(true);
    setDemoNote(null);
    try {
      const token = await getToken();
      const res = await seedIncidentDemo(token, provider);
      if (res.case_id) {
        router.push(`/security/cases/${res.case_id}`);
      } else {
        setDemoNote("Demo seeded.");
        await load();
        setDemoBusy(false);
      }
    } catch {
      setDemoNote("Could not load the demo. Please try again.");
      setDemoBusy(false);
    }
  }, [getToken, router, load]);

  const onClearDemo = useCallback(async (provider: "github" | "aws") => {
    setDemoBusy(true);
    setDemoNote(null);
    try {
      const token = await getToken();
      await clearIncidentDemo(token, provider);
      setDemoNote(provider === "aws" ? "AWS demo data cleared." : "Demo data cleared.");
      await load();
    } catch {
      setDemoNote("Could not clear the demo. Please try again.");
    } finally {
      setDemoBusy(false);
    }
  }, [getToken, load]);

  return (
    <div>
      <Hero />

      {/* Admin-only: load/clear the GitHub incident-workflow demo (M66.10) */}
      {isAdmin && (
        <div
          className="bg-surface1 border border-border"
          style={{ borderRadius: "12px", padding: "12px 16px", marginBottom: "20px", display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center" }}
        >
          <span style={{ fontSize: "12.5px", color: "#8b90a0", flex: 1, minWidth: "200px" }}>
            <strong style={{ color: "#e8eaf0" }}>Try the GitHub incident demo:</strong>{" "}
            seeds a sample risk → activity → signal → correlation → case (clearly
            marked demo, no real provider sync).
          </span>
          <button
            onClick={() => onSeedDemo("github")}
            disabled={demoBusy}
            style={{ fontSize: "12.5px", fontWeight: 500, color: "#0b0d12", background: "#6b9cf8", border: "none", padding: "7px 14px", borderRadius: "8px", cursor: demoBusy ? "not-allowed" : "pointer", opacity: demoBusy ? 0.7 : 1, whiteSpace: "nowrap" }}
          >
            {demoBusy ? "Working…" : "Load GitHub incident demo"}
          </button>
          <button
            onClick={() => onClearDemo("github")}
            disabled={demoBusy}
            className="bg-surface1 border border-border"
            style={{ fontSize: "12.5px", fontWeight: 500, color: "#c4c8d4", borderRadius: "8px", padding: "7px 14px", cursor: demoBusy ? "not-allowed" : "pointer", opacity: demoBusy ? 0.7 : 1, whiteSpace: "nowrap" }}
          >
            Clear demo
          </button>
          {demoNote && <span style={{ fontSize: "12px", color: "#3ccf7e", width: "100%" }}>{demoNote}</span>}
        </div>
      )}

      {/* Admin-only: load/clear the AWS incident-workflow demo (M67.4) */}
      {isAdmin && (
        <div
          className="bg-surface1 border border-border"
          style={{ borderRadius: "12px", padding: "12px 16px", marginBottom: "20px", display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center" }}
        >
          <span style={{ fontSize: "12.5px", color: "#8b90a0", flex: 1, minWidth: "200px" }}>
            <strong style={{ color: "#e8eaf0" }}>Try the AWS security demo:</strong>{" "}
            seed a sample AWS evidence chain across configuration risk, provider
            findings, CloudTrail activity, S3 data events, and VPC Flow Logs
            (clearly marked demo, no real AWS sync).
          </span>
          <button
            onClick={() => onSeedDemo("aws")}
            disabled={demoBusy}
            style={{ fontSize: "12.5px", fontWeight: 500, color: "#0b0d12", background: "#f5a623", border: "none", padding: "7px 14px", borderRadius: "8px", cursor: demoBusy ? "not-allowed" : "pointer", opacity: demoBusy ? 0.7 : 1, whiteSpace: "nowrap" }}
          >
            {demoBusy ? "Working…" : "Load AWS security demo"}
          </button>
          <button
            onClick={() => onClearDemo("aws")}
            disabled={demoBusy}
            className="bg-surface1 border border-border"
            style={{ fontSize: "12.5px", fontWeight: 500, color: "#c4c8d4", borderRadius: "8px", padding: "7px 14px", cursor: demoBusy ? "not-allowed" : "pointer", opacity: demoBusy ? 0.7 : 1, whiteSpace: "nowrap" }}
          >
            Clear AWS demo
          </button>
        </div>
      )}

      {/* Create case */}
      <div
        className="bg-surface1 border border-border"
        style={{ borderRadius: "12px", padding: "14px 16px", marginBottom: "20px", display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center" }}
      >
        <input
          value={newTitle}
          onChange={(e) => setNewTitle(e.target.value)}
          placeholder="New investigation title…"
          className="bg-surface2 border border-border"
          style={{ flex: 1, minWidth: "200px", fontSize: "13px", color: "#e8eaf0", borderRadius: "8px", padding: "8px 12px" }}
        />
        <button
          onClick={onCreate}
          disabled={creating || !newTitle.trim()}
          style={{
            fontSize: "13px",
            fontWeight: 500,
            color: newTitle.trim() ? "#0b0d12" : "#565b6e",
            background: newTitle.trim() ? "#6b9cf8" : "#1e2030",
            border: "none",
            padding: "8px 16px",
            borderRadius: "8px",
            cursor: creating || !newTitle.trim() ? "not-allowed" : "pointer",
            whiteSpace: "nowrap",
          }}
        >
          {creating ? "Creating…" : "Create case"}
        </button>
        {createError && <span style={{ fontSize: "12px", color: "#e84040" }}>{createError}</span>}
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center", marginBottom: "18px" }}>
        <Select label="Status" value={status} onChange={setStatus} options={STATUS_OPTIONS} />
        <Select label="Severity" value={severity} onChange={setSeverity} options={SEVERITY_OPTIONS} />
      </div>

      {loading ? (
        <LoadingState />
      ) : error ? (
        <ErrorState message={error} />
      ) : cases.length === 0 ? (
        <EmptyState />
      ) : (
        <>
          <SectionLabel>
            {total} case{total === 1 ? "" : "s"}
          </SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {cases.map((c) => (
              <Row key={c.id} c={c} />
            ))}
          </div>
        </>
      )}

      <p style={{ margin: "26px 0 0", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
        Cases are investigation workspaces. ConfigTrace does not automatically
        confirm breaches or unauthorized access — confirmation and dismissal are
        human actions.
      </p>
    </div>
  );
}

function Hero() {
  return (
    <>
      <PageHeader
        title="Cases"
        description="Group incident signals, configuration risks, activity events, and correlations into human-reviewed investigations."
      />
      <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px", marginBottom: "20px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>GitHub beta</span>
          <Badge>Beta</Badge>
        </div>
        <p style={{ margin: 0, fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
          Cases are investigation workspaces. ConfigTrace does not automatically
          confirm breaches or unauthorized access.
        </p>
      </div>
    </>
  );
}

function Row({ c }: { c: SecurityCase }) {
  return (
    <Link
      href={`/security/cases/${c.id}`}
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", textDecoration: "none", display: "block", padding: "14px 16px" }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
        <SeverityBadge severity={c.severity} />
        <span style={{ fontSize: "14px", fontWeight: 600, color: "#e8eaf0", flex: 1, minWidth: 0 }}>{c.title}</span>
        <span style={{ fontSize: "12px", color: "#6b9cf8" }}>View case →</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap", marginTop: "9px", fontSize: "12px", color: "#8b90a0" }}>
        <CaseStatusBadge status={c.status} />
        <span>{c.link_count} linked</span>
        {c.provider && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <span>{c.provider}</span>
          </>
        )}
        <span style={{ color: "#3a3d48" }}>·</span>
        <span>updated {formatRelativeTime(c.updated_at)}</span>
      </div>
    </Link>
  );
}

function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: string[] }) {
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

function Badge({ children }: { children: React.ReactNode }) {
  return (
    <span style={{ fontSize: "9px", fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase", color: "#6b9cf8", border: "1px solid rgba(107,156,248,0.4)", borderRadius: "5px", padding: "1px 6px" }}>
      {children}
    </span>
  );
}

function EmptyState() {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "32px 24px", textAlign: "center" }}>
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#e8eaf0" }}>No cases yet.</div>
      <p style={{ margin: "8px auto 0", maxWidth: "470px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
        Create a case above, or open an incident signal or correlation and choose
        “Create case” to start an investigation.
      </p>
    </div>
  );
}
