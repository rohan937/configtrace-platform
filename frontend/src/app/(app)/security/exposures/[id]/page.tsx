"use client";

/**
 * Exposure Detail (M60.6).
 *
 * A deep-linkable investigation packet for a single security exposure finding,
 * backed by GET /security/findings/{id} (getSecurityFinding). Read-only:
 * mutation/review workflows (acknowledge/snooze/accept) arrive in a later
 * milestone and are shown here only as informational placeholders.
 */

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useAuth } from "@clerk/nextjs";

import type { SecurityFinding } from "@/types";
import { getSecurityFinding, acceptSecurityFindingRisk } from "@/lib/api";
import { getProviderMeta } from "@/lib/providers";
import { formatAbsoluteTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";
import {
  EvidenceBlock,
  FindingStatusBadge,
  RemediationBlock,
  SeverityBadge,
  formatExposureDuration,
  sevColor,
} from "@/components/security/findingDisplay";

// ── Page ─────────────────────────────────────────────────────────────────────

export default function ExposureDetailPage() {
  const params = useParams();
  const id = Array.isArray(params?.id) ? params.id[0] : (params?.id as string);
  const { getToken } = useAuth();

  const [finding, setFinding] = useState<SecurityFinding | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const f = await getSecurityFinding(id, token);
      setFinding(f);
    } catch {
      // 404 / unauthorized / network all surface as a not-found state.
      setError("This exposure could not be found, or you do not have access to it.");
      setFinding(null);
    } finally {
      setLoading(false);
    }
  }, [id, getToken]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div>
      <BackLink />

      {loading ? (
        <>
          <PageHeader title="Exposure Detail" />
          <LoadingState message="Loading exposure…" />
        </>
      ) : error || !finding ? (
        <>
          <PageHeader title="Exposure Detail" />
          <ErrorState message={error ?? "Exposure not found."} />
        </>
      ) : (
        <ExposureBody finding={finding} onUpdated={setFinding} />
      )}
    </div>
  );
}

function BackLink() {
  return (
    <Link
      href="/security/exposures"
      style={{
        display: "inline-block",
        fontSize: "13px",
        color: "#6b9cf8",
        textDecoration: "none",
        marginBottom: "16px",
      }}
    >
      ← Back to Active Exposures
    </Link>
  );
}

// ── Body ──────────────────────────────────────────────────────────────────────

function ExposureBody({
  finding,
  onUpdated,
}: {
  finding: SecurityFinding;
  onUpdated: (f: SecurityFinding) => void;
}) {
  const provider = getProviderMeta(finding.provider);
  const c = sevColor(finding.severity);
  const duration = formatExposureDuration(finding);
  const resourceLabel = finding.resource_id ?? "—";
  const isAccepted = finding.status === "accepted_risk";

  return (
    <div>
      {/* Header */}
      <div
        className="bg-surface1 border border-border"
        style={{
          borderRadius: "12px",
          overflow: "hidden",
          display: "flex",
          marginBottom: "20px",
        }}
      >
        <div style={{ width: "4px", background: c, flexShrink: 0 }} />
        <div style={{ flex: 1, padding: "18px 20px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
            <SeverityBadge severity={finding.severity} />
            <FindingStatusBadge status={finding.status} />
            <span style={{ fontSize: "12px", color: provider.color, fontWeight: 600 }}>
              {provider.shortLabel}
            </span>
          </div>
          <h1
            style={{
              fontSize: "22px",
              fontWeight: 600,
              color: "#e8eaf0",
              margin: "12px 0 0",
              letterSpacing: "-0.01em",
            }}
          >
            {finding.title}
          </h1>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "8px",
              marginTop: "10px",
              fontSize: "12px",
              color: "#8b90a0",
            }}
          >
            <span style={{ fontFamily: "monospace", color: "#565b6e" }}>
              {finding.finding_key}
            </span>
            {duration ? (
              <>
                <span style={{ color: "#3a3d4a" }}>·</span>
                <span>{duration}</span>
              </>
            ) : null}
          </div>
        </div>
      </div>

      {/* Header facts grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: "12px",
          marginBottom: "24px",
        }}
      >
        <Fact label="Provider" value={provider.shortLabel} />
        <Fact label="Status" value={finding.status} />
        <Fact label="Resource" value={resourceLabel} mono />
        <Fact label="First detected" value={formatAbsoluteTime(finding.first_detected_at)} />
        <Fact label="Last seen" value={formatAbsoluteTime(finding.last_seen_at)} />
        {finding.status === "resolved" && finding.resolved_at ? (
          <Fact label="Resolved at" value={formatAbsoluteTime(finding.resolved_at)} />
        ) : null}
        {isAccepted && finding.accepted_until ? (
          <Fact label="Accepted until" value={formatAbsoluteTime(finding.accepted_until)} />
        ) : null}
      </div>

      {/* 1. What is exposed */}
      <Panel>
        <SectionLabel>What is exposed?</SectionLabel>
        <p style={{ fontSize: "14px", color: "#c4c8d4", lineHeight: 1.6, marginTop: "8px" }}>
          {finding.description || finding.title}
        </p>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
            gap: "10px",
            marginTop: "14px",
          }}
        >
          <Fact label="Provider" value={provider.label} inset />
          <Fact label="Finding key" value={finding.finding_key} mono inset />
          <Fact label="Resource" value={resourceLabel} mono inset />
          <Fact label="Integration" value={finding.integration_id} mono inset />
        </div>
      </Panel>

      {/* 2. Why it matters */}
      <Panel severity={finding.severity}>
        <SectionLabel>Why it matters</SectionLabel>
        <p style={{ fontSize: "14px", color: "#c4c8d4", lineHeight: 1.65, marginTop: "8px" }}>
          {finding.description ||
            "This configuration state may weaken security controls. Review the evidence below to confirm the impact."}
        </p>
        <p style={{ fontSize: "12px", color: "#565b6e", lineHeight: 1.6, marginTop: "12px" }}>
          ConfigTrace reports security-relevant configuration exposure from provider
          settings. This is a risky current state, not a confirmed compromise.
        </p>
      </Panel>

      {/* 3. Evidence */}
      <Panel>
        {finding.evidence ? (
          <EvidenceBlock evidence={finding.evidence} />
        ) : (
          <>
            <SectionLabel>Evidence</SectionLabel>
            <div style={{ fontSize: "12.5px", color: "#565b6e", marginTop: "6px" }}>
              No evidence was recorded for this finding.
            </div>
          </>
        )}
      </Panel>

      {/* 4. Suggested remediation */}
      <Panel>
        {finding.remediation ? (
          <RemediationBlock remediation={finding.remediation} />
        ) : (
          <>
            <SectionLabel>Suggested remediation</SectionLabel>
            <div style={{ fontSize: "12.5px", color: "#565b6e", marginTop: "6px" }}>
              No remediation guidance is available for this finding.
            </div>
          </>
        )}
      </Panel>

      {/* 5. Exposure lifecycle */}
      <Panel>
        <SectionLabel>Exposure lifecycle</SectionLabel>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
            gap: "10px",
            marginTop: "12px",
          }}
        >
          <Fact label="Status" value={finding.status} inset />
          <Fact label="First detected" value={formatAbsoluteTime(finding.first_detected_at)} inset />
          <Fact label="Last seen" value={formatAbsoluteTime(finding.last_seen_at)} inset />
          {finding.resolved_at ? (
            <Fact label="Resolved at" value={formatAbsoluteTime(finding.resolved_at)} inset />
          ) : null}
        </div>
        {duration ? (
          <div
            style={{
              marginTop: "14px",
              display: "inline-block",
              fontSize: "13px",
              fontWeight: 600,
              color: finding.status === "resolved" ? "#3ccf7e" : c,
              background: finding.status === "resolved" ? "rgba(60,207,126,0.12)" : `${c}1f`,
              border: `1px solid ${finding.status === "resolved" ? "rgba(60,207,126,0.4)" : `${c}55`}`,
              borderRadius: "8px",
              padding: "6px 12px",
            }}
          >
            {duration}
          </div>
        ) : null}
      </Panel>

      {/* 6. Linked drift event */}
      <Panel>
        <SectionLabel>Linked drift event</SectionLabel>
        {finding.linked_change_id ? (
          <div style={{ marginTop: "10px" }}>
            <p style={{ fontSize: "13px", color: "#c4c8d4", lineHeight: 1.6, marginBottom: "10px" }}>
              This exposure was associated with a configuration change.
            </p>
            <Link
              href={`/changes/${finding.linked_change_id}`}
              style={{
                display: "inline-block",
                fontSize: "13px",
                fontWeight: 600,
                color: "#6b9cf8",
                textDecoration: "none",
                border: "1px solid #2a2d38",
                borderRadius: "8px",
                padding: "8px 14px",
              }}
            >
              View drift change {finding.linked_change_id.slice(0, 8)}… →
            </Link>
          </div>
        ) : (
          <p style={{ fontSize: "13px", color: "#8b90a0", lineHeight: 1.6, marginTop: "8px" }}>
            No linked drift event was attached. This can happen when the risky state
            existed at baseline or no matching change was available.
          </p>
        )}
      </Panel>

      {/* 7. Accepted risk record (shown once a risk has been accepted) */}
      {isAccepted ? (
        <Panel>
          <SectionLabel>Accepted risk</SectionLabel>
          <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "8px 0 12px", lineHeight: 1.6 }}>
            The team is intentionally carrying this exposure until the date below.
            Accepting risk does not mark the exposure fixed.
          </p>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
              gap: "10px",
            }}
          >
            {finding.accepted_until ? (
              <Fact label="Accepted until" value={formatAbsoluteTime(finding.accepted_until)} inset />
            ) : null}
            {finding.reviewed_at ? (
              <Fact label="Accepted at" value={formatAbsoluteTime(finding.reviewed_at)} inset />
            ) : null}
          </div>
          {finding.acceptance_reason ? (
            <div style={{ marginTop: "12px" }}>
              <SectionLabel>Reason</SectionLabel>
              <p style={{ fontSize: "13px", color: "#c4c8d4", lineHeight: 1.6, marginTop: "6px", whiteSpace: "pre-wrap" }}>
                {finding.acceptance_reason}
              </p>
            </div>
          ) : null}
        </Panel>
      ) : null}

      {/* 8. Review actions */}
      <Panel>
        <SectionLabel>Review actions</SectionLabel>
        <AcceptRiskAction finding={finding} onUpdated={onUpdated} />
        <p style={{ fontSize: "12px", color: "#565b6e", margin: "14px 0 0", lineHeight: 1.6 }}>
          Acknowledge and Snooze arrive in a later milestone.
        </p>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "10px", marginTop: "8px" }}>
          {["Acknowledge", "Snooze"].map((label) => (
            <span
              key={label}
              aria-disabled="true"
              title="This review action arrives in a later milestone."
              style={{
                fontSize: "13px",
                fontWeight: 600,
                color: "#565b6e",
                background: "rgba(148,163,184,0.06)",
                border: "1px solid #2a2d38",
                borderRadius: "8px",
                padding: "8px 14px",
                cursor: "not-allowed",
              }}
            >
              {label}
            </span>
          ))}
        </div>
      </Panel>
    </div>
  );
}

// ── Accept Risk action ────────────────────────────────────────────────────────

function defaultAcceptedUntil(): string {
  // Default the date picker to 30 days out (local date, YYYY-MM-DD).
  const d = new Date();
  d.setDate(d.getDate() + 30);
  return d.toISOString().slice(0, 10);
}

function AcceptRiskAction({
  finding,
  onUpdated,
}: {
  finding: SecurityFinding;
  onUpdated: (f: SecurityFinding) => void;
}) {
  const { getToken } = useAuth();
  const isAccepted = finding.status === "accepted_risk";
  const isResolved = finding.status === "resolved";

  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState(defaultAcceptedUntil());
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const reasonValid = reason.trim().length >= 5;
  const untilValid = (() => {
    if (!until) return false;
    const t = new Date(`${until}T23:59:59`).getTime();
    return !Number.isNaN(t) && t > Date.now();
  })();

  async function submit() {
    if (!reasonValid || !untilValid) return;
    setBusy(true);
    setErr(null);
    try {
      const token = await getToken();
      // Send end-of-day in the user's local zone so "today" is never in the past.
      const acceptedUntilIso = new Date(`${until}T23:59:59`).toISOString();
      const updated = await acceptSecurityFindingRisk(
        finding.id,
        { reason: reason.trim(), accepted_until: acceptedUntilIso },
        token,
      );
      onUpdated(updated);
      setOpen(false);
      setReason("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to accept risk.");
    } finally {
      setBusy(false);
    }
  }

  if (isResolved) {
    return (
      <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "8px 0 0", lineHeight: 1.6 }}>
        This exposure is resolved. Resolved exposures cannot be accepted as risk.
      </p>
    );
  }

  const btnPrimary: React.CSSProperties = {
    fontSize: "13px",
    fontWeight: 600,
    color: "#f5a623",
    background: "rgba(245,166,35,0.12)",
    border: "1px solid rgba(245,166,35,0.4)",
    borderRadius: "8px",
    padding: "8px 14px",
    cursor: "pointer",
    fontFamily: "inherit",
  };
  const inputStyle: React.CSSProperties = {
    background: "#1c1e26",
    border: "1px solid #3a3d4a",
    borderRadius: "6px",
    padding: "8px 10px",
    fontSize: "13px",
    color: "#e2e5ef",
    fontFamily: "inherit",
    width: "100%",
    boxSizing: "border-box",
  };

  if (!open) {
    return (
      <div style={{ marginTop: "8px" }}>
        <button type="button" style={btnPrimary} onClick={() => { setOpen(true); setErr(null); }}>
          {isAccepted ? "Update accepted risk" : "Accept risk"}
        </button>
        <p style={{ fontSize: "12px", color: "#8b90a0", margin: "10px 0 0", lineHeight: 1.6 }}>
          Accepting risk does not mark the exposure fixed. It records that the team
          is intentionally carrying this risk until the chosen date.
        </p>
      </div>
    );
  }

  return (
    <div
      style={{
        marginTop: "10px",
        background: "#1a1d28",
        border: "1px solid #3a3d4a",
        borderRadius: "8px",
        padding: "14px",
      }}
    >
      <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "0 0 12px", lineHeight: 1.6 }}>
        Accepting risk does not mark the exposure fixed. It records that the team is
        intentionally carrying this risk until the chosen date.
      </p>

      <label style={{ display: "block", fontSize: "12px", color: "#8b90a0", marginBottom: "5px" }}>
        Reason <span style={{ color: "#f5a623" }}>*</span>
      </label>
      <textarea
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        rows={3}
        maxLength={1000}
        placeholder="Why is the team intentionally carrying this risk?"
        style={{ ...inputStyle, resize: "vertical", marginBottom: "4px" }}
      />
      <p style={{ fontSize: "11px", color: reasonValid ? "#565b6e" : "#e07a5f", margin: "0 0 12px" }}>
        At least 5 characters required.
      </p>

      <label style={{ display: "block", fontSize: "12px", color: "#8b90a0", marginBottom: "5px" }}>
        Accepted until <span style={{ color: "#f5a623" }}>*</span>
      </label>
      <input
        type="date"
        value={until}
        onChange={(e) => setUntil(e.target.value)}
        style={{ ...inputStyle, marginBottom: "4px" }}
      />
      <p style={{ fontSize: "11px", color: untilValid ? "#565b6e" : "#e07a5f", margin: "0 0 12px" }}>
        Must be a future date.
      </p>

      {err ? (
        <p style={{ fontSize: "12px", color: "#e07a5f", margin: "0 0 10px" }}>{err}</p>
      ) : null}

      <div style={{ display: "flex", gap: "8px" }}>
        <button
          type="button"
          style={{ ...btnPrimary, opacity: busy || !reasonValid || !untilValid ? 0.5 : 1, cursor: busy || !reasonValid || !untilValid ? "not-allowed" : "pointer" }}
          disabled={busy || !reasonValid || !untilValid}
          onClick={submit}
        >
          {busy ? "Saving…" : isAccepted ? "Update acceptance" : "Confirm accept risk"}
        </button>
        <button
          type="button"
          style={{
            fontSize: "13px",
            fontWeight: 600,
            color: "#8b90a0",
            background: "none",
            border: "1px solid #2a2d38",
            borderRadius: "8px",
            padding: "8px 14px",
            cursor: "pointer",
            fontFamily: "inherit",
          }}
          onClick={() => { setOpen(false); setErr(null); }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// ── Small building blocks ─────────────────────────────────────────────────────

function Panel({
  children,
  severity,
}: {
  children: React.ReactNode;
  severity?: string;
}) {
  const border = severity ? `${sevColor(severity)}55` : "#2a2d38";
  return (
    <div
      className="bg-surface1"
      style={{
        border: `1px solid ${border}`,
        borderRadius: "12px",
        padding: "18px 20px",
        marginBottom: "16px",
      }}
    >
      {children}
    </div>
  );
}

function Fact({
  label,
  value,
  mono,
  inset,
}: {
  label: string;
  value: string;
  mono?: boolean;
  inset?: boolean;
}) {
  return (
    <div
      className={inset ? undefined : "bg-surface1 border border-border"}
      style={
        inset
          ? undefined
          : { borderRadius: "10px", padding: "12px 14px" }
      }
    >
      <div style={{ fontSize: "11px", color: "#565b6e", marginBottom: "3px" }}>
        {label}
      </div>
      <div
        style={{
          fontSize: "13px",
          color: "#c4c8d4",
          fontFamily: mono ? "monospace" : undefined,
          wordBreak: "break-all",
          textTransform: mono ? undefined : "capitalize",
        }}
      >
        {value}
      </div>
    </div>
  );
}
