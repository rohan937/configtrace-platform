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
import { getSecurityFinding } from "@/lib/api";
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
        <ExposureBody finding={finding} />
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

function ExposureBody({ finding }: { finding: SecurityFinding }) {
  const provider = getProviderMeta(finding.provider);
  const c = sevColor(finding.severity);
  const duration = formatExposureDuration(finding);
  const resourceLabel = finding.resource_id ?? "—";

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

      {/* 7. Review actions placeholder */}
      <Panel>
        <SectionLabel>Review actions</SectionLabel>
        <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "8px 0 12px" }}>
          Review actions arrive in a later milestone.
        </p>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "10px" }}>
          {["Acknowledge", "Snooze", "Accept risk"].map((label) => (
            <span
              key={label}
              aria-disabled="true"
              title="Review actions arrive in a later milestone."
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
