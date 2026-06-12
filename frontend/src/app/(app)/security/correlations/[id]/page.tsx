"use client";

/**
 * Correlation detail (M66.6).
 *
 * Read-only detail for one Configuration Risk × GitHub audit-activity correlation.
 *
 * CLAIM DISCIPLINE: a correlation is evidence for review. Never state that a
 * breach, attacker, compromise, or unauthorized access has been confirmed.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useAuth } from "@clerk/nextjs";

import type { SecuritySignalCorrelation } from "@/types";
import { getSecurityCorrelation } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";
import {
  SeverityBadge,
  ConfidenceBadge,
  humanizeKey,
  maskSensitiveValue,
} from "@/components/security/findingDisplay";
import { SignalStatusBadge } from "@/components/security/signalDisplay";

export default function CorrelationDetailPage() {
  const params = useParams();
  const id = Array.isArray(params?.id) ? params.id[0] : (params?.id as string);
  const { getToken } = useAuth();

  const [c, setC] = useState<SecuritySignalCorrelation | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const token = await getToken();
        const res = await getSecurityCorrelation(id, token);
        if (!cancelled) setC(res);
      } catch {
        if (!cancelled) setError("This correlation could not be found, or you do not have access to it.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [getToken, id]);

  return (
    <div>
      <Link href="/security/correlations" style={{ fontSize: "13px", color: "#6b9cf8", textDecoration: "none" }}>
        ← Back to Correlations
      </Link>

      {loading ? (
        <div style={{ marginTop: "16px" }}>
          <LoadingState message="Loading correlation…" />
        </div>
      ) : error || !c ? (
        <div style={{ marginTop: "16px" }}>
          <ErrorState message={error ?? "Correlation not found."} />
        </div>
      ) : (
        <Body c={c} />
      )}
    </div>
  );
}

function Body({ c }: { c: SecuritySignalCorrelation }) {
  const metaKeys = Object.keys(c.metadata ?? {});

  return (
    <div style={{ marginTop: "12px" }}>
      <PageHeader title={c.title} />

      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "18px" }}>
        <SeverityBadge severity={c.severity} />
        <SignalStatusBadge status={c.status} />
        <ConfidenceBadge confidence={c.confidence} />
        <Chip>{c.provider}</Chip>
        <Chip>{c.correlation_type}</Chip>
      </div>

      <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px", marginBottom: "18px" }}>
        <p style={{ margin: 0, fontSize: "14px", color: "#c4c8d4", lineHeight: 1.6 }}>{c.summary}</p>
      </div>

      {/* Linked evidence */}
      <div style={{ marginBottom: "22px" }}>
        <SectionLabel>Linked evidence</SectionLabel>
        <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "8px" }}>
          <EvidenceLink
            label="Configuration risk"
            href={c.linked_finding_id ? `/security/risks/${c.linked_finding_id}` : null}
            cta="View configuration risk →"
          />
          <EvidenceLink
            label="Activity event"
            href={c.linked_activity_event_id ? `/security/activity/${c.linked_activity_event_id}` : null}
            cta="View source activity event →"
          />
          <EvidenceLink
            label="Incident signal"
            href={c.linked_signal_id ? `/security/signals/${c.linked_signal_id}` : null}
            cta="View related signal →"
          />
        </div>
      </div>

      {/* Evidence timeline */}
      <div style={{ marginBottom: "22px" }}>
        <SectionLabel>Evidence timeline</SectionLabel>
        <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "8px" }}>
          <TimelineRow
            label="Configuration risk first seen"
            value={c.first_seen_at ? formatRelativeTime(c.first_seen_at) : "—"}
          />
          <TimelineRow
            label="Review window"
            value={
              c.window_start && c.window_end
                ? `${formatRelativeTime(c.window_start)} → ${formatRelativeTime(c.window_end)}`
                : "—"
            }
          />
          <TimelineRow
            label="Latest activity in window"
            value={c.last_seen_at ? formatRelativeTime(c.last_seen_at) : "—"}
          />
          <TimelineRow
            label="Correlation generated"
            value={c.created_at ? formatRelativeTime(c.created_at) : "—"}
          />
        </div>
      </div>

      {/* Metadata */}
      <div style={{ marginBottom: "22px" }}>
        <SectionLabel>Correlation metadata</SectionLabel>
        {metaKeys.length > 0 ? (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
              gap: "10px",
              marginTop: "8px",
            }}
          >
            {metaKeys.map((k) => (
              <div key={k}>
                <div style={{ fontSize: "11px", color: "#565b6e", marginBottom: "2px" }}>{humanizeKey(k)}</div>
                <div style={{ fontSize: "12.5px", color: "#c4c8d4", fontFamily: "monospace", wordBreak: "break-all" }}>
                  {maskSensitiveValue(k, (c.metadata ?? {})[k])}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ fontSize: "12.5px", color: "#565b6e", marginTop: "6px" }}>No additional metadata recorded.</div>
        )}
      </div>

      {/* Claim-discipline note */}
      <div
        style={{
          borderRadius: "10px",
          background: "rgba(107,156,248,0.06)",
          border: "1px solid rgba(107,156,248,0.22)",
          padding: "12px 14px",
        }}
      >
        <p style={{ margin: 0, fontSize: "12.5px", color: "#8b90a0", lineHeight: 1.6 }}>
          A configuration risk and GitHub audit activity were observed for the same
          repository within the review window. This is evidence for review. It does
          not by itself confirm compromise or unauthorized access, and ConfigTrace
          does not identify attackers.
        </p>
      </div>
    </div>
  );
}

function EvidenceLink({ label, href, cta }: { label: string; href: string | null; cta: string }) {
  return (
    <div style={{ display: "flex", gap: "10px", fontSize: "12.5px", flexWrap: "wrap", alignItems: "center" }}>
      <span style={{ color: "#565b6e", minWidth: "180px" }}>{label}</span>
      {href ? (
        <Link href={href} style={{ color: "#6b9cf8", textDecoration: "none", fontWeight: 500 }}>
          {cta}
        </Link>
      ) : (
        <span style={{ color: "#565b6e" }}>— not linked</span>
      )}
    </div>
  );
}

function TimelineRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: "flex", gap: "10px", fontSize: "12.5px", flexWrap: "wrap" }}>
      <span style={{ color: "#565b6e", minWidth: "220px" }}>{label}</span>
      <span style={{ color: "#c4c8d4" }}>{value}</span>
    </div>
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
