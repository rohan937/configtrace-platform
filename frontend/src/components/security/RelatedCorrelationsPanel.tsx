"use client";

/**
 * RelatedCorrelationsPanel (M66.7).
 *
 * Shared evidence-backlink panel. Given a link filter (one of linked_signal_id /
 * linked_finding_id / linked_activity_event_id), it lists the correlations that
 * connect this object to the rest of the GitHub incident-evidence graph
 * (Configuration Risk ↔ Activity Event ↔ Incident Signal).
 *
 * CLAIM DISCIPLINE: correlations are evidence for review. This panel never states
 * that a breach, attacker, compromise, or unauthorized access has been confirmed.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import type { SecuritySignalCorrelation } from "@/types";
import { getSecurityCorrelations } from "@/lib/api";
import { SectionLabel } from "@/components/security/previews";
import { SeverityBadge, ConfidenceBadge } from "@/components/security/findingDisplay";

type LinkFilter =
  | { linked_signal_id: string }
  | { linked_finding_id: string }
  | { linked_activity_event_id: string };

export default function RelatedCorrelationsPanel({
  filter,
  emptyText,
  /** Which object the panel is rendered on, so we omit its own redundant link. */
  hide,
}: {
  filter: LinkFilter;
  emptyText: string;
  hide?: "risk" | "activity" | "signal";
}) {
  const { getToken } = useAuth();
  const [rows, setRows] = useState<SecuritySignalCorrelation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  // Stable dependency key so the effect refetches only when the filter changes.
  const filterKey = JSON.stringify(filter);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(false);
      try {
        const token = await getToken();
        const res = await getSecurityCorrelations(
          { provider: "github", page_size: 50, ...filter },
          token,
        );
        if (!cancelled) setRows(res.items ?? []);
      } catch {
        if (!cancelled) setError(true);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [getToken, filterKey]);

  return (
    <div style={{ marginBottom: "22px" }}>
      <SectionLabel>Related correlations</SectionLabel>
      {loading ? (
        <div style={{ fontSize: "12.5px", color: "#565b6e", marginTop: "6px" }}>
          Loading correlations…
        </div>
      ) : error ? (
        <div style={{ fontSize: "12.5px", color: "#565b6e", marginTop: "6px" }}>
          Could not load related correlations.
        </div>
      ) : rows.length === 0 ? (
        <div style={{ fontSize: "12.5px", color: "#565b6e", marginTop: "6px" }}>{emptyText}</div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginTop: "8px" }}>
          {rows.map((c) => (
            <CorrelationMiniCard key={c.id} c={c} hide={hide} />
          ))}
        </div>
      )}
    </div>
  );
}

function CorrelationMiniCard({
  c,
  hide,
}: {
  c: SecuritySignalCorrelation;
  hide?: "risk" | "activity" | "signal";
}) {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "12px 14px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
        <SeverityBadge severity={c.severity} />
        <span style={{ fontSize: "13px", fontWeight: 600, color: "#e8eaf0", flex: 1, minWidth: 0 }}>
          {c.title}
        </span>
        <Link
          href={`/security/correlations/${c.id}`}
          style={{ fontSize: "12px", color: "#6b9cf8", textDecoration: "none" }}
        >
          View correlation →
        </Link>
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
        <ConfidenceBadge confidence={c.confidence} />
        <span>{c.correlation_type}</span>
        {c.linked_finding_id && hide !== "risk" && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <Link href={`/security/risks/${c.linked_finding_id}`} style={ctaLink}>
              risk →
            </Link>
          </>
        )}
        {c.linked_activity_event_id && hide !== "activity" && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <Link href={`/security/activity/${c.linked_activity_event_id}`} style={ctaLink}>
              activity →
            </Link>
          </>
        )}
        {c.linked_signal_id && hide !== "signal" && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <Link href={`/security/signals/${c.linked_signal_id}`} style={ctaLink}>
              signal →
            </Link>
          </>
        )}
      </div>
    </div>
  );
}

const ctaLink: React.CSSProperties = { color: "#6b9cf8", textDecoration: "none" };
