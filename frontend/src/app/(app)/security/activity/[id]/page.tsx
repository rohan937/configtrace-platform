"use client";

/**
 * Activity Event detail (M66.5).
 *
 * Read-only detail for one normalized GitHub audit activity event (M66.2).
 *
 * CLAIM DISCIPLINE: this is normalized audit metadata — evidence for review, not
 * proof of compromise. Never state that a breach, attacker, compromise, or
 * unauthorized access has been confirmed.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useAuth } from "@clerk/nextjs";

import type { SecurityActivityEvent } from "@/types";
import { getSecurityActivityEvent } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";
import { humanizeKey, maskSensitiveValue } from "@/components/security/findingDisplay";
import RelatedCorrelationsPanel from "@/components/security/RelatedCorrelationsPanel";

export default function ActivityEventDetailPage() {
  const params = useParams();
  const id = Array.isArray(params?.id) ? params.id[0] : (params?.id as string);
  const { getToken } = useAuth();

  const [event, setEvent] = useState<SecurityActivityEvent | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const token = await getToken();
        const ev = await getSecurityActivityEvent(id, token);
        if (!cancelled) setEvent(ev);
      } catch {
        if (!cancelled) {
          setError("This activity event could not be found, or you do not have access to it.");
        }
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
      <Link href="/security/activity" style={{ fontSize: "13px", color: "#6b9cf8", textDecoration: "none" }}>
        ← Back to Activity Events
      </Link>

      {loading ? (
        <div style={{ marginTop: "16px" }}>
          <LoadingState message="Loading activity event…" />
        </div>
      ) : error || !event ? (
        <div style={{ marginTop: "16px" }}>
          <ErrorState message={error ?? "Activity event not found."} />
        </div>
      ) : (
        <EventBody event={event} />
      )}
    </div>
  );
}

function EventBody({ event }: { event: SecurityActivityEvent }) {
  const metaKeys = Object.keys(event.metadata ?? {});

  return (
    <div style={{ marginTop: "12px" }}>
      <PageHeader title={event.event_type} />

      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "18px" }}>
        <Chip>{event.provider}</Chip>
        <Chip>source: {event.source}</Chip>
        {event.actor_type && <Chip>actor type: {event.actor_type}</Chip>}
      </div>

      {/* Facts grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "12px",
          marginBottom: "22px",
        }}
      >
        <Fact label="Event type" value={event.event_type} mono />
        <Fact label="Actor id" value={event.actor_id ?? "—"} mono />
        <Fact label="Actor type" value={event.actor_type ?? "—"} />
        <Fact label="Resource type" value={event.resource_type ?? "—"} />
        <Fact label="Resource id" value={event.resource_id ?? "—"} mono />
        <Fact
          label="Occurred"
          value={event.occurred_at ? formatRelativeTime(event.occurred_at) : "—"}
        />
        <Fact
          label="Ingested"
          value={event.ingested_at ? formatRelativeTime(event.ingested_at) : "—"}
        />
        <Fact label="Provider event id" value={event.provider_event_id ?? "—"} mono />
        <Fact label="Raw ref (pointer)" value={event.raw_ref ?? "—"} mono />
        <Fact
          label="Source IP (hashed)"
          value={event.source_ip_hash ?? "—"}
          mono
          hint="Salted hash only — the raw IP is never stored."
        />
      </div>

      {/* Metadata */}
      <div style={{ marginBottom: "22px" }}>
        <SectionLabel>Activity metadata</SectionLabel>
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
                <div style={{ fontSize: "11px", color: "#565b6e", marginBottom: "2px" }}>
                  {humanizeKey(k)}
                </div>
                <div
                  style={{
                    fontSize: "12.5px",
                    color: "#c4c8d4",
                    fontFamily: "monospace",
                    wordBreak: "break-all",
                  }}
                >
                  {maskSensitiveValue(k, (event.metadata ?? {})[k])}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ fontSize: "12.5px", color: "#565b6e", marginTop: "6px" }}>
            No additional metadata recorded.
          </div>
        )}
      </div>

      {/* Related correlations (M66.7) */}
      <RelatedCorrelationsPanel
        filter={{ linked_activity_event_id: event.id }}
        emptyText="No configuration-risk correlation has been linked to this activity event yet."
        hide="activity"
      />

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
          This event is normalized audit metadata. It is evidence for review, not
          proof of compromise. ConfigTrace does not identify attackers or confirm
          unauthorized access.
        </p>
      </div>
    </div>
  );
}

function Fact({
  label,
  value,
  mono,
  hint,
}: {
  label: string;
  value: string;
  mono?: boolean;
  hint?: string;
}) {
  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "10px", padding: "12px 14px" }}
      title={hint}
    >
      <div style={{ fontSize: "11px", color: "#565b6e", marginBottom: "4px" }}>{label}</div>
      <div
        style={{
          fontSize: "13px",
          color: "#c4c8d4",
          fontFamily: mono ? "monospace" : undefined,
          wordBreak: "break-all",
        }}
      >
        {value}
      </div>
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
