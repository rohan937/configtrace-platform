"use client";

/**
 * Incident Signal detail (M66.4).
 *
 * Read-only detail for one control-plane review signal (M66.3 backend).
 *
 * CLAIM DISCIPLINE: this page describes a signal based on GitHub audit activity.
 * It must never state that a breach, attacker, compromise, or unauthorized
 * access has been confirmed.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useAuth } from "@clerk/nextjs";

import type { SecurityIncidentSignal } from "@/types";
import { getSecurityIncidentSignal } from "@/lib/api";
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

export default function IncidentSignalDetailPage() {
  const params = useParams();
  const id = Array.isArray(params?.id) ? params.id[0] : (params?.id as string);
  const { getToken } = useAuth();

  const [signal, setSignal] = useState<SecurityIncidentSignal | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const token = await getToken();
        const s = await getSecurityIncidentSignal(id, token);
        if (!cancelled) setSignal(s);
      } catch {
        if (!cancelled) {
          setError(
            "This signal could not be found, or you do not have access to it.",
          );
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
      <Link
        href="/security/signals"
        style={{ fontSize: "13px", color: "#6b9cf8", textDecoration: "none" }}
      >
        ← Back to Incident Signals
      </Link>

      {loading ? (
        <div style={{ marginTop: "16px" }}>
          <LoadingState message="Loading signal…" />
        </div>
      ) : error || !signal ? (
        <div style={{ marginTop: "16px" }}>
          <ErrorState message={error ?? "Incident signal not found."} />
        </div>
      ) : (
        <SignalBody signal={signal} />
      )}
    </div>
  );
}

function SignalBody({ signal }: { signal: SecurityIncidentSignal }) {
  const metaKeys = Object.keys(signal.metadata ?? {});

  return (
    <div style={{ marginTop: "12px" }}>
      <PageHeader title={signal.title} />

      {/* Badges row */}
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "18px" }}>
        <SeverityBadge severity={signal.severity} />
        <SignalStatusBadge status={signal.status} />
        <ConfidenceBadge confidence={signal.confidence} />
        <Chip>evidence: {signal.evidence_level}</Chip>
        <Chip>{signal.provider}</Chip>
        <Chip>{signal.signal_type}</Chip>
      </div>

      {/* Summary */}
      <div
        className="bg-surface1 border border-border"
        style={{ borderRadius: "12px", padding: "16px 18px", marginBottom: "18px" }}
      >
        <p style={{ margin: 0, fontSize: "14px", color: "#c4c8d4", lineHeight: 1.6 }}>
          {signal.summary}
        </p>
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
        <Fact label="Signal key" value={signal.signal_key} mono />
        <Fact label="Evidence level" value={signal.evidence_level} />
        <Fact label="Confidence" value={signal.confidence} />
        <Fact
          label="First seen"
          value={signal.first_seen_at ? formatRelativeTime(signal.first_seen_at) : "—"}
        />
        <Fact
          label="Last seen"
          value={signal.last_seen_at ? formatRelativeTime(signal.last_seen_at) : "—"}
        />
        <Fact
          label="Created"
          value={signal.created_at ? formatRelativeTime(signal.created_at) : "—"}
        />
      </div>

      {/* Metadata (allowlisted, masked) */}
      <div style={{ marginBottom: "22px" }}>
        <SectionLabel>Signal metadata</SectionLabel>
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
                  {maskSensitiveValue(k, (signal.metadata ?? {})[k])}
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

      {/* Links */}
      <div style={{ marginBottom: "22px" }}>
        <SectionLabel>Source &amp; correlation</SectionLabel>
        <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "8px" }}>
          <LinkFact
            label="Linked activity event"
            value={signal.linked_activity_event_id}
            empty="—"
          />
          <LinkFact
            label="Linked configuration risk"
            value={signal.linked_finding_id ?? null}
            empty="Not linked — correlation coming soon"
          />
          <LinkFact
            label="Linked change"
            value={signal.linked_change_id ?? null}
            empty="Not linked — correlation coming soon"
          />
        </div>
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
          This signal is based on GitHub audit activity. It may require review, but
          it does not by itself confirm compromise or unauthorized access.
          ConfigTrace does not identify attackers or confirm breaches.
        </p>
      </div>
    </div>
  );
}

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "10px", padding: "12px 14px" }}>
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

function LinkFact({
  label,
  value,
  empty,
}: {
  label: string;
  value: string | null;
  empty: string;
}) {
  return (
    <div style={{ display: "flex", gap: "10px", fontSize: "12.5px", flexWrap: "wrap" }}>
      <span style={{ color: "#565b6e", minWidth: "180px" }}>{label}</span>
      <span
        style={{
          color: value ? "#c4c8d4" : "#565b6e",
          fontFamily: value ? "monospace" : undefined,
          wordBreak: "break-all",
        }}
      >
        {value ?? empty}
      </span>
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
