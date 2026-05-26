"use client";

/**
 * CorrelationPanel — M58.10.
 *
 * Displays the deterministic change-correlation / risk-cluster result for the
 * current change.  Data comes from GET /changes/{id}/correlation — computed
 * on demand on the backend, nothing persisted.
 *
 * Design rules:
 *   - No free-text input.  No LLM.  No external API calls from this component.
 *   - Language: "possible / may be related" — never "confirmed / root cause".
 *   - For low confidence: the panel renders collapsed/subtle.
 *   - Empty state: a brief note that ConfigTrace watches for related signals.
 *   - Never displays prev_value / new_value (not in CorrelationResponse).
 */

import Link from "next/link";
import type { CorrelationResponse, CorrelationCluster } from "@/types";
import RiskBadge from "@/components/common/RiskBadge";
import type { RiskLevel } from "@/types";
import { formatRelativeTime } from "@/lib/utils";

// ── Colour helpers ────────────────────────────────────────────────────────────

const CONFIDENCE_COLORS: Record<string, string> = {
  high:   "#3ccf7e",
  medium: "#f5a623",
  low:    "#565b6e",
};

const CLUSTER_TYPE_COLORS: Record<string, string> = {
  deployment_routing: "#4f80f7",
  payments_commerce:  "#3ccf7e",
  edge_security:      "#f5632a",
  auth_access:        "#8b5cf6",
  data_protection:    "#e84040",
  provider_local:     "#565b6e",
  unknown:            "#565b6e",
};

const CLUSTER_TYPE_ICONS: Record<string, string> = {
  deployment_routing: "🚀",
  payments_commerce:  "💳",
  edge_security:      "🛡",
  auth_access:        "🔑",
  data_protection:    "🗄",
  provider_local:     "🔗",
  unknown:            "🔗",
};

// ── Sub-components ────────────────────────────────────────────────────────────

function ConfidenceBadge({ confidence }: { confidence: string }) {
  const color = CONFIDENCE_COLORS[confidence] ?? "#565b6e";
  const label =
    confidence === "high" ? "High confidence" :
    confidence === "medium" ? "Medium confidence" :
    "Low confidence";
  return (
    <span
      style={{
        fontSize: "10px",
        color,
        border: `1px solid ${color}33`,
        borderRadius: "4px",
        padding: "2px 7px",
        letterSpacing: "0.03em",
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

function ClusterTypePill({ type }: { type: string }) {
  const color = CLUSTER_TYPE_COLORS[type] ?? "#565b6e";
  const icon = CLUSTER_TYPE_ICONS[type] ?? "🔗";
  const label = type.replace(/_/g, " ");
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
        fontSize: "11px",
        color,
        background: `${color}14`,
        border: `1px solid ${color}30`,
        borderRadius: "4px",
        padding: "2px 8px",
      }}
    >
      <span aria-hidden="true">{icon}</span>
      {label}
    </span>
  );
}

function SignalList({ signals }: { signals: string[] }) {
  if (!signals.length) return null;
  return (
    <div>
      <p
        style={{
          fontSize: "10px",
          color: "#3a3e50",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          margin: "0 0 5px",
        }}
      >
        Correlation signals
      </p>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
        {signals.map((sig, i) => (
          <span
            key={i}
            style={{
              fontSize: "11px",
              color: "#565b6e",
              background: "#0e0f11",
              border: "1px solid #1e2030",
              borderRadius: "4px",
              padding: "2px 7px",
            }}
          >
            {sig}
          </span>
        ))}
      </div>
    </div>
  );
}

function RelatedChangeRow({ item }: { item: CorrelationCluster["related_changes"][number] }) {
  const typeColor = CLUSTER_TYPE_COLORS["unknown"];
  return (
    <Link href={item.url} style={{ textDecoration: "none" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "10px",
          padding: "7px 0",
          borderBottom: "1px solid #1a1d26",
        }}
      >
        <RiskBadge level={item.risk_level as RiskLevel} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <p
            style={{
              fontSize: "13px",
              color: "#c8ccd8",
              margin: 0,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {item.title}
          </p>
          <p style={{ fontSize: "11px", color: "#565b6e", margin: "2px 0 0" }}>
            <span style={{ color: "#8b90a0", fontWeight: 500 }}>
              {item.provider}
            </span>
            {item.record_type ? (
              <>
                {" · "}
                <span className="font-mono" style={{ fontSize: "10px" }}>
                  {item.record_type}
                </span>
              </>
            ) : null}
            {" · "}
            {formatRelativeTime(item.detected_at)}
          </p>
        </div>
        <span style={{ fontSize: "12px", color: "#565b6e", flexShrink: 0 }}>→</span>
      </div>
    </Link>
  );
}

function ClusterCard({ cluster }: { cluster: CorrelationCluster }) {
  const isLowConf = cluster.confidence === "low";

  return (
    <div>
      {/* Cluster header */}
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: "12px",
          marginBottom: "10px",
          flexWrap: "wrap",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          <h3
            style={{
              fontSize: "13px",
              fontWeight: 600,
              color: "#e8eaf0",
              margin: 0,
              lineHeight: 1.4,
            }}
          >
            {cluster.title}
          </h3>
          <div style={{ display: "flex", gap: "6px", alignItems: "center", flexWrap: "wrap" }}>
            <ClusterTypePill type={cluster.cluster_type} />
            <ConfidenceBadge confidence={cluster.confidence} />
            <span style={{ fontSize: "11px", color: "#565b6e" }}>
              {cluster.time_window_minutes < 60
                ? `±${cluster.time_window_minutes} min window`
                : `±${Math.round(cluster.time_window_minutes / 60)} h window`}
            </span>
          </div>
        </div>
      </div>

      {/* Summary */}
      <p
        style={{
          fontSize: "13px",
          color: "#8b90a0",
          lineHeight: 1.6,
          margin: "0 0 14px",
        }}
      >
        {cluster.summary}
      </p>

      {/* Related changes list */}
      {cluster.related_changes.length > 0 && (
        <div style={{ marginBottom: "14px" }}>
          {cluster.related_changes.map((item) => (
            <RelatedChangeRow key={item.id} item={item} />
          ))}
        </div>
      )}

      {/* Signals */}
      {!isLowConf && cluster.signals.length > 0 && (
        <div style={{ marginBottom: "12px" }}>
          <SignalList signals={cluster.signals} />
        </div>
      )}

      {/* Recommended review */}
      {cluster.recommended_review.length > 0 && (
        <div
          style={{
            borderTop: "1px solid #1e2030",
            paddingTop: "10px",
            marginTop: "4px",
          }}
        >
          <p
            style={{
              fontSize: "10px",
              color: "#3a3e50",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              margin: "0 0 6px",
            }}
          >
            Recommended review
          </p>
          <ul role="list" style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {cluster.recommended_review.map((step, i) => (
              <li
                key={i}
                style={{
                  display: "flex",
                  gap: "8px",
                  fontSize: "12px",
                  color: "#8b90a0",
                  lineHeight: 1.6,
                  paddingBottom: "2px",
                }}
              >
                <span aria-hidden="true" style={{ color: "#4f80f7", flexShrink: 0 }}>·</span>
                {step}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function EmptyState() {
  return (
    <p
      style={{
        fontSize: "12px",
        color: "#3a3e50",
        fontStyle: "italic",
        margin: 0,
        lineHeight: 1.5,
      }}
    >
      No strong cluster detected. ConfigTrace will surface nearby changes when
      multiple related signals appear in the same time window.
    </p>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface CorrelationPanelProps {
  correlation: CorrelationResponse | null;
  loading?: boolean;
}

export default function CorrelationPanel({
  correlation,
  loading = false,
}: CorrelationPanelProps) {
  const isLowConf =
    correlation?.available &&
    correlation.primary_cluster?.confidence === "low";

  return (
    <section aria-labelledby="section-correlation" id="correlation">
      <h2
        id="section-correlation"
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          margin: "0 0 8px",
          fontWeight: 500,
        }}
      >
        Change cluster
      </h2>

      <div
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "6px",
          padding: "14px 16px",
          // Subtle styling for low-confidence clusters
          opacity: isLowConf ? 0.8 : 1,
        }}
      >
        {loading ? (
          <p style={{ fontSize: "13px", color: "#565b6e", margin: 0 }}>
            Analyzing nearby changes…
          </p>
        ) : !correlation || !correlation.available || !correlation.primary_cluster ? (
          <EmptyState />
        ) : (
          <ClusterCard cluster={correlation.primary_cluster} />
        )}
      </div>
    </section>
  );
}
