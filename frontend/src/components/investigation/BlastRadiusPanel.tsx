"use client";

/**
 * BlastRadiusPanel — M58.11.
 *
 * Displays the deterministic blast radius / potential impact analysis for the
 * current change.  Data comes from GET /changes/{id}/blast-radius — computed
 * on demand on the backend, nothing persisted.
 *
 * Design rules:
 *   - No free-text input.  No LLM.  No external API calls from this component.
 *   - Language: "potentially affects" / "may affect" — never "confirmed affected".
 *   - Empty state: a brief note that no model is available for this change type.
 *   - Always renders the disclaimer: "Blast radius is inferred from
 *     configuration metadata. Review provider context before acting."
 *   - Never displays prev_value / new_value.
 */

import type { BlastRadiusResponse, BlastRadiusItem, AffectedSurface } from "@/types";

// ── Colour helpers ────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#e84040",
  high:     "#f5632a",
  medium:   "#f5a623",
  low:      "#6b9cf8",
};

const CONFIDENCE_COLORS: Record<string, string> = {
  high:   "#3ccf7e",
  medium: "#f5a623",
  low:    "#565b6e",
};

const DOMAIN_ICONS: Record<string, string> = {
  network_exposure:     "🌐",
  admin_access:         "🔐",
  data_access:          "🗄",
  auth_flow:            "🔑",
  deployment_path:      "🚀",
  payment_flow:         "💳",
  commerce_operations:  "🛍",
  edge_protection:      "🛡",
  monitoring_visibility:"👁",
  credential_access:    "🗝",
  customer_self_service:"👤",
  dns_routing:          "📡",
};

const DOMAIN_LABELS: Record<string, string> = {
  network_exposure:     "Network exposure",
  admin_access:         "Admin access",
  data_access:          "Data access",
  auth_flow:            "Auth flow",
  deployment_path:      "Deployment path",
  payment_flow:         "Payment flow",
  commerce_operations:  "Commerce operations",
  edge_protection:      "Edge protection",
  monitoring_visibility:"Monitoring visibility",
  credential_access:    "Credential access",
  customer_self_service:"Customer self-service",
  dns_routing:          "DNS routing",
};

const SURFACE_TYPE_ICONS: Record<string, string> = {
  resource:    "📦",
  integration: "🔗",
  workflow:    "⚙",
  infra:       "🏗",
};

// ── Sub-components ────────────────────────────────────────────────────────────

function ConfidenceBadge({ confidence }: { confidence: string }) {
  const color = CONFIDENCE_COLORS[confidence] ?? "#565b6e";
  const label =
    confidence === "high"   ? "High confidence" :
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
        flexShrink: 0,
      }}
    >
      {label}
    </span>
  );
}

function SeverityPip({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity] ?? "#565b6e";
  return (
    <span
      style={{
        display: "inline-block",
        width: "7px",
        height: "7px",
        borderRadius: "50%",
        background: color,
        flexShrink: 0,
        marginTop: "5px",
      }}
      title={`${severity} severity`}
    />
  );
}

function DomainPill({ domain }: { domain: string }) {
  const icon  = DOMAIN_ICONS[domain] ?? "•";
  const label = DOMAIN_LABELS[domain] ?? domain.replace(/_/g, " ");
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
        fontSize: "11px",
        color: "#8b90a0",
        background: "#1c1e26",
        border: "1px solid #2a2d38",
        borderRadius: "4px",
        padding: "2px 8px",
      }}
    >
      <span aria-hidden="true">{icon}</span>
      {label}
    </span>
  );
}

function EvidenceChip({ text }: { text: string }) {
  return (
    <span
      style={{
        fontSize: "11px",
        color: "#565b6e",
        background: "#0e0f11",
        border: "1px solid #1e2030",
        borderRadius: "4px",
        padding: "2px 7px",
      }}
    >
      {text}
    </span>
  );
}

function ImpactItem({ item }: { item: BlastRadiusItem }) {
  return (
    <div
      style={{
        borderBottom: "1px solid #1a1d26",
        paddingBottom: "14px",
        marginBottom: "14px",
      }}
    >
      {/* Item header */}
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: "8px",
          marginBottom: "6px",
        }}
      >
        <SeverityPip severity={item.severity} />
        <div style={{ flex: 1 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              flexWrap: "wrap",
            }}
          >
            <span
              style={{
                fontSize: "13px",
                fontWeight: 600,
                color: "#c8ccd8",
              }}
            >
              {item.label}
            </span>
            <ConfidenceBadge confidence={item.confidence} />
          </div>
        </div>
      </div>

      {/* Description */}
      <p
        style={{
          fontSize: "13px",
          color: "#8b90a0",
          lineHeight: 1.6,
          margin: "0 0 8px 15px",
        }}
      >
        {item.description}
      </p>

      {/* Evidence chips */}
      {item.evidence.length > 0 && (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: "4px",
            marginLeft: "15px",
            marginBottom: "8px",
          }}
        >
          {item.evidence.map((e, i) => (
            <EvidenceChip key={i} text={e} />
          ))}
        </div>
      )}

      {/* Recommended review steps */}
      {item.recommended_review.length > 0 && (
        <div style={{ marginLeft: "15px" }}>
          <p
            style={{
              fontSize: "10px",
              color: "#3a3e50",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              margin: "0 0 4px",
            }}
          >
            Review steps
          </p>
          <ul role="list" style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {item.recommended_review.map((step, i) => (
              <li
                key={i}
                style={{
                  display: "flex",
                  gap: "7px",
                  fontSize: "12px",
                  color: "#8b90a0",
                  lineHeight: 1.6,
                  paddingBottom: "1px",
                }}
              >
                <span
                  aria-hidden="true"
                  style={{ color: "#4f80f7", flexShrink: 0 }}
                >
                  ·
                </span>
                {step}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function AffectedSurfaceRow({ surface }: { surface: AffectedSurface }) {
  const icon = SURFACE_TYPE_ICONS[surface.type] ?? "•";
  const confColor = CONFIDENCE_COLORS[surface.confidence] ?? "#565b6e";
  return (
    <div
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: "10px",
        padding: "7px 0",
        borderBottom: "1px solid #1a1d26",
      }}
    >
      <span
        aria-hidden="true"
        style={{ fontSize: "14px", flexShrink: 0, paddingTop: "1px" }}
      >
        {icon}
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            flexWrap: "wrap",
            marginBottom: "2px",
          }}
        >
          <span style={{ fontSize: "13px", fontWeight: 500, color: "#c8ccd8" }}>
            {surface.label}
          </span>
          {surface.known && (
            <span
              style={{
                fontSize: "10px",
                color: "#3ccf7e",
                border: "1px solid #3ccf7e33",
                borderRadius: "3px",
                padding: "1px 5px",
              }}
            >
              inferred
            </span>
          )}
        </div>
        <p style={{ fontSize: "12px", color: "#565b6e", margin: 0, lineHeight: 1.5 }}>
          {surface.description}
        </p>
      </div>
      <span
        style={{
          fontSize: "10px",
          color: confColor,
          flexShrink: 0,
          paddingTop: "3px",
        }}
      >
        {surface.confidence}
      </span>
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
      No specific blast radius model is available for this change type.
      ConfigTrace will model impact surfaces as provider coverage expands.
    </p>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface BlastRadiusPanelProps {
  blastRadius: BlastRadiusResponse | null;
  loading?: boolean;
}

export default function BlastRadiusPanel({
  blastRadius,
  loading = false,
}: BlastRadiusPanelProps) {
  const isAvailable = blastRadius?.available === true;

  return (
    <section aria-labelledby="section-blast-radius" id="blast-radius">
      <h2
        id="section-blast-radius"
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          margin: "0 0 8px",
          fontWeight: 500,
        }}
      >
        Blast radius
      </h2>

      <div
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "6px",
          padding: "14px 16px",
        }}
      >
        {loading ? (
          <p style={{ fontSize: "13px", color: "#565b6e", margin: 0 }}>
            Analyzing potential impact…
          </p>
        ) : !isAvailable ? (
          <EmptyState />
        ) : (
          <>
            {/* Panel header */}
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
              <h3
                style={{
                  fontSize: "13px",
                  fontWeight: 600,
                  color: "#e8eaf0",
                  margin: 0,
                  lineHeight: 1.4,
                  flex: 1,
                }}
              >
                {blastRadius!.title}
              </h3>
              <ConfidenceBadge confidence={blastRadius!.confidence} />
            </div>

            {/* Summary */}
            <p
              style={{
                fontSize: "13px",
                color: "#8b90a0",
                lineHeight: 1.6,
                margin: "0 0 12px",
              }}
            >
              {blastRadius!.summary}
            </p>

            {/* Impact domain pills */}
            {blastRadius!.impact_domains.length > 0 && (
              <div
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  gap: "5px",
                  marginBottom: "16px",
                }}
              >
                {blastRadius!.impact_domains.map((d) => (
                  <DomainPill key={d} domain={d} />
                ))}
              </div>
            )}

            {/* Impact items */}
            {blastRadius!.items.length > 0 && (
              <div style={{ marginBottom: "4px" }}>
                {blastRadius!.items.map((item, i) => (
                  <ImpactItem key={i} item={item} />
                ))}
              </div>
            )}

            {/* Affected surfaces */}
            {blastRadius!.affected_surfaces.length > 0 && (
              <div style={{ marginBottom: "14px" }}>
                <p
                  style={{
                    fontSize: "10px",
                    color: "#3a3e50",
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    margin: "0 0 4px",
                  }}
                >
                  Potentially affected surfaces
                </p>
                {blastRadius!.affected_surfaces.map((s, i) => (
                  <AffectedSurfaceRow key={i} surface={s} />
                ))}
              </div>
            )}

            {/* Limitations */}
            {blastRadius!.limitations.length > 0 && (
              <div
                style={{
                  borderTop: "1px solid #1e2030",
                  paddingTop: "10px",
                  marginTop: "4px",
                }}
              >
                {blastRadius!.limitations.map((lim, i) => (
                  <p
                    key={i}
                    style={{
                      fontSize: "11px",
                      color: "#3a3e50",
                      fontStyle: "italic",
                      lineHeight: 1.5,
                      margin: i === 0 ? "0" : "4px 0 0",
                    }}
                  >
                    ℹ {lim}
                  </p>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </section>
  );
}
