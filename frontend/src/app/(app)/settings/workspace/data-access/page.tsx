"use client";

/**
 * Trust Center page — M58.12.
 *
 * Provider Trust Center at /settings/workspace/data-access.
 * Replaces the previous Data Access page with a first-class trust view.
 *
 * Sections:
 *   1. Page header + "Export security packet" button (window.print)
 *   2. Global trust summary cards
 *   3. Permission boundary table
 *   4. Per-provider collapsible trust profiles
 *   5. Footer disclaimer + manage team link
 *
 * Design rules:
 *   - No raw credential values, secret values, or API keys shown.
 *   - No compliance claims (SOC2 etc.) — describe only what the product does.
 *   - Language: "reads", "never reads", "encrypted at rest" — factual only.
 *   - Print export: window.print() + @media print CSS hides nav, inverts theme.
 */

import { useState } from "react";
import { useRouter } from "next/navigation";
import PageHeader from "@/components/common/PageHeader";
import { PROVIDERS, PROVIDER_IDS } from "@/lib/providers";
import {
  TRUST_PROFILES,
  TRUST_SUMMARY,
  PERMISSION_BOUNDARY,
} from "@/lib/trustCenter";

// ── Summary cards ─────────────────────────────────────────────────────────────

const SUMMARY_CARDS = [
  {
    value: `${TRUST_SUMMARY.provider_count}`,
    label: "Providers monitored",
    color: "#4f80f7",
    icon: "🔌",
  },
  {
    value: TRUST_SUMMARY.access_type,
    label: "API access type",
    color: "#3ccf7e",
    icon: "🔒",
  },
  {
    value: "Zero",
    label: "Secrets stored in plaintext",
    color: "#f5a623",
    icon: "🗝",
  },
  {
    value: "None",
    label: "Customer data accessed",
    color: "#8b90a0",
    icon: "🛡",
  },
] as const;

function SummaryCard({
  value,
  label,
  color,
  icon,
}: {
  value: string;
  label: string;
  color: string;
  icon: string;
}) {
  return (
    <div
      style={{
        background: "#13151a",
        border: `1px solid ${color}22`,
        borderRadius: "8px",
        padding: "16px",
        flex: "1 1 140px",
        minWidth: 0,
      }}
    >
      <div style={{ fontSize: "18px", marginBottom: "6px" }} aria-hidden="true">
        {icon}
      </div>
      <p
        style={{
          margin: "0 0 3px",
          fontSize: "16px",
          fontWeight: 700,
          color,
          lineHeight: 1.2,
        }}
      >
        {value}
      </p>
      <p style={{ margin: 0, fontSize: "11px", color: "#565b6e", lineHeight: 1.4 }}>
        {label}
      </p>
    </div>
  );
}

// ── Permission boundary ───────────────────────────────────────────────────────

function PermissionBoundaryTable() {
  return (
    <section
      aria-labelledby="section-boundary"
      style={{
        background: "#13151a",
        border: "1px solid #2a2d38",
        borderRadius: "8px",
        marginBottom: "24px",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          padding: "14px 20px",
          borderBottom: "1px solid #2a2d38",
          background: "#0f1117",
        }}
      >
        <h2
          id="section-boundary"
          style={{
            margin: 0,
            fontSize: "13px",
            fontWeight: 600,
            color: "#c4c8d4",
          }}
        >
          Permission boundary
        </h2>
        <p style={{ margin: "3px 0 0", fontSize: "12px", color: "#565b6e" }}>
          Hard limits enforced by read-only API scopes and IAM policies.
        </p>
      </div>

      <div style={{ padding: "4px 0" }}>
        {PERMISSION_BOUNDARY.map((row, i) => (
          <div
            key={i}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "14px",
              padding: "10px 20px",
              borderBottom:
                i < PERMISSION_BOUNDARY.length - 1
                  ? "1px solid #1a1d26"
                  : "none",
            }}
          >
            {/* Permitted indicator */}
            <span
              aria-label={row.permitted ? "Permitted" : "Blocked"}
              style={{
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                width: "20px",
                height: "20px",
                borderRadius: "50%",
                fontSize: "11px",
                fontWeight: 700,
                flexShrink: 0,
                background: row.permitted
                  ? "rgba(60,207,126,0.12)"
                  : "rgba(248,113,113,0.10)",
                color: row.permitted ? "#3ccf7e" : "#f87171",
                border: `1px solid ${row.permitted ? "#3ccf7e33" : "#f8717133"}`,
              }}
            >
              {row.permitted ? "✓" : "✕"}
            </span>

            {/* Action label */}
            <span
              style={{
                flex: 1,
                fontSize: "13px",
                color: "#c4c8d4",
                fontWeight: 500,
              }}
            >
              {row.action}
            </span>

            {/* Note */}
            <span
              style={{
                fontSize: "11px",
                color: "#3a3e50",
                fontStyle: "italic",
                textAlign: "right",
                maxWidth: "260px",
              }}
            >
              {row.note}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

// ── Provider trust card ───────────────────────────────────────────────────────

function ProviderTrustCard({ pid }: { pid: string }) {
  const [open, setOpen] = useState(false);
  const meta    = PROVIDERS[pid as keyof typeof PROVIDERS];
  const profile = TRUST_PROFILES[pid as keyof typeof TRUST_PROFILES];
  if (!meta || !profile) return null;

  return (
    <section
      aria-labelledby={`tc-provider-${pid}`}
      className="trust-provider-card"
      style={{
        background: "#13151a",
        border: "1px solid #2a2d38",
        borderRadius: "8px",
        marginBottom: "10px",
        overflow: "hidden",
      }}
    >
      {/* Provider header (toggle) */}
      <button
        aria-expanded={open}
        aria-controls={`tc-details-${pid}`}
        onClick={() => setOpen((v) => !v)}
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          gap: "10px",
          padding: "13px 18px",
          background: open ? "#0f1117" : "transparent",
          border: "none",
          borderBottom: open ? "1px solid #2a2d38" : "none",
          cursor: "pointer",
          textAlign: "left",
          fontFamily: "inherit",
        }}
      >
        {/* Color dot */}
        <span
          aria-hidden="true"
          style={{
            flexShrink: 0,
            display: "inline-block",
            width: "8px",
            height: "8px",
            borderRadius: "50%",
            background: meta.color,
          }}
        />

        {/* Provider name */}
        <span
          id={`tc-provider-${pid}`}
          style={{
            flex: 1,
            fontSize: "13px",
            fontWeight: 600,
            color: meta.color,
          }}
        >
          {meta.label}
        </span>

        {/* Category badge */}
        <span
          style={{
            fontSize: "10px",
            color: "#3a3e50",
            letterSpacing: "0.04em",
            textTransform: "uppercase",
          }}
        >
          {meta.category.replace(/_/g, " ")}
        </span>

        {/* Read-only badge */}
        <span
          style={{
            fontSize: "10px",
            color: "#3ccf7e",
            border: "1px solid #3ccf7e22",
            borderRadius: "4px",
            padding: "1px 6px",
          }}
        >
          Read-only
        </span>

        {/* Chevron */}
        <span
          aria-hidden="true"
          style={{
            fontSize: "11px",
            color: "#3a3e50",
            transform: open ? "rotate(180deg)" : "rotate(0deg)",
            transition: "transform 0.15s ease",
            marginLeft: "4px",
          }}
        >
          ▾
        </span>
      </button>

      {/* Detail panel */}
      <div
        id={`tc-details-${pid}`}
        className="trust-provider-details"
        style={{
          display: open ? "block" : "none",
          padding: "16px 18px",
        }}
      >
        {/* Reads / Never reads — two columns */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "20px",
            marginBottom: "18px",
          }}
        >
          {/* Reads */}
          <div>
            <p
              style={{
                margin: "0 0 8px",
                fontSize: "10px",
                fontWeight: 600,
                color: "#3ccf7e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
              }}
            >
              Reads
            </p>
            <ul role="list" style={{ margin: 0, padding: 0, listStyle: "none" }}>
              {profile.reads.map((item) => (
                <li
                  key={item}
                  style={{
                    fontSize: "12px",
                    color: "#c4c8d4",
                    padding: "3px 0 3px 16px",
                    position: "relative",
                    lineHeight: 1.55,
                  }}
                >
                  <span
                    aria-hidden="true"
                    style={{
                      position: "absolute",
                      left: 0,
                      top: "3px",
                      color: "#3ccf7e",
                      fontSize: "11px",
                    }}
                  >
                    ✓
                  </span>
                  {item}
                </li>
              ))}
            </ul>
          </div>

          {/* Never reads */}
          <div>
            <p
              style={{
                margin: "0 0 8px",
                fontSize: "10px",
                fontWeight: 600,
                color: "#f87171",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
              }}
            >
              Never reads
            </p>
            <ul role="list" style={{ margin: 0, padding: 0, listStyle: "none" }}>
              {profile.never_reads.map((item) => (
                <li
                  key={item}
                  style={{
                    fontSize: "12px",
                    color: "#8b90a0",
                    padding: "3px 0 3px 16px",
                    position: "relative",
                    lineHeight: 1.55,
                  }}
                >
                  <span
                    aria-hidden="true"
                    style={{
                      position: "absolute",
                      left: 0,
                      top: "3px",
                      color: "#f87171",
                      fontSize: "11px",
                    }}
                  >
                    ✕
                  </span>
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Credential note */}
        <div
          style={{
            background: "rgba(79,128,247,0.05)",
            border: "1px solid rgba(79,128,247,0.15)",
            borderRadius: "5px",
            padding: "10px 14px",
            marginBottom: "16px",
          }}
        >
          <p
            style={{
              margin: "0 0 2px",
              fontSize: "10px",
              fontWeight: 600,
              color: "#4f80f7",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
            }}
          >
            Credential storage
          </p>
          <p style={{ margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
            {profile.credential_note}
          </p>
        </div>

        {/* Permissions + Revoke steps — two columns */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "20px",
          }}
        >
          {/* Permissions */}
          <div>
            <p
              style={{
                margin: "0 0 8px",
                fontSize: "10px",
                fontWeight: 600,
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
              }}
            >
              Permissions / scopes
            </p>
            <ul role="list" style={{ margin: 0, padding: 0, listStyle: "none" }}>
              {profile.permissions.map((perm) => (
                <li
                  key={perm}
                  style={{
                    fontSize: "11px",
                    color: "#565b6e",
                    background: "#0e0f11",
                    border: "1px solid #1e2030",
                    borderRadius: "3px",
                    padding: "3px 8px",
                    marginBottom: "4px",
                    lineHeight: 1.5,
                    fontFamily: "monospace",
                    wordBreak: "break-word",
                  }}
                >
                  {perm}
                </li>
              ))}
            </ul>
          </div>

          {/* Revoke steps */}
          <div>
            <p
              style={{
                margin: "0 0 8px",
                fontSize: "10px",
                fontWeight: 600,
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
              }}
            >
              How to revoke access
            </p>
            <ol
              role="list"
              style={{ margin: 0, padding: 0, listStyle: "none", counterReset: "revoke-step" }}
            >
              {profile.revoke_steps.map((step, i) => (
                <li
                  key={i}
                  style={{
                    fontSize: "12px",
                    color: "#8b90a0",
                    padding: "3px 0 3px 22px",
                    position: "relative",
                    lineHeight: 1.55,
                  }}
                >
                  <span
                    aria-hidden="true"
                    style={{
                      position: "absolute",
                      left: 0,
                      top: "3px",
                      fontSize: "10px",
                      color: "#3a3e50",
                      fontWeight: 600,
                      width: "16px",
                      textAlign: "center",
                    }}
                  >
                    {i + 1}.
                  </span>
                  {step}
                </li>
              ))}
            </ol>
          </div>
        </div>

        {/* Remediation note */}
        {profile.remediation_supported && (
          <p
            style={{
              margin: "14px 0 0",
              paddingTop: "12px",
              borderTop: "1px solid #1a1d26",
              fontSize: "11px",
              color: "#3a3e50",
              fontStyle: "italic",
              lineHeight: 1.5,
            }}
          >
            ℹ ConfigTrace can surface remediation recommendations for this provider. It never applies
            them automatically — all changes require human review and are made directly in the
            provider console.
          </p>
        )}
      </div>
    </section>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function TrustCenterPage() {
  const router = useRouter();

  function handleExportPacket() {
    window.print();
  }

  return (
    <>
      <PageHeader
        title="Trust Center"
        description="How ConfigTrace accesses your providers, what it reads, and how to revoke access."
      />

      {/* Print-only header (hidden on screen) */}
      <div
        className="print-only"
        style={{ display: "none" }}
        aria-hidden="true"
      >
        <div
          style={{
            borderBottom: "2px solid #111",
            paddingBottom: "12px",
            marginBottom: "20px",
          }}
        >
          <h1 style={{ margin: 0, fontSize: "20px", color: "#111" }}>
            ConfigTrace — Security Packet
          </h1>
          <p style={{ margin: "4px 0 0", fontSize: "13px", color: "#555" }}>
            Provider Trust Center export · Generated{" "}
            {new Date().toLocaleDateString("en-US", {
              year: "numeric",
              month: "long",
              day: "numeric",
            })}
          </p>
        </div>
      </div>

      <div className="px-6 pb-12" style={{ maxWidth: "780px" }}>
        {/* Back link — hidden on print */}
        <button
          className="no-print"
          onClick={() => router.back()}
          aria-label="Back to Workspace"
          style={{
            background: "none",
            border: "none",
            color: "#8b90a0",
            cursor: "pointer",
            fontSize: "13px",
            padding: "0 0 20px 0",
            display: "flex",
            alignItems: "center",
            gap: "6px",
            fontFamily: "inherit",
          }}
        >
          ← Back to Workspace
        </button>

        {/* ── Export button ────────────────────────────────────────── */}
        <div
          className="no-print"
          style={{
            display: "flex",
            justifyContent: "flex-end",
            marginBottom: "24px",
          }}
        >
          <button
            onClick={handleExportPacket}
            style={{
              fontSize: "13px",
              color: "#4f80f7",
              background: "rgba(79,128,247,0.08)",
              border: "1px solid rgba(79,128,247,0.30)",
              borderRadius: "6px",
              padding: "7px 16px",
              cursor: "pointer",
              fontFamily: "inherit",
              display: "flex",
              alignItems: "center",
              gap: "6px",
            }}
          >
            <span aria-hidden="true">⎙</span>
            Export security packet
          </button>
        </div>

        {/* ── Summary cards ────────────────────────────────────────── */}
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: "10px",
            marginBottom: "24px",
          }}
        >
          {SUMMARY_CARDS.map((card) => (
            <SummaryCard key={card.label} {...card} />
          ))}
        </div>

        {/* ── Global access callout ─────────────────────────────────── */}
        <div
          role="note"
          style={{
            background: "rgba(79,128,247,0.06)",
            border: "1px solid rgba(79,128,247,0.20)",
            borderRadius: "8px",
            padding: "14px 18px",
            marginBottom: "24px",
          }}
        >
          <p style={{ margin: 0, fontSize: "13px", color: "#c4c8d4", lineHeight: 1.7 }}>
            ConfigTrace uses <strong style={{ color: "#e8eaf0" }}>read-only</strong> API credentials
            to snapshot provider configuration on a schedule. It never writes to any provider,
            never reads customer data, and never stores secret values in plaintext. All credentials
            are encrypted at rest and never returned in API responses.
          </p>
        </div>

        {/* ── Permission boundary ───────────────────────────────────── */}
        <PermissionBoundaryTable />

        {/* ── Provider profiles header ─────────────────────────────── */}
        <h2
          style={{
            fontSize: "11px",
            color: "#565b6e",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            fontWeight: 500,
            margin: "0 0 12px",
          }}
        >
          Per-provider access profiles
        </h2>

        {/* ── Provider trust cards ──────────────────────────────────── */}
        {PROVIDER_IDS.map((pid) => (
          <ProviderTrustCard key={pid} pid={pid} />
        ))}

        {/* ── Footer ───────────────────────────────────────────────── */}
        <p
          style={{
            fontSize: "12px",
            color: "#565b6e",
            lineHeight: 1.7,
            marginTop: "16px",
          }}
        >
          Credentials are encrypted at rest and enforced by read-only IAM policies, fine-grained
          PATs, and restricted API keys. Credentials are never returned in API responses or exports.{" "}
          <button
            className="no-print"
            onClick={() => router.push("/settings/workspace/members")}
            style={{
              background: "none",
              border: "none",
              color: "#4f80f7",
              cursor: "pointer",
              fontSize: "12px",
              padding: 0,
              fontFamily: "inherit",
            }}
          >
            Manage team access →
          </button>
        </p>
      </div>

      {/* ── @media print styles ──────────────────────────────────────── */}
      <style>{`
        @media print {
          /* Hide navigation and interactive elements */
          aside,
          .no-print,
          header nav,
          [data-clerk-component] { display: none !important; }

          /* Show print-only content */
          .print-only { display: block !important; }

          /* Force light background */
          body, html { background: #fff !important; color: #111 !important; }

          /* Expand all provider detail panels */
          .trust-provider-details { display: block !important; }

          /* Fix card backgrounds for print */
          section, div, [style] {
            background: transparent !important;
            color: #111 !important;
            border-color: #ccc !important;
          }

          /* Keep trust green / red indicators visible */
          span[aria-label="Permitted"] { color: #16a34a !important; }
          span[aria-label="Blocked"]   { color: #dc2626 !important; }

          /* Avoid page breaks inside provider cards */
          .trust-provider-card { page-break-inside: avoid; }

          /* Remove box shadows */
          * { box-shadow: none !important; }
        }
      `}</style>
    </>
  );
}
