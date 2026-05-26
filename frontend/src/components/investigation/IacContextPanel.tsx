"use client";

/**
 * IacContextPanel — M58.18.
 *
 * Displays advisory IaC context for a change: whether any registered Terraform
 * resources may correspond to the changed cloud resource.
 *
 * Language contract (permanent):
 * - Uses "may be managed by Terraform", "possible IaC mapping"
 * - Never claims definite Terraform ownership unless match_confidence == "high"
 * - Advisory only — not a Terraform confirmation, not a compliance statement
 * - future_fix_available is always false in M58.18 (Terraform patch in M58.19)
 */

import Link from "next/link";
import type { IacContextResponse, IacChangeMappingCandidate } from "@/types";

// ── Confidence badge ──────────────────────────────────────────────────────────

const CONFIDENCE_STYLE: Record<string, { bg: string; border: string; text: string; label: string }> = {
  high:   { bg: "#0d1f12", border: "#1a4028", text: "#3ccf7e", label: "High confidence" },
  medium: { bg: "#1c1508", border: "#3d2e06", text: "#f5a623", label: "Medium confidence" },
  low:    { bg: "#0e1120", border: "#252a42", text: "#8b90a0", label: "Low confidence" },
};

function ConfidenceBadge({ confidence }: { confidence: string }) {
  const style = CONFIDENCE_STYLE[confidence] ?? CONFIDENCE_STYLE.low;
  return (
    <span
      style={{
        fontSize: "10px",
        fontWeight: 600,
        textTransform: "uppercase",
        letterSpacing: "0.05em",
        color: style.text,
        background: style.bg,
        border: `1px solid ${style.border}`,
        borderRadius: "10px",
        padding: "2px 7px",
        flexShrink: 0,
      }}
    >
      {style.label}
    </span>
  );
}

// ── Single mapping candidate row ──────────────────────────────────────────────

function MappingCandidateRow({ candidate }: { candidate: IacChangeMappingCandidate }) {
  const fileLabel = candidate.line_start
    ? `${candidate.file_path}:${candidate.line_start}`
    : candidate.file_path;

  return (
    <div
      style={{
        padding: "10px 0",
        borderBottom: "1px solid #1e2130",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: "8px",
          marginBottom: "4px",
        }}
      >
        <div style={{ flex: 1 }}>
          {/* Resource type + name */}
          <p style={{ margin: 0, fontSize: "12px", color: "#c4c8d4", fontWeight: 500 }}>
            <span style={{ color: "#4f80f7", fontFamily: "monospace" }}>
              {candidate.terraform_resource_type ?? "unknown"}
            </span>
            {candidate.terraform_resource_name && (
              <span style={{ color: "#8b90a0", fontFamily: "monospace" }}>
                {" "}&quot;{candidate.terraform_resource_name}&quot;
              </span>
            )}
          </p>
          {/* File path */}
          <p style={{ margin: "2px 0 0", fontSize: "11px", color: "#565b6e", fontFamily: "monospace" }}>
            {candidate.repo_full_name && (
              <span style={{ color: "#8b90a0" }}>{candidate.repo_full_name} / </span>
            )}
            {fileLabel}
          </p>
        </div>
        <ConfidenceBadge confidence={candidate.match_confidence} />
      </div>
      {/* Match reason */}
      <p style={{ margin: "4px 0 0", fontSize: "11px", color: "#565b6e", lineHeight: 1.5 }}>
        {candidate.match_reason}
      </p>
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

interface IacContextPanelProps {
  data: IacContextResponse | null;
  loading?: boolean;
}

export default function IacContextPanel({
  data,
  loading = false,
}: IacContextPanelProps) {
  const isAvailable = data?.available === true;

  return (
    <section aria-labelledby="section-iac-context" id="iac-context">
      <h2
        id="section-iac-context"
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          margin: "0 0 8px",
          fontWeight: 500,
        }}
      >
        Infrastructure-as-Code context
      </h2>

      <div
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "6px",
          padding: "16px 18px",
        }}
      >
        {loading && (
          <p style={{ fontSize: "12px", color: "#565b6e", margin: 0 }}>
            Checking IaC mappings…
          </p>
        )}

        {!loading && !data && (
          <p style={{ fontSize: "12px", color: "#565b6e", margin: 0 }}>
            IaC context unavailable.
          </p>
        )}

        {!loading && data && !isAvailable && (
          <div>
            <p style={{ fontSize: "12px", color: "#8b90a0", margin: 0, lineHeight: 1.6 }}>
              {data.summary}
            </p>
            {data.future_fix_note && (
              <p
                style={{
                  fontSize: "11px",
                  color: "#565b6e",
                  margin: "8px 0 0",
                  fontStyle: "italic",
                }}
              >
                {data.future_fix_note}
              </p>
            )}
            <div style={{ marginTop: "10px" }}>
              <Link
                href="/settings/workspace/iac"
                style={{ fontSize: "12px", color: "#4f80f7", textDecoration: "none" }}
              >
                Manage IaC repositories →
              </Link>
            </div>
          </div>
        )}

        {!loading && data && isAvailable && (
          <div>
            {/* Summary */}
            <p style={{ fontSize: "12px", color: "#c4c8d4", margin: "0 0 12px", lineHeight: 1.6 }}>
              {data.summary}
            </p>

            {/* Warning banner */}
            <div
              style={{
                background: "#1c1508",
                border: "1px solid #3d2e06",
                borderRadius: "5px",
                padding: "8px 12px",
                marginBottom: "12px",
                display: "flex",
                gap: "8px",
                alignItems: "flex-start",
              }}
            >
              <span style={{ fontSize: "13px", flexShrink: 0 }}>⚠</span>
              <p style={{ fontSize: "11px", color: "#f5a623", margin: 0, lineHeight: 1.5 }}>
                Avoid manually changing provider settings if this resource may be managed
                by Terraform — the next <code style={{ fontFamily: "monospace" }}>terraform apply</code> may
                overwrite manual changes.
              </p>
            </div>

            {/* Mapping candidates */}
            <div style={{ marginBottom: "12px" }}>
              {data.mappings.map((candidate) => (
                <MappingCandidateRow key={candidate.mapping_id} candidate={candidate} />
              ))}
            </div>

            {/* Recommended workflow */}
            {data.recommended_workflow && (
              <div
                style={{
                  background: "#0e1120",
                  border: "1px solid #252a42",
                  borderRadius: "5px",
                  padding: "10px 12px",
                  marginBottom: "10px",
                }}
              >
                <p
                  style={{
                    fontSize: "11px",
                    color: "#565b6e",
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    margin: "0 0 6px",
                    fontWeight: 600,
                  }}
                >
                  Recommended workflow
                </p>
                <p style={{ fontSize: "12px", color: "#8b90a0", margin: 0, lineHeight: 1.6 }}>
                  {data.recommended_workflow}
                </p>
              </div>
            )}

            {/* Future fix note */}
            {data.future_fix_note && (
              <p style={{ fontSize: "11px", color: "#565b6e", margin: "0 0 8px", fontStyle: "italic" }}>
                {data.future_fix_note}
              </p>
            )}

            {/* Footer: advisory disclaimer */}
            <p style={{ fontSize: "10px", color: "#3a3d4a", margin: 0 }}>
              IaC mapping is advisory only — ConfigTrace does not confirm Terraform ownership
              or execute any infrastructure changes.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
