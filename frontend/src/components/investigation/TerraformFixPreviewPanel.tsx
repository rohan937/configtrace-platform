"use client";

/**
 * TerraformFixPreviewPanel — M58.19.
 *
 * Displays an advisory Terraform fix suggestion preview for a change.
 * All content is read-only and conceptual — no Terraform is ever executed,
 * no GitHub PRs are created, no provider resources are mutated.
 *
 * PERMANENT LANGUAGE CONSTRAINTS:
 * - Uses "conceptual preview", "possible fix", "may manage"
 * - Never claims exact Terraform ownership unless match_confidence == "high"
 * - Always shows the "requires_human_review" safety level
 * - Always shows "Run terraform plan" before apply
 * - execution_enabled and pr_available are always false — never display
 *   "Apply", "Create PR", or "Auto-fix" affordances
 */

import Link from "next/link";
import type {
  TerraformFixPreviewResponse,
  TerraformFixSuggestion,
  TerraformFixPlaceholder,
} from "@/types";

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

// ── Placeholder chip ──────────────────────────────────────────────────────────

function PlaceholderChip({ ph }: { ph: TerraformFixPlaceholder }) {
  return (
    <div
      style={{
        background: "#0e1120",
        border: "1px solid #252a42",
        borderRadius: "5px",
        padding: "7px 10px",
        marginBottom: "6px",
      }}
    >
      <p style={{ margin: "0 0 2px", fontSize: "11px", color: "#4f80f7", fontFamily: "monospace", fontWeight: 600 }}>
        &lt;{ph.name}&gt;
      </p>
      <p style={{ margin: "0 0 2px", fontSize: "11px", color: "#8b90a0", lineHeight: 1.5 }}>
        {ph.description}
      </p>
      <p style={{ margin: 0, fontSize: "11px", color: "#565b6e" }}>
        Example:{" "}
        <code style={{ fontFamily: "monospace", color: "#c4c8d4", fontSize: "10px" }}>
          {ph.example}
        </code>
      </p>
    </div>
  );
}

// ── Single suggestion card ────────────────────────────────────────────────────

function SuggestionCard({ suggestion }: { suggestion: TerraformFixSuggestion }) {
  const isGuidance = suggestion.kind === "guidance_only";

  return (
    <div
      style={{
        background: "#0d0f14",
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        padding: "14px 16px",
        marginBottom: "10px",
      }}
    >
      {/* Title + safety badge */}
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: "10px",
          marginBottom: "8px",
        }}
      >
        <p style={{ margin: 0, fontSize: "13px", color: "#c4c8d4", fontWeight: 500 }}>
          {suggestion.title}
        </p>
        <span
          style={{
            fontSize: "10px",
            color: "#f5a623",
            background: "#1c1508",
            border: "1px solid #3d2e06",
            borderRadius: "10px",
            padding: "2px 7px",
            flexShrink: 0,
            fontWeight: 600,
            textTransform: "uppercase",
            letterSpacing: "0.04em",
          }}
        >
          Requires human review
        </span>
      </div>

      {/* Description */}
      <p style={{ margin: "0 0 10px", fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
        {suggestion.description}
      </p>

      {/* HCL diff */}
      {!isGuidance && suggestion.diff && (
        <div style={{ marginBottom: "10px" }}>
          <p
            style={{
              fontSize: "10px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              margin: "0 0 6px",
              fontWeight: 600,
            }}
          >
            Conceptual diff
          </p>
          <pre
            style={{
              background: "#0a0c10",
              border: "1px solid #1e2130",
              borderRadius: "5px",
              padding: "10px 12px",
              fontSize: "11px",
              fontFamily: "monospace",
              color: "#c4c8d4",
              overflowX: "auto",
              margin: 0,
              lineHeight: 1.7,
              whiteSpace: "pre",
            }}
          >
            {suggestion.diff.split("\n").map((line, i) => {
              const added = line.startsWith("+");
              const removed = line.startsWith("-");
              return (
                <span
                  key={i}
                  style={{
                    display: "block",
                    color: added ? "#3ccf7e" : removed ? "#f5632a" : "#c4c8d4",
                    background: added ? "rgba(60,207,126,0.05)" : removed ? "rgba(245,99,42,0.05)" : "transparent",
                  }}
                >
                  {line}
                </span>
              );
            })}
          </pre>
        </div>
      )}

      {/* Placeholders */}
      {suggestion.placeholders && suggestion.placeholders.length > 0 && (
        <div style={{ marginBottom: "10px" }}>
          <p
            style={{
              fontSize: "10px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              margin: "0 0 6px",
              fontWeight: 600,
            }}
          >
            Placeholders to fill in
          </p>
          {suggestion.placeholders.map((ph) => (
            <PlaceholderChip key={ph.name} ph={ph} />
          ))}
        </div>
      )}

      {/* Warnings */}
      {suggestion.warnings && suggestion.warnings.length > 0 && (
        <div>
          {suggestion.warnings.map((w, i) => (
            <div
              key={i}
              style={{
                display: "flex",
                gap: "8px",
                alignItems: "flex-start",
                marginTop: i === 0 ? "0" : "4px",
              }}
            >
              <span style={{ fontSize: "11px", color: "#f5a623", flexShrink: 0 }}>⚠</span>
              <p style={{ margin: 0, fontSize: "11px", color: "#8b90a0", lineHeight: 1.5 }}>
                {w}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Mapping info row ──────────────────────────────────────────────────────────

function MappingInfoRow({ mapping }: { mapping: NonNullable<TerraformFixPreviewResponse["mapping"]> }) {
  return (
    <div
      style={{
        background: "#0e1120",
        border: "1px solid #252a42",
        borderRadius: "5px",
        padding: "10px 12px",
        marginBottom: "12px",
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "space-between",
        gap: "10px",
      }}
    >
      <div style={{ flex: 1, minWidth: 0 }}>
        {mapping.terraform_resource_type && (
          <p style={{ margin: "0 0 2px", fontSize: "12px", fontFamily: "monospace", color: "#4f80f7" }}>
            {mapping.terraform_resource_type}
            {mapping.terraform_resource_name && (
              <span style={{ color: "#8b90a0" }}> &quot;{mapping.terraform_resource_name}&quot;</span>
            )}
          </p>
        )}
        {mapping.repo_full_name && (
          <p style={{ margin: "2px 0 0", fontSize: "11px", color: "#8b90a0", fontFamily: "monospace" }}>
            {mapping.repo_full_name}
            {mapping.file_path && (
              <span style={{ color: "#565b6e" }}> / {mapping.file_path}</span>
            )}
          </p>
        )}
      </div>
      <ConfidenceBadge confidence={mapping.match_confidence} />
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

interface TerraformFixPreviewPanelProps {
  data: TerraformFixPreviewResponse | null;
  loading?: boolean;
}

export default function TerraformFixPreviewPanel({
  data,
  loading = false,
}: TerraformFixPreviewPanelProps) {
  return (
    <section aria-labelledby="section-terraform-fix" id="terraform-fix-preview">
      <h2
        id="section-terraform-fix"
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          margin: "0 0 8px",
          fontWeight: 500,
        }}
      >
        Terraform fix preview
      </h2>

      <div
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "6px",
          padding: "16px 18px",
        }}
      >
        {/* Loading state */}
        {loading && (
          <p style={{ fontSize: "12px", color: "#565b6e", margin: 0 }}>
            Checking for Terraform fix suggestions…
          </p>
        )}

        {/* No data */}
        {!loading && !data && (
          <p style={{ fontSize: "12px", color: "#565b6e", margin: 0 }}>
            Terraform fix suggestions unavailable.
          </p>
        )}

        {/* Unavailable */}
        {!loading && data && !data.available && (
          <div>
            <p style={{ fontSize: "12px", color: "#8b90a0", margin: "0 0 10px", lineHeight: 1.6 }}>
              {data.summary || "No Terraform fix suggestion available for this change."}
            </p>
            <Link
              href="/settings/workspace/iac"
              style={{ fontSize: "12px", color: "#4f80f7", textDecoration: "none" }}
            >
              Manage IaC repositories →
            </Link>
          </div>
        )}

        {/* Available */}
        {!loading && data && data.available && (
          <div>
            {/* Title + confidence */}
            <div
              style={{
                display: "flex",
                alignItems: "flex-start",
                justifyContent: "space-between",
                gap: "10px",
                marginBottom: "8px",
              }}
            >
              <p style={{ margin: 0, fontSize: "13px", color: "#c4c8d4", fontWeight: 600 }}>
                {data.title ?? "Terraform fix suggestion preview"}
              </p>
              {data.confidence && <ConfidenceBadge confidence={data.confidence} />}
            </div>

            {/* Summary */}
            {data.summary && (
              <p style={{ fontSize: "12px", color: "#8b90a0", margin: "0 0 12px", lineHeight: 1.6 }}>
                {data.summary}
              </p>
            )}

            {/* Mapping info */}
            {data.mapping && <MappingInfoRow mapping={data.mapping} />}

            {/* Suggestions */}
            {data.suggestions.length > 0 && (
              <div style={{ marginBottom: "12px" }}>
                {data.suggestions.map((s, i) => (
                  <SuggestionCard key={i} suggestion={s} />
                ))}
              </div>
            )}

            {/* Recommended workflow */}
            {data.recommended_workflow && data.recommended_workflow.length > 0 && (
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
                    fontSize: "10px",
                    color: "#565b6e",
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    margin: "0 0 8px",
                    fontWeight: 600,
                  }}
                >
                  Recommended workflow
                </p>
                <ol style={{ margin: 0, padding: "0 0 0 16px", fontSize: "12px", color: "#8b90a0", lineHeight: 1.8 }}>
                  {data.recommended_workflow.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              </div>
            )}

            {/* Footer: advisory disclaimer */}
            <p style={{ fontSize: "10px", color: "#3a3d4a", margin: 0 }}>
              Terraform fix suggestions are advisory only — ConfigTrace does not
              execute Terraform, create pull requests, or mutate provider resources.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
