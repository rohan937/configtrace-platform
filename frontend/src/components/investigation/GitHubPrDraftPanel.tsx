"use client";

/**
 * GitHubPrDraftPanel — M58.20.
 *
 * Displays a safe, read-only GitHub PR draft proposal derived from the
 * Terraform fix suggestion (M58.19).
 *
 * PERMANENT CONSTRAINTS:
 * - Never shows an enabled "Open PR" or "Create Branch" button.
 * - Never makes GitHub write API calls.
 * - Always shows the safety disclaimer ("ConfigTrace has not changed...").
 * - "Open PR" CTA is permanently disabled in M58.20.
 *
 * Supported copy actions:
 * - Copy PR body
 * - Copy branch name
 * - Copy patch preview
 */

import { useState } from "react";
import Link from "next/link";
import type { GitHubPrDraftResponse, GitHubPrDraftObject } from "@/types";

// ── Copy button ───────────────────────────────────────────────────────────────

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {});
  }

  return (
    <button
      onClick={handleCopy}
      style={{
        fontSize: "11px",
        color: copied ? "#3ccf7e" : "#4f80f7",
        background: "none",
        border: `1px solid ${copied ? "rgba(60,207,126,0.3)" : "rgba(79,128,247,0.3)"}`,
        borderRadius: "4px",
        padding: "3px 9px",
        cursor: "pointer",
        fontFamily: "inherit",
        transition: "color 0.15s, border-color 0.15s",
      }}
    >
      {copied ? "Copied!" : label}
    </button>
  );
}

// ── Code block ────────────────────────────────────────────────────────────────

function CodeBlock({
  content,
  isDiff = false,
  maxHeight = 200,
}: {
  content: string;
  isDiff?: boolean;
  maxHeight?: number;
}) {
  return (
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
        overflowY: "auto",
        maxHeight: `${maxHeight}px`,
        margin: 0,
        lineHeight: 1.7,
        whiteSpace: "pre",
      }}
    >
      {isDiff
        ? content.split("\n").map((line, i) => {
            const added = line.startsWith("+");
            const removed = line.startsWith("-");
            return (
              <span
                key={i}
                style={{
                  display: "block",
                  color: added ? "#3ccf7e" : removed ? "#f5632a" : "#c4c8d4",
                  background: added
                    ? "rgba(60,207,126,0.05)"
                    : removed
                    ? "rgba(245,99,42,0.05)"
                    : "transparent",
                }}
              >
                {line}
              </span>
            );
          })
        : content}
    </pre>
  );
}

// ── Label chip ────────────────────────────────────────────────────────────────

function LabelChip({ label }: { label: string }) {
  const colors: Record<string, { bg: string; border: string; text: string }> = {
    configtrace: { bg: "#0e1120", border: "#252a42", text: "#4f80f7" },
    security:    { bg: "#1c1508", border: "#3d2e06", text: "#f5a623" },
    terraform:   { bg: "#0d1f12", border: "#1a4028", text: "#3ccf7e" },
  };
  const style = colors[label] ?? { bg: "#0e1120", border: "#252a42", text: "#8b90a0" };

  return (
    <span
      style={{
        fontSize: "10px",
        fontWeight: 600,
        color: style.text,
        background: style.bg,
        border: `1px solid ${style.border}`,
        borderRadius: "10px",
        padding: "2px 8px",
        marginRight: "5px",
        display: "inline-block",
      }}
    >
      {label}
    </span>
  );
}

// ── Section label ─────────────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
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
      {children}
    </p>
  );
}

// ── Draft content ─────────────────────────────────────────────────────────────

function DraftContent({ draft, mode }: { draft: GitHubPrDraftObject; mode: string }) {
  const isOutline = mode === "outline_only";

  return (
    <div>
      {/* Outline-only notice */}
      {isOutline && (
        <div
          style={{
            background: "#1c1508",
            border: "1px solid #3d2e06",
            borderRadius: "5px",
            padding: "8px 12px",
            marginBottom: "14px",
            display: "flex",
            gap: "8px",
          }}
        >
          <span style={{ fontSize: "12px", flexShrink: 0 }}>⚠</span>
          <p style={{ margin: 0, fontSize: "11px", color: "#f5a623", lineHeight: 1.5 }}>
            Outline only — patch preview is not available for this draft (low IaC
            mapping confidence). Use the guidance in the Terraform fix preview to
            update the target file manually.
          </p>
        </div>
      )}

      {/* Branch name */}
      <div style={{ marginBottom: "12px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "4px" }}>
          <SectionLabel>Suggested branch name</SectionLabel>
          <CopyButton text={draft.branch_name} label="Copy branch" />
        </div>
        <code
          style={{
            display: "block",
            background: "#0a0c10",
            border: "1px solid #1e2130",
            borderRadius: "4px",
            padding: "6px 10px",
            fontSize: "12px",
            fontFamily: "monospace",
            color: "#4f80f7",
          }}
        >
          {draft.branch_name}
        </code>
      </div>

      {/* Commit message */}
      <div style={{ marginBottom: "12px" }}>
        <SectionLabel>Commit message</SectionLabel>
        <code
          style={{
            display: "block",
            background: "#0a0c10",
            border: "1px solid #1e2130",
            borderRadius: "4px",
            padding: "6px 10px",
            fontSize: "12px",
            fontFamily: "monospace",
            color: "#c4c8d4",
          }}
        >
          {draft.commit_message}
        </code>
      </div>

      {/* PR title */}
      <div style={{ marginBottom: "12px" }}>
        <SectionLabel>PR title</SectionLabel>
        <p
          style={{
            margin: 0,
            fontSize: "13px",
            color: "#c4c8d4",
            fontWeight: 500,
            background: "#0a0c10",
            border: "1px solid #1e2130",
            borderRadius: "4px",
            padding: "7px 10px",
          }}
        >
          {draft.pr_title}
        </p>
      </div>

      {/* Labels */}
      {draft.labels && draft.labels.length > 0 && (
        <div style={{ marginBottom: "12px" }}>
          <SectionLabel>Labels</SectionLabel>
          <div>
            {draft.labels.map((l) => (
              <LabelChip key={l} label={l} />
            ))}
          </div>
          <p style={{ margin: "4px 0 0", fontSize: "10px", color: "#3a3d4a", fontStyle: "italic" }}>
            Labels are static suggestions — no GitHub label creation occurs in this milestone.
          </p>
        </div>
      )}

      {/* Patch preview */}
      {draft.patch_preview && (
        <div style={{ marginBottom: "12px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "4px" }}>
            <SectionLabel>Patch preview</SectionLabel>
            <CopyButton text={draft.patch_preview} label="Copy patch" />
          </div>
          <CodeBlock content={draft.patch_preview} isDiff maxHeight={180} />
        </div>
      )}

      {/* PR body */}
      <div style={{ marginBottom: "12px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "4px" }}>
          <SectionLabel>PR body (markdown)</SectionLabel>
          <CopyButton text={draft.pr_body} label="Copy PR body" />
        </div>
        <CodeBlock content={draft.pr_body} maxHeight={220} />
      </div>

      {/* Review notes */}
      {draft.review_notes && draft.review_notes.length > 0 && (
        <div style={{ marginBottom: "10px" }}>
          <SectionLabel>Pre-merge checklist</SectionLabel>
          <ul style={{ margin: 0, padding: "0 0 0 16px", fontSize: "12px", color: "#8b90a0", lineHeight: 1.8 }}>
            {draft.review_notes.map((note, i) => (
              <li key={i}>{note}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Disabled "Open PR" CTA */}
      <div
        style={{
          marginTop: "14px",
          padding: "12px 14px",
          background: "#0e1120",
          border: "1px solid #252a42",
          borderRadius: "5px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <button
            disabled
            style={{
              background: "#1a1d28",
              color: "#3a3d4a",
              border: "1px solid #252a42",
              borderRadius: "5px",
              padding: "7px 14px",
              fontSize: "12px",
              cursor: "not-allowed",
              fontFamily: "inherit",
            }}
          >
            Open PR — coming in M58.21
          </button>
          <p style={{ margin: 0, fontSize: "11px", color: "#565b6e" }}>
            Actual PR creation is disabled in this milestone.
          </p>
        </div>
      </div>
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

interface GitHubPrDraftPanelProps {
  data: GitHubPrDraftResponse | null;
  loading?: boolean;
}

export default function GitHubPrDraftPanel({
  data,
  loading = false,
}: GitHubPrDraftPanelProps) {
  return (
    <section aria-labelledby="section-github-pr-draft" id="github-pr-draft">
      <h2
        id="section-github-pr-draft"
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          margin: "0 0 8px",
          fontWeight: 500,
        }}
      >
        GitHub PR draft
      </h2>

      <div
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "6px",
          padding: "16px 18px",
        }}
      >
        {/* Loading */}
        {loading && (
          <p style={{ fontSize: "12px", color: "#565b6e", margin: 0 }}>
            Preparing GitHub PR draft…
          </p>
        )}

        {/* No data */}
        {!loading && !data && (
          <p style={{ fontSize: "12px", color: "#565b6e", margin: 0 }}>
            GitHub PR draft unavailable.
          </p>
        )}

        {/* Unavailable */}
        {!loading && data && !data.available && (
          <div>
            <p style={{ fontSize: "12px", color: "#8b90a0", margin: "0 0 10px", lineHeight: 1.6 }}>
              {data.reason || "No GitHub PR draft is available for this change yet."}
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
        {!loading && data && data.available && data.draft && (
          <div>
            {/* Title + summary */}
            <p style={{ margin: "0 0 4px", fontSize: "13px", color: "#c4c8d4", fontWeight: 600 }}>
              {data.title ?? "GitHub PR draft suggestion"}
            </p>
            {data.summary && (
              <p style={{ fontSize: "12px", color: "#8b90a0", margin: "0 0 12px", lineHeight: 1.6 }}>
                {data.summary}
              </p>
            )}

            {/* Repo info */}
            {data.repo && (
              <div
                style={{
                  background: "#0e1120",
                  border: "1px solid #252a42",
                  borderRadius: "5px",
                  padding: "8px 12px",
                  marginBottom: "14px",
                  fontSize: "12px",
                  color: "#8b90a0",
                }}
              >
                <span style={{ color: "#4f80f7", fontFamily: "monospace" }}>
                  {data.repo.repo_full_name}
                </span>
                <span style={{ color: "#565b6e" }}>
                  {" "}→ {data.repo.default_branch} → {data.repo.file_path}
                </span>
              </div>
            )}

            {/* Safety banner */}
            <div
              style={{
                background: "#0d1f12",
                border: "1px solid #1a4028",
                borderRadius: "5px",
                padding: "8px 12px",
                marginBottom: "14px",
              }}
            >
              <p style={{ margin: 0, fontSize: "11px", color: "#3ccf7e", lineHeight: 1.5 }}>
                ✓ ConfigTrace does not create branches, commits, or pull requests in
                this milestone. This is a draft preview only.
              </p>
            </div>

            {/* Draft content */}
            <DraftContent draft={data.draft} mode={data.mode} />

            {/* Next step */}
            {data.next_step && (
              <p style={{ margin: "12px 0 0", fontSize: "11px", color: "#565b6e", lineHeight: 1.5 }}>
                {data.next_step}
              </p>
            )}

            {/* Footer disclaimer */}
            <p style={{ fontSize: "10px", color: "#3a3d4a", margin: "10px 0 0" }}>
              GitHub PR drafts are advisory only — ConfigTrace does not create branches,
              commits, or pull requests. All changes require human review and approval.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
