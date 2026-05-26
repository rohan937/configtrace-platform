"use client";

/**
 * GitHubPrDraftPanel — M58.20 / M58.21.
 *
 * Displays a GitHub PR draft proposal derived from the Terraform fix suggestion
 * (M58.19) and allows creating an actual GitHub draft PR (M58.21).
 *
 * PERMANENT CONSTRAINTS:
 * - Always shows the safety disclaimer ("ConfigTrace has not changed...").
 * - PR creation requires explicit "CREATE DRAFT PR" confirmation phrase.
 * - executes_terraform is always False — Terraform is never executed.
 * - mutates_provider_resource is always False — no provider resources are mutated.
 *
 * Supported copy actions:
 * - Copy PR body
 * - Copy branch name
 * - Copy patch preview
 */

import { useState } from "react";
import Link from "next/link";
import type {
  GitHubPrDraftResponse,
  GitHubPrDraftObject,
  GitHubPrCreateResponse,
} from "@/types";
import { createChangeGitHubPr } from "@/lib/api";

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

// ── PR creation form ──────────────────────────────────────────────────────────

const _CONFIRM_PHRASE = "CREATE DRAFT PR";

interface CreatePrFormProps {
  changeId: string;
  iacRepositoryId: string;
  defaultBaseBranch: string;
  hasPlaceholders: boolean;
  token?: string | null;
  onCreated: (result: GitHubPrCreateResponse) => void;
}

function CreatePrForm({
  changeId,
  iacRepositoryId,
  defaultBaseBranch,
  hasPlaceholders,
  token,
  onCreated,
}: CreatePrFormProps) {
  const [phrase, setPhrase] = useState("");
  const [baseBranch, setBaseBranch] = useState(defaultBaseBranch);
  const [ackPlaceholders, setAckPlaceholders] = useState(!hasPlaceholders);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit =
    phrase === _CONFIRM_PHRASE &&
    baseBranch.trim() !== "" &&
    (!hasPlaceholders || ackPlaceholders) &&
    !loading;

  async function handleCreate() {
    if (!canSubmit) return;
    setLoading(true);
    setError(null);
    try {
      const result = await createChangeGitHubPr(
        changeId,
        {
          confirmation_phrase: phrase,
          iac_repository_id: iacRepositoryId,
          target_base_branch: baseBranch.trim(),
          acknowledge_placeholders: ackPlaceholders,
        },
        token,
      );
      if (result.success) {
        onCreated(result);
      } else {
        setError(result.error ?? "PR creation failed. Please try again.");
      }
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "An unexpected error occurred.",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      style={{
        marginTop: "14px",
        padding: "14px 16px",
        background: "#0e1120",
        border: "1px solid #252a42",
        borderRadius: "5px",
      }}
    >
      <p style={{ margin: "0 0 10px", fontSize: "12px", color: "#8b90a0", fontWeight: 600 }}>
        Open Draft PR in GitHub
      </p>

      {/* Base branch */}
      <div style={{ marginBottom: "10px" }}>
        <label
          style={{
            display: "block",
            fontSize: "10px",
            color: "#565b6e",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            marginBottom: "4px",
            fontWeight: 600,
          }}
        >
          Base branch
        </label>
        <input
          type="text"
          value={baseBranch}
          onChange={(e) => setBaseBranch(e.target.value)}
          placeholder="main"
          style={{
            width: "100%",
            background: "#13151a",
            border: "1px solid #2a2d38",
            borderRadius: "4px",
            padding: "5px 8px",
            fontSize: "12px",
            color: "#c4c8d4",
            fontFamily: "monospace",
            boxSizing: "border-box",
          }}
        />
      </div>

      {/* Placeholder acknowledgement (shown only when fix has placeholders) */}
      {hasPlaceholders && (
        <div
          style={{
            marginBottom: "10px",
            padding: "8px 10px",
            background: "#1c1508",
            border: "1px solid #3d2e06",
            borderRadius: "4px",
          }}
        >
          <label
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: "8px",
              cursor: "pointer",
              fontSize: "11px",
              color: "#f5a623",
              lineHeight: 1.5,
            }}
          >
            <input
              type="checkbox"
              checked={ackPlaceholders}
              onChange={(e) => setAckPlaceholders(e.target.checked)}
              style={{ marginTop: "2px", flexShrink: 0 }}
            />
            I understand this fix contains &lt;PLACEHOLDER&gt; values that must be
            replaced with real values before the PR can be merged.
          </label>
        </div>
      )}

      {/* Confirmation phrase */}
      <div style={{ marginBottom: "12px" }}>
        <label
          style={{
            display: "block",
            fontSize: "10px",
            color: "#565b6e",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            marginBottom: "4px",
            fontWeight: 600,
          }}
        >
          Type <code style={{ color: "#4f80f7" }}>CREATE DRAFT PR</code> to confirm
        </label>
        <input
          type="text"
          value={phrase}
          onChange={(e) => setPhrase(e.target.value)}
          placeholder="CREATE DRAFT PR"
          style={{
            width: "100%",
            background: "#13151a",
            border: `1px solid ${phrase === _CONFIRM_PHRASE ? "rgba(60,207,126,0.4)" : "#2a2d38"}`,
            borderRadius: "4px",
            padding: "5px 8px",
            fontSize: "12px",
            color: phrase === _CONFIRM_PHRASE ? "#3ccf7e" : "#c4c8d4",
            fontFamily: "monospace",
            boxSizing: "border-box",
          }}
        />
      </div>

      {/* Error message */}
      {error && (
        <div
          style={{
            marginBottom: "10px",
            padding: "7px 10px",
            background: "rgba(245,99,42,0.08)",
            border: "1px solid rgba(245,99,42,0.3)",
            borderRadius: "4px",
            fontSize: "11px",
            color: "#f5632a",
            lineHeight: 1.5,
          }}
        >
          {error}
        </div>
      )}

      {/* Submit button */}
      <button
        onClick={handleCreate}
        disabled={!canSubmit}
        style={{
          background: canSubmit ? "#1a2d4a" : "#1a1d28",
          color: canSubmit ? "#4f80f7" : "#3a3d4a",
          border: `1px solid ${canSubmit ? "rgba(79,128,247,0.4)" : "#252a42"}`,
          borderRadius: "5px",
          padding: "7px 16px",
          fontSize: "12px",
          cursor: canSubmit ? "pointer" : "not-allowed",
          fontFamily: "inherit",
          fontWeight: 500,
          transition: "background 0.15s, color 0.15s",
        }}
      >
        {loading ? "Creating draft PR…" : "Open Draft PR in GitHub"}
      </button>

      <p style={{ margin: "8px 0 0", fontSize: "10px", color: "#3a3d4a", lineHeight: 1.5 }}>
        This will create a branch and a draft PR in your GitHub repository.
        ConfigTrace will not execute Terraform or modify any cloud resources.
      </p>
    </div>
  );
}

// ── PR created success state ──────────────────────────────────────────────────

function PrCreatedBanner({ result }: { result: GitHubPrCreateResponse }) {
  return (
    <div
      style={{
        marginTop: "14px",
        padding: "14px 16px",
        background: "#0d1f12",
        border: "1px solid #1a4028",
        borderRadius: "5px",
      }}
    >
      <p style={{ margin: "0 0 8px", fontSize: "12px", color: "#3ccf7e", fontWeight: 600 }}>
        ✓ Draft PR created
      </p>
      {result.pr_url && (
        <a
          href={result.pr_url}
          target="_blank"
          rel="noopener noreferrer"
          style={{
            display: "inline-block",
            fontSize: "12px",
            color: "#4f80f7",
            textDecoration: "none",
            marginBottom: "8px",
          }}
        >
          #{result.pr_number} — View on GitHub →
        </a>
      )}
      <p style={{ margin: 0, fontSize: "11px", color: "#565b6e", lineHeight: 1.5 }}>
        Branch: <code style={{ color: "#c4c8d4", fontFamily: "monospace" }}>{result.branch_name}</code>
        {" · "}
        Patch file: <code style={{ color: "#c4c8d4", fontFamily: "monospace" }}>{result.patch_file_path}</code>
      </p>
      <p style={{ margin: "6px 0 0", fontSize: "10px", color: "#3a3d4a" }}>
        ConfigTrace has not run Terraform or modified any cloud resources.
        Review and merge the PR through your normal approval process.
      </p>
    </div>
  );
}

// ── Draft content ─────────────────────────────────────────────────────────────

interface DraftContentProps {
  draft: GitHubPrDraftObject;
  mode: string;
  changeId: string;
  iacRepositoryId: string | null;
  defaultBaseBranch: string;
  token?: string | null;
}

function DraftContent({
  draft,
  mode,
  changeId,
  iacRepositoryId,
  defaultBaseBranch,
  token,
}: DraftContentProps) {
  const isOutline = mode === "outline_only";
  const [prResult, setPrResult] = useState<GitHubPrCreateResponse | null>(null);

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

      {/* PR creation — show form or success banner */}
      {prResult ? (
        <PrCreatedBanner result={prResult} />
      ) : iacRepositoryId ? (
        <CreatePrForm
          changeId={changeId}
          iacRepositoryId={iacRepositoryId}
          defaultBaseBranch={defaultBaseBranch}
          hasPlaceholders={Boolean(draft.patch_preview)}
          token={token}
          onCreated={setPrResult}
        />
      ) : (
        <div
          style={{
            marginTop: "14px",
            padding: "10px 12px",
            background: "#0e1120",
            border: "1px solid #252a42",
            borderRadius: "5px",
          }}
        >
          <p style={{ margin: 0, fontSize: "11px", color: "#565b6e" }}>
            PR creation requires a configured GitHub App installation.
            Set up the GitHub App on your IaC repository to enable this feature.
          </p>
        </div>
      )}
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

interface GitHubPrDraftPanelProps {
  data: GitHubPrDraftResponse | null;
  loading?: boolean;
  changeId: string;
  token?: string | null;
}

export default function GitHubPrDraftPanel({
  data,
  loading = false,
  changeId,
  token,
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
            <DraftContent
              draft={data.draft}
              mode={data.mode}
              changeId={changeId}
              iacRepositoryId={data.iac_repository_id ?? null}
              defaultBaseBranch={data.repo?.default_branch ?? "main"}
              token={token}
            />

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
