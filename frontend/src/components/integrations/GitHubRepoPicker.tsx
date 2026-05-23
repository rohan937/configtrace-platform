"use client";

/**
 * GitHubRepoPicker — M31.
 *
 * Shown on the GitHub App callback page when the installation covers multiple
 * repositories.  The user selects one and confirms with a display name.
 *
 * For single-repo installations, the parent pre-fills autoSelectedRepo and
 * the user just confirms the display name.
 */

import { useState } from "react";
import type { GitHubInstallationRepo } from "@/types";

interface GitHubRepoPickerProps {
  repos: GitHubInstallationRepo[];
  /** Pre-selected repo (single-repo installations). If set, hides the picker list. */
  autoSelectedRepo: GitHubInstallationRepo | null;
  initialDisplayName: string;
  onComplete: (repo: GitHubInstallationRepo, displayName: string) => void;
  onCancel: () => void;
}

const INPUT_STYLE: React.CSSProperties = {
  width: "100%",
  background: "#1c1e26",
  border: "1px solid #2a2d38",
  borderRadius: "6px",
  color: "#e8eaf0",
  fontSize: "13px",
  padding: "8px 10px",
  outline: "none",
  fontFamily: "inherit",
};

export default function GitHubRepoPicker({
  repos,
  autoSelectedRepo,
  initialDisplayName,
  onComplete,
  onCancel,
}: GitHubRepoPickerProps) {
  const [selectedRepo, setSelectedRepo] = useState<GitHubInstallationRepo | null>(
    autoSelectedRepo
  );
  const [displayName, setDisplayName] = useState(initialDisplayName);
  const [submitting, setSubmitting] = useState(false);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedRepo || submitting) return;
    setSubmitting(true);
    onComplete(selectedRepo, displayName.trim() || selectedRepo.full_name);
  }

  return (
    <form onSubmit={handleSubmit} autoComplete="off">
      <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>

        {/* ── Repo list (only shown for multi-repo installations) ── */}
        {!autoSelectedRepo && (
          <div>
            <label
              style={{
                display: "block",
                fontSize: "11px",
                color: "#8b90a0",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                marginBottom: "8px",
              }}
            >
              Repository ({repos.length} accessible)
            </label>
            <div
              style={{
                border: "1px solid #2a2d38",
                borderRadius: "6px",
                overflow: "hidden",
                maxHeight: "280px",
                overflowY: "auto",
              }}
            >
              {repos.map((repo) => {
                const isSelected = selectedRepo?.full_name === repo.full_name;
                return (
                  <button
                    key={repo.full_name}
                    type="button"
                    onClick={() => {
                      setSelectedRepo(repo);
                      if (!displayName || displayName === selectedRepo?.full_name) {
                        setDisplayName(repo.full_name);
                      }
                    }}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      background: isSelected
                        ? "rgba(79,128,247,0.10)"
                        : "transparent",
                      border: "none",
                      borderBottom: "1px solid #2a2d38",
                      borderLeft: isSelected
                        ? "3px solid #4f80f7"
                        : "3px solid transparent",
                      padding: "10px 12px",
                      cursor: "pointer",
                      fontFamily: "inherit",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <span
                        style={{
                          fontSize: "13px",
                          color: isSelected ? "#e8eaf0" : "#b0b5c4",
                          fontFamily: "monospace",
                          fontWeight: isSelected ? 600 : 400,
                        }}
                      >
                        {repo.full_name}
                      </span>
                      {repo.private && (
                        <span
                          style={{
                            fontSize: "10px",
                            color: "#565b6e",
                            background: "#1c1e26",
                            border: "1px solid #2a2d38",
                            borderRadius: "3px",
                            padding: "1px 5px",
                            flexShrink: 0,
                          }}
                        >
                          private
                        </span>
                      )}
                    </div>
                    {repo.description && (
                      <p
                        style={{
                          fontSize: "11px",
                          color: "#565b6e",
                          margin: "3px 0 0",
                          lineHeight: 1.4,
                        }}
                      >
                        {repo.description}
                      </p>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Single-repo confirmation box */}
        {autoSelectedRepo && (
          <div
            style={{
              background: "#1c1e26",
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              padding: "12px 14px",
            }}
          >
            <p style={{ fontSize: "11px", color: "#565b6e", margin: "0 0 4px" }}>
              Repository
            </p>
            <p
              style={{
                fontSize: "13px",
                color: "#e8eaf0",
                fontFamily: "monospace",
                margin: 0,
              }}
            >
              {autoSelectedRepo.full_name}
              {autoSelectedRepo.private && (
                <span
                  style={{
                    marginLeft: "8px",
                    fontSize: "10px",
                    color: "#565b6e",
                    background: "#13151a",
                    border: "1px solid #2a2d38",
                    borderRadius: "3px",
                    padding: "1px 5px",
                    verticalAlign: "middle",
                  }}
                >
                  private
                </span>
              )}
            </p>
            {autoSelectedRepo.description && (
              <p style={{ fontSize: "11px", color: "#565b6e", margin: "4px 0 0" }}>
                {autoSelectedRepo.description}
              </p>
            )}
          </div>
        )}

        {/* ── Display name ── */}
        <div>
          <label
            htmlFor="gh-app-display-name"
            style={{
              display: "block",
              fontSize: "11px",
              color: "#8b90a0",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              marginBottom: "6px",
            }}
          >
            Display name
          </label>
          <input
            id="gh-app-display-name"
            type="text"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder={selectedRepo?.full_name ?? "e.g. acme/api-server"}
            disabled={submitting}
            style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            onFocus={(e) => {
              e.currentTarget.style.borderColor = "#4f80f7";
            }}
            onBlur={(e) => {
              e.currentTarget.style.borderColor = "#2a2d38";
            }}
          />
          <p style={{ fontSize: "12px", color: "#565b6e", marginTop: "5px" }}>
            A label for this integration — shown in the integrations list.
          </p>
        </div>

        {/* ── Buttons ── */}
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <button
            type="submit"
            disabled={!selectedRepo || submitting}
            style={{
              background: !selectedRepo || submitting ? "#2a3050" : "#4f80f7",
              color: "#ffffff",
              border: "none",
              borderRadius: "6px",
              padding: "8px 18px",
              fontSize: "13px",
              fontWeight: 500,
              cursor: !selectedRepo || submitting ? "not-allowed" : "pointer",
              opacity: !selectedRepo || submitting ? 0.7 : 1,
              fontFamily: "inherit",
            }}
          >
            {submitting ? "Connecting…" : "Connect repository"}
          </button>
          <button
            type="button"
            onClick={onCancel}
            disabled={submitting}
            style={{
              background: "transparent",
              color: "#8b90a0",
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              padding: "8px 14px",
              fontSize: "13px",
              cursor: submitting ? "not-allowed" : "pointer",
              fontFamily: "inherit",
            }}
          >
            Cancel
          </button>
        </div>
      </div>
    </form>
  );
}
