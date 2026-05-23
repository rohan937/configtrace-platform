"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface GitHubIntegrationFormProps {
  /** Called after a successful integration creation so the parent can refresh. */
  onCreated: () => void;
  /** Called when the user dismisses / cancels the form. */
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

const LABEL_STYLE: React.CSSProperties = {
  display: "block",
  fontSize: "11px",
  color: "#8b90a0",
  textTransform: "uppercase",
  letterSpacing: "0.06em",
  marginBottom: "6px",
};

const HELPER_STYLE: React.CSSProperties = {
  fontSize: "12px",
  color: "#565b6e",
  marginTop: "5px",
};

/**
 * Inline form for connecting a GitHub repository integration.
 *
 * The fine-grained PAT is sent to the backend once and immediately cleared
 * from state on success.  It is never logged, never stored in localStorage
 * or sessionStorage, and never rendered after submission.
 */
export default function GitHubIntegrationForm({
  onCreated,
  onCancel,
}: GitHubIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [repoOwner, setRepoOwner] = useState("");
  const [repoName, setRepoName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const { getToken } = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim() || !githubToken.trim() || !repoOwner.trim() || !repoName.trim()) {
      setError("All fields are required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider: "github",
          display_name: displayName.trim(),
          github_token: githubToken,   // sent once; cleared below
          repo_owner: repoOwner.trim(),
          repo_name: repoName.trim(),
        },
        token,
      );

      // Clear the sensitive field immediately — do not keep it in state.
      setGithubToken("");
      setSuccessMsg("Integration connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your credentials and try again.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      style={{
        background: "#1c1e26",
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        padding: "20px 24px",
        marginBottom: "24px",
      }}
    >
      {/* Section heading */}
      <div style={{ marginBottom: "16px" }}>
        <div
          style={{
            fontSize: "11px",
            color: "#8b90a0",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            marginBottom: "6px",
          }}
        >
          Connect GitHub Repository — Advanced (Personal Access Token)
        </div>
        <p style={{ fontSize: "12px", color: "#565b6e", margin: 0, lineHeight: 1.5 }}>
          For most users, the{" "}
          <strong style={{ color: "#8b90a0" }}>GitHub App</strong> option is
          easier and more secure — no token to create or manage.
        </p>
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

          {/* Display name */}
          <div>
            <label htmlFor="gh-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="gh-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. acme/api-server"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — shown in the integrations list.
            </p>
          </div>

          {/* Repository owner */}
          <div>
            <label htmlFor="gh-repo-owner" style={LABEL_STYLE}>
              Repository Owner
            </label>
            <input
              id="gh-repo-owner"
              type="text"
              value={repoOwner}
              onChange={(e) => setRepoOwner(e.target.value)}
              placeholder="username or organisation"
              disabled={submitting}
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              The GitHub username or organisation name that owns the repository.
            </p>
          </div>

          {/* Repository name */}
          <div>
            <label htmlFor="gh-repo-name" style={LABEL_STYLE}>
              Repository Name
            </label>
            <input
              id="gh-repo-name"
              type="text"
              value={repoName}
              onChange={(e) => setRepoName(e.target.value)}
              placeholder="repository-name"
              disabled={submitting}
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              The repository name only — without the owner prefix.
            </p>
          </div>

          {/* Fine-grained PAT — type=password to prevent shoulder-surfing */}
          <div>
            <label htmlFor="gh-pat" style={LABEL_STYLE}>
              Fine-grained Personal Access Token
            </label>
            <input
              id="gh-pat"
              type="password"
              value={githubToken}
              onChange={(e) => setGithubToken(e.target.value)}
              placeholder="github_pat_…"
              disabled={submitting}
              autoComplete="new-password"
              style={{
                ...INPUT_STYLE,
                fontFamily: "monospace",
                opacity: submitting ? 0.6 : 1,
              }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              Use a fine-grained PAT, not a classic token. Credentials are
              encrypted server-side and never shown again.
            </p>
            {/* Required permissions block */}
            <div
              style={{
                marginTop: "8px",
                background: "#13151a",
                border: "1px solid #2a2d38",
                borderRadius: "4px",
                padding: "8px 12px",
                fontSize: "11px",
                color: "#565b6e",
                lineHeight: 1.7,
              }}
            >
              <span style={{ color: "#8b90a0", display: "block", marginBottom: "2px" }}>
                Required token permissions (repository scope):
              </span>
              <span style={{ fontFamily: "monospace" }}>Metadata: Read</span>
              <br />
              <span style={{ fontFamily: "monospace" }}>Administration: Read</span>
              <br />
              <span style={{ fontFamily: "monospace" }}>Secrets: Read</span>
              <br />
              <span style={{ fontFamily: "monospace" }}>Variables: Read</span>
              <br />
              <span style={{ color: "#3a3d4a" }}>
                Scope to a specific repository only.
              </span>
            </div>
          </div>

          {/* Inline error */}
          {error && (
            <p style={{ fontSize: "13px", color: "#e84040", margin: 0 }}>
              {error}
            </p>
          )}

          {/* Inline success */}
          {successMsg && (
            <p style={{ fontSize: "13px", color: "#3ccf7e", margin: 0 }}>
              {successMsg}
            </p>
          )}

          {/* Buttons */}
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <button
              type="submit"
              disabled={submitting}
              style={{
                background: submitting ? "#2a3050" : "#4f80f7",
                color: "#ffffff",
                border: "none",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 500,
                cursor: submitting ? "not-allowed" : "pointer",
                opacity: submitting ? 0.7 : 1,
                fontFamily: "inherit",
              }}
            >
              {submitting ? "Validating…" : "Connect GitHub"}
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
                padding: "8px 16px",
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
    </div>
  );
}
