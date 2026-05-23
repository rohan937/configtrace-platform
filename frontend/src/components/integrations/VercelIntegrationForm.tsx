"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface VercelIntegrationFormProps {
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
 * Inline form for connecting a Vercel project integration.
 *
 * The API token is sent to the backend once and immediately cleared from
 * state on success.  It is never logged, never stored in localStorage or
 * sessionStorage, and never rendered after submission.
 *
 * SECURITY: Vercel environment variable values are NEVER stored.  ConfigTrace
 * only records env var key names, target environments, and timestamps.
 */
export default function VercelIntegrationForm({
  onCreated,
  onCancel,
}: VercelIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [vercelToken, setVercelToken] = useState("");
  const [projectId, setProjectId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const { getToken } = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim() || !vercelToken.trim() || !projectId.trim()) {
      setError("All three fields are required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider: "vercel",
          display_name: displayName.trim(),
          vercel_token: vercelToken,   // sent once; cleared below
          vercel_project_id: projectId.trim(),
        },
        token,
      );

      // Clear the sensitive field immediately — do not keep it in state.
      setVercelToken("");
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
      <div
        style={{
          fontSize: "11px",
          color: "#8b90a0",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: "16px",
        }}
      >
        Connect Vercel Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

          {/* Display name */}
          <div>
            <label htmlFor="vl-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="vl-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Vercel"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise
              later, e.g. &ldquo;Production Vercel&rdquo;.
            </p>
          </div>

          {/* API token — type=password to prevent shoulder-surfing */}
          <div>
            <label htmlFor="vl-api-token" style={LABEL_STYLE}>
              Vercel API Token
            </label>
            <input
              id="vl-api-token"
              type="password"
              value={vercelToken}
              onChange={(e) => setVercelToken(e.target.value)}
              placeholder="Vercel API token"
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
              Personal access token from vercel.com → Settings → Tokens.
              Credentials are encrypted server-side and never shown again.
            </p>
            {/* Required permissions note */}
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
                What ConfigTrace monitors (read-only):
              </span>
              <span>Project settings · Environment variable names &amp; targets</span>
              <br />
              <span>Custom domains</span>
              <br />
              <span style={{ color: "#3a3d4a" }}>
                Environment variable values are never stored or shown.
              </span>
            </div>
          </div>

          {/* Project ID */}
          <div>
            <label htmlFor="vl-project-id" style={LABEL_STYLE}>
              Project ID
            </label>
            <input
              id="vl-project-id"
              type="text"
              value={projectId}
              onChange={(e) => setProjectId(e.target.value)}
              placeholder="prj_xxxxxxxxxxxx or project-slug"
              disabled={submitting}
              style={{
                ...INPUT_STYLE,
                fontFamily: "monospace",
                opacity: submitting ? 0.6 : 1,
              }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              Found at vercel.com → select your project → Settings → General →
              Project ID. Accepts either the <code style={{ fontFamily: "monospace" }}>prj_xxx</code> ID
              or the project slug name.
            </p>
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
              {submitting ? "Validating…" : "Connect Vercel"}
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
