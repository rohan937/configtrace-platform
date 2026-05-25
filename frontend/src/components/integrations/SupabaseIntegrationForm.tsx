"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface SupabaseIntegrationFormProps {
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
  boxSizing: "border-box",
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
 * Inline form for connecting a Supabase project integration.
 *
 * The access token is sent to the backend once and immediately cleared
 * from state on success.  It is never logged, never stored in
 * localStorage or sessionStorage, and never rendered after submission.
 *
 * SECURITY: Only project-level configuration is monitored.  Database
 * table row data, Auth user PII, Edge Function source code, and Storage
 * file contents are NEVER fetched or stored by ConfigTrace.
 */
export default function SupabaseIntegrationForm({
  onCreated,
  onCancel,
}: SupabaseIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [projectRef, setProjectRef] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const { getToken } = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim()) {
      setError("Display name is required.");
      return;
    }
    if (!accessToken.trim()) {
      setError("Access token is required.");
      return;
    }
    if (!projectRef.trim()) {
      setError("Project reference is required.");
      return;
    }

    // Basic format check for project ref (20-char alphanumeric)
    if (!/^[a-z0-9]{20}$/.test(projectRef.trim())) {
      setError(
        "Project reference must be exactly 20 lowercase alphanumeric characters. " +
          "Find it in your Supabase project URL: supabase.com/dashboard/project/<ref>"
      );
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider: "supabase",
          display_name: displayName.trim(),
          // sent once; cleared below immediately after success
          supabase_access_token: accessToken.trim(),
          supabase_project_ref: projectRef.trim(),
        },
        token
      );

      // Clear the sensitive field immediately — do not keep it in state.
      setAccessToken("");
      setSuccessMsg("Supabase project connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your access token and project reference and try again."
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
        Connect Supabase Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

          {/* Display name */}
          <div>
            <label htmlFor="supabase-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="supabase-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Supabase"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise
              later, e.g. &ldquo;Production Supabase&rdquo;.
            </p>
          </div>

          {/* Project reference */}
          <div>
            <label htmlFor="supabase-project-ref" style={LABEL_STYLE}>
              Project Reference
            </label>
            <input
              id="supabase-project-ref"
              type="text"
              value={projectRef}
              onChange={(e) => setProjectRef(e.target.value)}
              placeholder="abcdefghijklmnopqrst"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              The 20-character project reference from your Supabase project URL:{" "}
              <code style={{ fontSize: "11px" }}>
                supabase.com/dashboard/project/&lt;ref&gt;
              </code>
            </p>
          </div>

          {/* Access token */}
          <div>
            <label htmlFor="supabase-access-token" style={LABEL_STYLE}>
              Management API Access Token
              <span
                style={{
                  marginLeft: "6px",
                  background: "rgba(79,128,247,0.15)",
                  color: "#4f80f7",
                  borderRadius: "3px",
                  padding: "1px 5px",
                  fontSize: "9px",
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  verticalAlign: "middle",
                }}
              >
                Encrypted at rest
              </span>
            </label>
            <input
              id="supabase-access-token"
              type="password"
              value={accessToken}
              onChange={(e) => setAccessToken(e.target.value)}
              placeholder="sbp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              Personal access token from{" "}
              <code style={{ fontSize: "11px" }}>
                supabase.com/dashboard/account/tokens
              </code>
              . Uses the Supabase Management API (read-only project config).
            </p>

            {/* Permissions note */}
            <div
              style={{
                marginTop: "8px",
                background: "#13151a",
                border: "1px solid #2a2d38",
                borderRadius: "4px",
                padding: "10px 12px",
                fontSize: "11px",
                color: "#565b6e",
                lineHeight: 1.75,
              }}
            >
              <span
                style={{
                  color: "#8b90a0",
                  display: "block",
                  marginBottom: "4px",
                  fontWeight: 500,
                }}
              >
                What ConfigTrace reads (read-only):
              </span>
              <span style={{ color: "#6b7080" }}>
                ✓ Project metadata (region, status, plan)
              </span>
              <br />
              <span style={{ color: "#6b7080" }}>
                ✓ Auth settings (sign-in methods, MFA, session config)
              </span>
              <br />
              <span style={{ color: "#6b7080" }}>
                ✓ Database pooler config, Storage config, Edge Function metadata
              </span>
              <br />
              <span style={{ color: "#6b7080" }}>
                ✓ RLS enabled/forced flags per table (no row data)
              </span>
              <br />
              <span style={{ color: "#6b7080" }}>
                ✓ Network restrictions, custom domain
              </span>
              <br />
              <span
                style={{
                  color: "#3a3d4a",
                  marginTop: "4px",
                  display: "block",
                }}
              >
                Database row data, Auth user PII, Edge Function source code,
                secret values, and Storage file contents are never accessed.
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
              {submitting ? "Validating…" : "Connect Supabase"}
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
