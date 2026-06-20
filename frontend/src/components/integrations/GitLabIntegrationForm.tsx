"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";
import type { IntegrationCreateRequest } from "@/types";

interface GitLabIntegrationFormProps {
  onCreated: () => void;
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
 * Inline form for connecting a GitLab instance.
 *
 * Requires a personal access token with read_api or api scope. The token is
 * sent to the backend once and immediately cleared from state on success. It
 * is never logged, never stored in localStorage or sessionStorage, and never
 * rendered after submission.
 *
 * SECURITY: only configuration metadata is monitored. Access token values,
 * webhook secrets, raw URLs, project names, branch names, CI variable names
 * or values, deploy key material, user emails, usernames, issue titles, MR
 * content, commit messages, pipeline logs, and customer PII are never accessed
 * or stored.
 */
export default function GitLabIntegrationForm({
  onCreated,
  onCancel,
}: GitLabIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [baseUrl, setBaseUrl]         = useState("");
  const [submitting, setSubmitting]   = useState(false);
  const [error, setError]             = useState<string | null>(null);
  const [successMsg, setSuccessMsg]   = useState<string | null>(null);
  const { getToken }                  = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim()) {
      setError("Display name is required.");
      return;
    }
    if (!accessToken.trim()) {
      setError("GitLab access token is required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      const payload: IntegrationCreateRequest = {
        provider:             "gitlab",
        display_name:         displayName.trim(),
        gitlab_access_token:  accessToken,  // sent once; cleared below
      };
      if (baseUrl.trim()) {
        payload.gitlab_base_url = baseUrl.trim();
      }
      await createIntegration(payload, token);

      // Clear sensitive field immediately — do not keep it in state.
      setAccessToken("");
      setSuccessMsg("GitLab connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your GitLab access token and try again.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  const canSubmit = !!displayName.trim() && !!accessToken.trim();

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
      <div
        style={{
          fontSize: "11px",
          color: "#8b90a0",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: "16px",
        }}
      >
        Connect GitLab Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="gitlab-display-name" style={LABEL_STYLE}>Display Name</label>
            <input
              id="gitlab-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production GitLab"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* Access token */}
          <div>
            <label htmlFor="gitlab-access-token" style={LABEL_STYLE}>Personal Access Token</label>
            <input
              id="gitlab-access-token"
              type="password"
              value={accessToken}
              onChange={(e) => setAccessToken(e.target.value)}
              placeholder="••••••••••••••••"
              disabled={submitting}
              autoComplete="new-password"
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Personal access token with <strong style={{ color: "#8b90a0" }}>read_api</strong> scope.
              Stored encrypted — never returned in any response.
            </p>
          </div>

          {/* Base URL (optional) */}
          <div>
            <label htmlFor="gitlab-base-url" style={LABEL_STYLE}>
              GitLab URL <span style={{ color: "#3a3d4a", fontWeight: 400 }}>(optional)</span>
            </label>
            <input
              id="gitlab-base-url"
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://gitlab.com"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Leave blank for gitlab.com. For self-managed GitLab, enter your instance URL.
            </p>
          </div>

          {/* Error / success */}
          {error && (
            <p style={{ margin: 0, fontSize: "13px", color: "#f87171" }}>{error}</p>
          )}
          {successMsg && (
            <p style={{ margin: 0, fontSize: "13px", color: "#4ade80" }}>{successMsg}</p>
          )}

          {/* Actions */}
          <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
            <button
              type="button"
              onClick={onCancel}
              disabled={submitting}
              style={{
                background: "none",
                border: "1px solid #2a2d38",
                borderRadius: "6px",
                color: "#8b90a0",
                fontSize: "13px",
                padding: "7px 16px",
                cursor: "pointer",
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !canSubmit}
              style={{
                background: "#fc6d26",
                border: "none",
                borderRadius: "6px",
                color: "#fff",
                fontSize: "13px",
                fontWeight: 600,
                padding: "7px 16px",
                cursor: submitting ? "not-allowed" : "pointer",
                opacity: submitting ? 0.7 : 1,
              }}
            >
              {submitting ? "Connecting…" : "Connect GitLab"}
            </button>
          </div>
        </div>
      </form>

      <p
        style={{
          margin: "16px 0 0",
          fontSize: "11px",
          color: "#3a3d4a",
          lineHeight: 1.6,
        }}
      >
        ConfigTrace stores GitLab credentials encrypted and uses them only to read selected
        configuration metadata. It does not store access token values, project names, namespace
        paths, web/ssh/http URLs, branch names, CI variable names or values, deploy key material,
        webhook URLs or secrets, user emails, usernames, issue titles, MR content, commit messages,
        pipeline logs, artifacts, or customer PII. GitLab drift snapshots and risk classification
        are in foundation stage. Security rules planned next.
      </p>
    </div>
  );
}
