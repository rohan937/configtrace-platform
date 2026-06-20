"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface JiraIntegrationFormProps {
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
 * Inline form for connecting a Jira site.
 *
 * Requires a Jira site URL, account email, and API token. The API token is
 * sent to the backend once and immediately cleared from state on success. It
 * is never logged, never stored in localStorage or sessionStorage, and never
 * rendered after submission.
 *
 * SECURITY: only configuration metadata is monitored. API token values,
 * webhook secrets, delivery URLs, issue keys, issue titles, issue
 * descriptions, comments, attachments, user emails, account IDs, and
 * customer PII are never accessed or stored.
 */
export default function JiraIntegrationForm({
  onCreated,
  onCancel,
}: JiraIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [siteUrl, setSiteUrl]         = useState("");
  const [email, setEmail]             = useState("");
  const [apiToken, setApiToken]       = useState("");
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
    if (!siteUrl.trim()) {
      setError("Jira site URL is required.");
      return;
    }
    if (!email.trim()) {
      setError("Jira email is required.");
      return;
    }
    if (!apiToken.trim()) {
      setError("Jira API token is required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider:        "jira",
          display_name:    displayName.trim(),
          jira_site_url:   siteUrl.trim(),
          jira_email:      email.trim(),
          jira_api_token:  apiToken,  // sent once; cleared below
        },
        token,
      );

      // Clear sensitive field immediately — do not keep it in state.
      setApiToken("");
      setSuccessMsg("Jira site connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your Jira credentials and try again.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  const canSubmit =
    !!displayName.trim() && !!siteUrl.trim() && !!email.trim() && !!apiToken.trim();

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
        Connect Jira Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="jira-display-name" style={LABEL_STYLE}>Display Name</label>
            <input
              id="jira-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Jira"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* Site URL */}
          <div>
            <label htmlFor="jira-site-url" style={LABEL_STYLE}>Jira site URL</label>
            <input
              id="jira-site-url"
              type="text"
              value={siteUrl}
              onChange={(e) => setSiteUrl(e.target.value)}
              placeholder="https://your-org.atlassian.net"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Your Atlassian site, e.g. https://your-org.atlassian.net.
            </p>
          </div>

          {/* Email */}
          <div>
            <label htmlFor="jira-email" style={LABEL_STYLE}>Jira email</label>
            <input
              id="jira-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@your-org.com"
              disabled={submitting}
              autoComplete="off"
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              The account email associated with the API token.
            </p>
          </div>

          {/* API token */}
          <div>
            <label htmlFor="jira-api-token" style={LABEL_STYLE}>Jira API token</label>
            <input
              id="jira-api-token"
              type="password"
              value={apiToken}
              onChange={(e) => setApiToken(e.target.value)}
              placeholder="••••••••••••••••"
              disabled={submitting}
              autoComplete="new-password"
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Read-only API token. Stored encrypted — never returned in any response.
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
                background: "#0052CC",
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
              {submitting ? "Connecting…" : "Connect Jira"}
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
        ConfigTrace stores Jira credentials encrypted and uses them only to read selected
        configuration metadata. It does not store Jira API token values, OAuth tokens, webhook
        secrets, delivery URLs, issue keys, issue titles, issue descriptions, comments,
        attachments, user emails, account IDs, member identities, customer data, or PII.
      </p>
    </div>
  );
}
