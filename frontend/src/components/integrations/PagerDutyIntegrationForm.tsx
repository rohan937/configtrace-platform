"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface PagerDutyIntegrationFormProps {
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
 * Inline form for connecting a PagerDuty account.
 *
 * Requires a read-only PagerDuty API token. The token is sent to the backend
 * once and immediately cleared from state on success. It is never logged,
 * never stored in localStorage or sessionStorage, and never rendered after
 * submission.
 *
 * SECURITY: only configuration metadata is monitored. API token values,
 * routing keys, integration keys, webhook secrets, delivery URLs, user emails,
 * user names, phone numbers, contact methods, on-call user identities,
 * responder identities, subscriber identities, incident payloads, alert
 * payloads, and customer PII are never accessed or stored.
 */
export default function PagerDutyIntegrationForm({
  onCreated,
  onCancel,
}: PagerDutyIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
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
    if (!apiToken.trim()) {
      setError("API token is required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider:              "pagerduty",
          display_name:          displayName.trim(),
          pagerduty_api_token:   apiToken,  // sent once; cleared below
        },
        token,
      );

      // Clear sensitive field immediately — do not keep it in state.
      setApiToken("");
      setSuccessMsg("PagerDuty account connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your PagerDuty API token and try again.",
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
      <div
        style={{
          fontSize: "11px",
          color: "#8b90a0",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: "16px",
        }}
      >
        Connect PagerDuty Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="pd-display-name" style={LABEL_STYLE}>Display Name</label>
            <input
              id="pd-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production PagerDuty"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* API token */}
          <div>
            <label htmlFor="pd-api-token" style={LABEL_STYLE}>API Token</label>
            <input
              id="pd-api-token"
              type="password"
              value={apiToken}
              onChange={(e) => setApiToken(e.target.value)}
              placeholder="Your PagerDuty read-only API token"
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
              disabled={submitting || !displayName.trim() || !apiToken.trim()}
              style={{
                background: "#06ac38",
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
              {submitting ? "Connecting…" : "Connect PagerDuty"}
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
        ConfigTrace stores PagerDuty credentials encrypted and uses them only to read
        selected configuration metadata. It does not store API token values, routing keys,
        integration keys, webhook secrets, delivery URLs, user emails, user names, phone
        numbers, contact methods, on-call user identities, responder identities, subscriber
        identities, incident payloads, alert payloads, or customer PII.
      </p>
    </div>
  );
}
