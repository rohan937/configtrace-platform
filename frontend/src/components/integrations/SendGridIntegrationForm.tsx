"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface SendGridIntegrationFormProps {
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
 * Inline form for connecting a SendGrid account via API key.
 *
 * The API key is sent to the backend once and immediately cleared from
 * state on success. It is never logged, never stored in localStorage or
 * sessionStorage, and never rendered after submission.
 *
 * SECURITY: only mail configuration metadata is monitored. API key
 * values, email content, recipient data, raw event payloads, webhook
 * secrets, and customer PII are never accessed or stored.
 */
export default function SendGridIntegrationForm({
  onCreated,
  onCancel,
}: SendGridIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const { getToken } = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim() || !apiKey.trim()) {
      setError("Both fields are required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider: "sendgrid",
          display_name: displayName.trim(),
          sendgrid_api_key: apiKey, // sent once; cleared below
        },
        token,
      );

      setApiKey("");
      setSuccessMsg("SendGrid account connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your API key and try again.",
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
        Connect SendGrid Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="sendgrid-display-name" style={LABEL_STYLE}>Display Name</label>
            <input
              id="sendgrid-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production SendGrid"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* API Key */}
          <div>
            <label htmlFor="sendgrid-api-key" style={LABEL_STYLE}>
              SendGrid API Key
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
                Read-only recommended
              </span>
            </label>
            <input
              id="sendgrid-api-key"
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="SendGrid API key"
              disabled={submitting}
              autoComplete="new-password"
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              SendGrid Console → Settings → API Keys → Create API Key →
              <strong style={{ color: "#8b90a0" }}> Restricted Access</strong> with
              read-only permission on API Keys, Sender Authentication, Mail
              Settings, Tracking Settings, and Event Webhooks. Stored encrypted;
              never returned by the backend.
            </p>
          </div>

          {/* Trust note */}
          <p style={{ margin: 0, fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
            ConfigTrace stores SendGrid credentials encrypted and uses them only
            to read selected mail configuration metadata. It does not store API
            key values, email content, recipient data, raw event payloads,
            webhook secrets, or customer PII in findings.
          </p>

          {error && (
            <p style={{ fontSize: "13px", color: "#e84040", margin: 0 }}>{error}</p>
          )}
          {successMsg && (
            <p style={{ fontSize: "13px", color: "#3ccf7e", margin: 0 }}>{successMsg}</p>
          )}

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
              {submitting ? "Connecting…" : "Connect SendGrid"}
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
