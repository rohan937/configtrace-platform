"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface ClerkIntegrationFormProps {
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
 * Inline form for connecting a Clerk instance.
 *
 * Requires a Backend API Secret Key (sk_live_* or sk_test_*). The Frontend
 * API URL is optional and only needed if the connector requires it for
 * additional configuration surfaces.
 *
 * Secrets are sent to the backend once and immediately cleared from state
 * on success. They are never logged, never stored in localStorage or
 * sessionStorage, and never rendered after submission.
 *
 * SECURITY: only configuration-level metadata is monitored. Secret key values,
 * session tokens, JWTs, OAuth tokens, webhook secrets, raw redirect URLs,
 * raw callback URLs, user emails, user IDs, phone numbers, names, organization
 * member identities, session history, login history, IP addresses, user agents,
 * customer data, and PII are never accessed or stored.
 */
export default function ClerkIntegrationForm({
  onCreated,
  onCancel,
}: ClerkIntegrationFormProps) {
  const [displayName, setDisplayName]         = useState("");
  const [secretKey, setSecretKey]             = useState("");
  const [frontendApiUrl, setFrontendApiUrl]   = useState("");
  const [submitting, setSubmitting]           = useState(false);
  const [error, setError]                     = useState<string | null>(null);
  const [successMsg, setSuccessMsg]           = useState<string | null>(null);
  const { getToken }                          = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim()) {
      setError("Display name is required.");
      return;
    }
    if (!secretKey.trim()) {
      setError("Secret key is required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider:                   "clerk",
          display_name:               displayName.trim(),
          clerk_secret_key:           secretKey,                              // sent once; cleared below
          ...(frontendApiUrl.trim()
            ? { clerk_frontend_api_url: frontendApiUrl.trim() }
            : {}),
        },
        token,
      );

      // Clear sensitive fields immediately — do not keep them in state.
      setSecretKey("");
      setFrontendApiUrl("");
      setSuccessMsg("Clerk instance connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your Clerk secret key and try again.",
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
        Connect Clerk Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="clerk-display-name" style={LABEL_STYLE}>Display Name</label>
            <input
              id="clerk-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Clerk"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* Secret key */}
          <div>
            <label htmlFor="clerk-secret-key" style={LABEL_STYLE}>Secret Key</label>
            <input
              id="clerk-secret-key"
              type="password"
              value={secretKey}
              onChange={(e) => setSecretKey(e.target.value)}
              placeholder="sk_live_… or sk_test_…"
              disabled={submitting}
              autoComplete="new-password"
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Clerk Dashboard → Configure → API Keys → Secret keys. Use a key with
              read-only configuration access. Stored encrypted; never returned by the backend.
            </p>
          </div>

          {/* Frontend API URL (optional) */}
          <div>
            <label htmlFor="clerk-frontend-api-url" style={LABEL_STYLE}>
              Frontend API URL <span style={{ color: "#3a3d4a", fontWeight: 400 }}>(optional)</span>
            </label>
            <input
              id="clerk-frontend-api-url"
              type="text"
              value={frontendApiUrl}
              onChange={(e) => setFrontendApiUrl(e.target.value)}
              placeholder="https://your-instance.clerk.accounts.dev"
              disabled={submitting}
              autoComplete="off"
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Optional. Found in Clerk Dashboard → Configure → API Keys → Frontend API URL.
              Not required for configuration drift snapshots.
            </p>
          </div>

          {/* Trust note */}
          <p style={{ margin: 0, fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
            ConfigTrace stores Clerk credentials encrypted and uses them only to read
            selected configuration metadata. It does not store secret key values,
            session tokens, JWTs, OAuth tokens, webhook secrets, raw redirect URLs,
            raw callback URLs, user emails, user IDs, phone numbers, names, organization
            member identities, session history, login history, IP addresses, user agents,
            customer data, or PII in findings.
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
                background: submitting ? "#2a3050" : "#4f4fa3",
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
              {submitting ? "Connecting…" : "Connect Clerk"}
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
