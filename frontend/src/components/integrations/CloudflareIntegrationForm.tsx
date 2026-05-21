"use client";

import { useState } from "react";
import { createIntegration } from "@/lib/api";

interface CloudflareIntegrationFormProps {
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
 * Inline form for connecting a Cloudflare DNS integration.
 *
 * The API token is sent to the backend once and immediately cleared from
 * state on success.  It is never logged, never stored in localStorage or
 * sessionStorage, and never rendered after submission.
 */
export default function CloudflareIntegrationForm({
  onCreated,
  onCancel,
}: CloudflareIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [apiToken, setApiToken] = useState("");
  const [zoneId, setZoneId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim() || !apiToken.trim() || !zoneId.trim()) {
      setError("All three fields are required.");
      return;
    }

    setSubmitting(true);

    try {
      await createIntegration({
        provider: "cloudflare",
        display_name: displayName.trim(),
        api_token: apiToken,   // sent once; cleared below
        zone_id: zoneId.trim(),
      });

      // Clear the sensitive field immediately — do not keep it in state.
      setApiToken("");
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
        Connect Cloudflare Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

          {/* Display name */}
          <div>
            <label htmlFor="cf-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="cf-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Cloudflare Zone"
              disabled={submitting}
              style={{
                ...INPUT_STYLE,
                opacity: submitting ? 0.6 : 1,
              }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = "#4f80f7";
                e.currentTarget.style.outline = "none";
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = "#2a2d38";
              }}
            />
          </div>

          {/* API token — type=password to prevent shoulder-surfing */}
          <div>
            <label htmlFor="cf-api-token" style={LABEL_STYLE}>
              Cloudflare API Token
            </label>
            <input
              id="cf-api-token"
              type="password"
              value={apiToken}
              onChange={(e) => setApiToken(e.target.value)}
              placeholder="Your Cloudflare API token"
              disabled={submitting}
              autoComplete="new-password"
              style={{
                ...INPUT_STYLE,
                fontFamily: "monospace",
                opacity: submitting ? 0.6 : 1,
              }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = "#4f80f7";
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = "#2a2d38";
              }}
            />
            <p style={HELPER_STYLE}>
              Use a restricted Cloudflare API token with DNS read access.
              Credentials are encrypted by the backend and never shown again.
            </p>
          </div>

          {/* Zone ID */}
          <div>
            <label htmlFor="cf-zone-id" style={LABEL_STYLE}>
              Zone ID
            </label>
            <input
              id="cf-zone-id"
              type="text"
              value={zoneId}
              onChange={(e) => setZoneId(e.target.value)}
              placeholder="32-character hex Zone ID from the Cloudflare dashboard"
              disabled={submitting}
              style={{
                ...INPUT_STYLE,
                fontFamily: "monospace",
                opacity: submitting ? 0.6 : 1,
              }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = "#4f80f7";
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = "#2a2d38";
              }}
            />
          </div>

          {/* Inline error */}
          {error && (
            <p
              style={{
                fontSize: "13px",
                color: "#e84040",
                margin: 0,
              }}
            >
              {error}
            </p>
          )}

          {/* Inline success */}
          {successMsg && (
            <p
              style={{
                fontSize: "13px",
                color: "#3ccf7e",
                margin: 0,
              }}
            >
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
              {submitting ? "Validating…" : "Connect Cloudflare"}
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
