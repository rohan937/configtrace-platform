"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface LinearIntegrationFormProps {
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
 * Inline form for connecting a Linear workspace.
 *
 * Requires a Linear API key (lin_api_...). The key is sent to the backend
 * once and immediately cleared from state on success. It is never logged,
 * never stored in localStorage or sessionStorage, and never rendered after
 * submission.
 *
 * SECURITY: only configuration metadata is monitored. API key values,
 * webhook secrets, delivery URLs, issue titles, issue descriptions,
 * comments, attachments, user emails, user names, member identities,
 * and customer PII are never accessed or stored.
 */
export default function LinearIntegrationForm({
  onCreated,
  onCancel,
}: LinearIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [apiKey, setApiKey]           = useState("");
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
    if (!apiKey.trim()) {
      setError("Linear API key is required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider:        "linear",
          display_name:    displayName.trim(),
          linear_api_key:  apiKey,  // sent once; cleared below
        },
        token,
      );

      // Clear sensitive field immediately — do not keep it in state.
      setApiKey("");
      setSuccessMsg("Linear workspace connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your Linear API key and try again.",
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
        Connect Linear Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="linear-display-name" style={LABEL_STYLE}>Display Name</label>
            <input
              id="linear-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Linear"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* API key */}
          <div>
            <label htmlFor="linear-api-key" style={LABEL_STYLE}>Linear API key</label>
            <input
              id="linear-api-key"
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="lin_api_..."
              disabled={submitting}
              autoComplete="new-password"
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Read-only API key. Stored encrypted — never returned in any response.
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
              disabled={submitting || !displayName.trim() || !apiKey.trim()}
              style={{
                background: "#5E6AD2",
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
              {submitting ? "Connecting…" : "Connect Linear"}
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
        ConfigTrace stores Linear credentials encrypted and uses them only to read selected
        configuration metadata. It does not store Linear API key values, OAuth tokens, webhook
        secrets, delivery URLs, issue titles, issue descriptions, comments, attachments, user
        emails, user names, phone numbers, member identities, customer data, or PII.
      </p>
    </div>
  );
}
