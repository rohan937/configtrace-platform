"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface Auth0IntegrationFormProps {
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

type AuthMode = "client_credentials" | "management_token";

/**
 * Inline form for connecting an Auth0 tenant.
 *
 * Supports two authentication modes:
 *
 *   1. client_credentials (recommended): tenant domain + M2M client_id +
 *      client_secret. The backend mints a Management API token at sync
 *      time via the OAuth2 client_credentials flow.
 *   2. management_token (direct-token): tenant domain + a long-lived
 *      Management API token. Useful for quick demos or where minting a
 *      M2M application is impractical.
 *
 * Secrets are sent to the backend once and immediately cleared from state
 * on success. They are never logged, never stored in localStorage or
 * sessionStorage, and never rendered after submission.
 *
 * SECURITY: only tenant/application configuration metadata is monitored.
 * Client secrets, management tokens, access/refresh/ID tokens, JWTs, user
 * emails, user IDs, login history, IP addresses, sessions, raw callback
 * URLs, raw Auth0 logs, rule/action code, and customer PII are never
 * accessed or stored.
 */
export default function Auth0IntegrationForm({
  onCreated,
  onCancel,
}: Auth0IntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [domain, setDomain] = useState("");
  const [mode, setMode] = useState<AuthMode>("client_credentials");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [mgmtToken, setMgmtToken] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const { getToken } = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim() || !domain.trim()) {
      setError("Display name and Auth0 domain are required.");
      return;
    }
    if (mode === "client_credentials") {
      if (!clientId.trim() || !clientSecret.trim()) {
        setError("Client ID and Client Secret are required in client-credentials mode.");
        return;
      }
    } else {
      if (!mgmtToken.trim()) {
        setError("Management API Token is required in management-token mode.");
        return;
      }
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider: "auth0",
          display_name: displayName.trim(),
          auth0_domain: domain.trim(),
          ...(mode === "client_credentials"
            ? {
                auth0_client_id: clientId.trim(),
                auth0_client_secret: clientSecret, // sent once; cleared below
              }
            : {
                auth0_management_api_token: mgmtToken, // sent once; cleared below
              }),
        },
        token,
      );

      // Clear sensitive fields immediately — do not keep them in state.
      setClientSecret("");
      setMgmtToken("");
      setSuccessMsg("Auth0 tenant connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your Auth0 credentials and try again.",
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
        Connect Auth0 Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="auth0-display-name" style={LABEL_STYLE}>Display Name</label>
            <input
              id="auth0-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Auth0"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* Domain */}
          <div>
            <label htmlFor="auth0-domain" style={LABEL_STYLE}>Auth0 Domain</label>
            <input
              id="auth0-domain"
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="e.g. mytenant.auth0.com"
              disabled={submitting}
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Your Auth0 tenant domain. Do not include &ldquo;https://&rdquo;.
            </p>
          </div>

          {/* Mode selector */}
          <div>
            <label style={LABEL_STYLE}>Authentication Mode</label>
            <div style={{ display: "flex", gap: "10px" }}>
              <button
                type="button"
                onClick={() => setMode("client_credentials")}
                disabled={submitting}
                style={{
                  background: mode === "client_credentials" ? "rgba(79,128,247,0.15)" : "transparent",
                  border: `1px solid ${mode === "client_credentials" ? "#4f80f7" : "#2a2d38"}`,
                  color: mode === "client_credentials" ? "#4f80f7" : "#8b90a0",
                  borderRadius: "6px",
                  padding: "6px 12px",
                  fontSize: "12px",
                  cursor: submitting ? "not-allowed" : "pointer",
                  fontFamily: "inherit",
                }}
              >
                Client credentials (recommended)
              </button>
              <button
                type="button"
                onClick={() => setMode("management_token")}
                disabled={submitting}
                style={{
                  background: mode === "management_token" ? "rgba(79,128,247,0.15)" : "transparent",
                  border: `1px solid ${mode === "management_token" ? "#4f80f7" : "#2a2d38"}`,
                  color: mode === "management_token" ? "#4f80f7" : "#8b90a0",
                  borderRadius: "6px",
                  padding: "6px 12px",
                  fontSize: "12px",
                  cursor: submitting ? "not-allowed" : "pointer",
                  fontFamily: "inherit",
                }}
              >
                Management API token
              </button>
            </div>
          </div>

          {mode === "client_credentials" ? (
            <>
              {/* Client ID */}
              <div>
                <label htmlFor="auth0-client-id" style={LABEL_STYLE}>Client ID</label>
                <input
                  id="auth0-client-id"
                  type="text"
                  value={clientId}
                  onChange={(e) => setClientId(e.target.value)}
                  placeholder="Auth0 M2M application client ID"
                  disabled={submitting}
                  style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
                />
                <p style={HELPER_STYLE}>
                  Auth0 Dashboard → Applications → Machine-to-Machine application
                  authorised for the Management API → Client ID.
                </p>
              </div>

              {/* Client Secret */}
              <div>
                <label htmlFor="auth0-client-secret" style={LABEL_STYLE}>Client Secret</label>
                <input
                  id="auth0-client-secret"
                  type="password"
                  value={clientSecret}
                  onChange={(e) => setClientSecret(e.target.value)}
                  placeholder="Auth0 M2M application client secret"
                  disabled={submitting}
                  autoComplete="new-password"
                  style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
                />
                <p style={HELPER_STYLE}>
                  Stored encrypted; never returned by the backend.
                </p>
              </div>
            </>
          ) : (
            /* Management API Token */
            <div>
              <label htmlFor="auth0-mgmt-token" style={LABEL_STYLE}>Management API Token</label>
              <input
                id="auth0-mgmt-token"
                type="password"
                value={mgmtToken}
                onChange={(e) => setMgmtToken(e.target.value)}
                placeholder="Auth0 Management API token"
                disabled={submitting}
                autoComplete="new-password"
                style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
              />
              <p style={HELPER_STYLE}>
                Auth0 Dashboard → Applications → APIs → Auth0 Management API →
                API Explorer → Token. Stored encrypted; never returned by the backend.
              </p>
            </div>
          )}

          {/* Trust note */}
          <p style={{ margin: 0, fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
            ConfigTrace stores Auth0 credentials encrypted and uses them only to
            read selected tenant/application configuration metadata. It does not
            store client secrets, management tokens, access tokens, refresh
            tokens, ID tokens, JWTs, user emails, user IDs, login history, IP
            addresses, sessions, raw callback URLs, raw Auth0 logs, rule/action
            code, or customer PII in findings.
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
              {submitting ? "Connecting…" : "Connect Auth0"}
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
