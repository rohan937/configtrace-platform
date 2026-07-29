"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";
import type { IntegrationCreateRequest } from "@/types";

interface EntraIntegrationFormProps {
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
 * Inline form for connecting a Microsoft Entra ID tenant via an app
 * registration (OAuth 2.0 client credentials).
 *
 * The client secret is sent to the backend once and immediately cleared
 * from state on success. It is never logged, never stored in localStorage
 * or sessionStorage, and never rendered after submission — after a
 * successful connect only "Client secret configured" is shown, never the
 * secret itself.
 *
 * SECURITY: ConfigTrace only requests the read application permissions it
 * actually needs — never Directory.ReadWrite.All or Global Administrator.
 * This connector is read-only and supports the Microsoft commercial/
 * global cloud only.
 */
export default function EntraIntegrationForm({
  onCreated,
  onCancel,
}: EntraIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
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
    if (!tenantId.trim()) {
      setError("Microsoft Entra tenant ID is required.");
      return;
    }
    if (!clientId.trim()) {
      setError("Application (client) ID is required.");
      return;
    }
    if (!clientSecret.trim()) {
      setError("Client secret is required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      const payload: IntegrationCreateRequest = {
        provider: "entra",
        display_name: displayName.trim(),
        entra_tenant_id: tenantId.trim(),
        entra_client_id: clientId.trim(),
        entra_client_secret: clientSecret, // sent once; cleared below
      };
      await createIntegration(payload, token);

      // Clear the sensitive field immediately — do not keep it in state.
      setClientSecret("");
      setSuccessMsg("Client secret configured. Microsoft Entra ID tenant connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your tenant ID, client ID, and client secret and try again."
      );
    } finally {
      setSubmitting(false);
    }
  }

  const canSubmit =
    !!displayName.trim() && !!tenantId.trim() && !!clientId.trim() && !!clientSecret.trim();

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
        Connect Microsoft Entra ID
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="entra-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="entra-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Entra Tenant"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* Setup guidance */}
          <div
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: "4px",
              padding: "10px 12px",
              fontSize: "11px",
              color: "#6b7080",
              lineHeight: 1.75,
            }}
          >
            <span style={{ color: "#8b90a0", display: "block", marginBottom: "4px", fontWeight: 500 }}>
              Create a dedicated app registration for ConfigTrace — do not reuse
              an app that already has broader write permissions.
            </span>
            1. Microsoft Entra admin center → App registrations → New registration.
            <br />
            2. API permissions → Add a permission → Microsoft Graph → Application
            permissions → add the read permissions ConfigTrace needs (see setup
            guide below).
            <br />
            3. Grant admin consent for your organization.
            <br />
            4. Certificates &amp; secrets → New client secret → copy the secret{" "}
            <strong>value</strong> immediately (Microsoft only shows it once).
            <br />
            5. Copy the tenant ID and application (client) ID from the
            Overview page.
            <br />
            <span style={{ color: "#3a3d4a", marginTop: "4px", display: "block" }}>
              ConfigTrace never asks for Directory.ReadWrite.All or Global
              Administrator — this connector is read-only. A least-privileged
              app registration may not be granted every optional permission
              (e.g. Conditional Access, authentication methods, or directory
              roles) — that is expected and does not block the connection;
              coverage diagnostics are shown after the first sync.
            </span>
          </div>

          {/* Tenant ID */}
          <div>
            <label htmlFor="entra-tenant-id" style={LABEL_STYLE}>
              Microsoft Entra tenant ID
            </label>
            <input
              id="entra-tenant-id"
              type="text"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              placeholder="11111111-1111-1111-1111-111111111111"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Enter the directory (tenant) ID for your Microsoft Entra tenant.
            </p>
          </div>

          {/* Client ID */}
          <div>
            <label htmlFor="entra-client-id" style={LABEL_STYLE}>
              Application (client) ID
            </label>
            <input
              id="entra-client-id"
              type="text"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              placeholder="22222222-2222-2222-2222-222222222222"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              The application (client) ID of the app registration created for ConfigTrace.
            </p>
          </div>

          {/* Client secret */}
          <div>
            <label htmlFor="entra-client-secret" style={LABEL_STYLE}>
              Client secret
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
              id="entra-client-secret"
              type="password"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              placeholder="Client secret value"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Paste the secret <strong>value</strong> shown once when you created
              it under Certificates &amp; secrets — not the secret ID. Never
              echoed back after saving — only &ldquo;Client secret
              configured&rdquo; is shown once connected.
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
                background: "#0078D4",
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
              {submitting ? "Validating…" : "Connect Microsoft Entra ID"}
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
        ConfigTrace stores your client secret encrypted and uses it only to
        read tenant configuration metadata via Microsoft Graph. It does not
        store the secret value, passwords, password hashes, recovery codes,
        authentication method secrets, private keys, or session/refresh/
        access tokens. Supports the Microsoft commercial/global cloud only —
        GCC High, DoD, and China (21Vianet) national clouds are not
        supported. Coverage may be partial if some Graph permissions are not
        granted to the app registration — connection diagnostics are shown
        after the first sync.
      </p>
    </div>
  );
}
