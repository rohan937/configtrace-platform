"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface AzureIntegrationFormProps {
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
 * Inline form for connecting an Azure subscription via a service principal.
 *
 * The client_secret is sent to the backend once and immediately cleared
 * from state on success. It is never logged, never stored in localStorage
 * or sessionStorage, and never rendered after submission.
 *
 * SECURITY: only configuration metadata is monitored. Client secrets,
 * access tokens, private keys, raw policies, and customer/workload data
 * are never accessed.
 */
export default function AzureIntegrationForm({
  onCreated,
  onCancel,
}: AzureIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [subscriptionId, setSubscriptionId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const { getToken } = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (
      !displayName.trim()
      || !tenantId.trim()
      || !clientId.trim()
      || !clientSecret.trim()
      || !subscriptionId.trim()
    ) {
      setError("All five fields are required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider: "azure",
          display_name: displayName.trim(),
          azure_tenant_id: tenantId.trim(),
          azure_client_id: clientId.trim(),
          azure_client_secret: clientSecret, // sent once; cleared below
          azure_subscription_id: subscriptionId.trim(),
        },
        token,
      );

      // Clear sensitive field immediately — do not keep it in state.
      setClientSecret("");
      setSuccessMsg("Azure subscription connected.");
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
      <div
        style={{
          fontSize: "11px",
          color: "#8b90a0",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: "16px",
        }}
      >
        Connect Azure Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="azure-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="azure-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Azure"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* Tenant ID */}
          <div>
            <label htmlFor="azure-tenant-id" style={LABEL_STYLE}>Tenant ID</label>
            <input
              id="azure-tenant-id"
              type="text"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              placeholder="Azure AD / Entra ID tenant GUID"
              disabled={submitting}
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Azure portal → Microsoft Entra ID → Overview → Tenant ID.
            </p>
          </div>

          {/* Client ID */}
          <div>
            <label htmlFor="azure-client-id" style={LABEL_STYLE}>Client ID</label>
            <input
              id="azure-client-id"
              type="text"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              placeholder="Service principal application (client) ID"
              disabled={submitting}
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              App registration → Overview → Application (client) ID.
            </p>
          </div>

          {/* Client Secret */}
          <div>
            <label htmlFor="azure-client-secret" style={LABEL_STYLE}>Client Secret</label>
            <input
              id="azure-client-secret"
              type="password"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              placeholder="Service principal client secret"
              disabled={submitting}
              autoComplete="new-password"
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              App registration → Certificates &amp; secrets → New client secret.
              Stored encrypted; never returned by the backend.
            </p>
          </div>

          {/* Subscription ID */}
          <div>
            <label htmlFor="azure-subscription-id" style={LABEL_STYLE}>Subscription ID</label>
            <input
              id="azure-subscription-id"
              type="text"
              value={subscriptionId}
              onChange={(e) => setSubscriptionId(e.target.value)}
              placeholder="Azure subscription GUID"
              disabled={submitting}
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Azure portal → Subscriptions → select your subscription → Overview.
            </p>
          </div>

          {/* Trust note */}
          <p style={{ margin: 0, fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
            ConfigTrace stores Azure credentials encrypted and uses them only to
            read selected configuration metadata. It does not store client
            secrets, access tokens, private keys, raw policies, or customer data
            in findings.
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
              {submitting ? "Connecting…" : "Connect Azure"}
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
