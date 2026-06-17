"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface DatadogIntegrationFormProps {
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

const DATADOG_SITES = [
  { value: "datadoghq.com",     label: "US1 — datadoghq.com" },
  { value: "us3.datadoghq.com", label: "US3 — us3.datadoghq.com" },
  { value: "us5.datadoghq.com", label: "US5 — us5.datadoghq.com" },
  { value: "datadoghq.eu",      label: "EU — datadoghq.eu" },
  { value: "ap1.datadoghq.com", label: "AP1 — ap1.datadoghq.com" },
  { value: "ap2.datadoghq.com", label: "AP2 — ap2.datadoghq.com" },
  { value: "ddog-gov.com",      label: "US1-FED — ddog-gov.com" },
];

/**
 * Inline form for connecting a Datadog account.
 *
 * Requires an API key and an Application key. The site can be selected from
 * the known Datadog regions (defaults to datadoghq.com).
 *
 * Secrets are sent to the backend once and immediately cleared from state
 * on success. They are never logged, never stored in localStorage or
 * sessionStorage, and never rendered after submission.
 *
 * SECURITY: only configuration-level metadata is monitored. API key values,
 * application key values, OAuth tokens, webhook secrets, raw monitor queries,
 * raw dashboard JSON, logs, traces, metric values, incident text, emails,
 * destination handles, and customer PII are never accessed or stored.
 */
export default function DatadogIntegrationForm({
  onCreated,
  onCancel,
}: DatadogIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [site, setSite]               = useState("datadoghq.com");
  const [apiKey, setApiKey]           = useState("");
  const [appKey, setAppKey]           = useState("");
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
      setError("API key is required.");
      return;
    }
    if (!appKey.trim()) {
      setError("Application key is required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider:               "datadog",
          display_name:           displayName.trim(),
          datadog_api_key:        apiKey,        // sent once; cleared below
          datadog_application_key: appKey,       // sent once; cleared below
          datadog_site:           site,
        },
        token,
      );

      // Clear sensitive fields immediately — do not keep them in state.
      setApiKey("");
      setAppKey("");
      setSuccessMsg("Datadog account connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your Datadog credentials and try again.",
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
        Connect Datadog Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="datadog-display-name" style={LABEL_STYLE}>Display Name</label>
            <input
              id="datadog-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Datadog"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* Datadog site */}
          <div>
            <label htmlFor="datadog-site" style={LABEL_STYLE}>Datadog Site</label>
            <select
              id="datadog-site"
              value={site}
              onChange={(e) => setSite(e.target.value)}
              disabled={submitting}
              style={{
                ...INPUT_STYLE,
                cursor: submitting ? "not-allowed" : "pointer",
                opacity: submitting ? 0.6 : 1,
              }}
            >
              {DATADOG_SITES.map((s) => (
                <option key={s.value} value={s.value}>{s.label}</option>
              ))}
            </select>
            <p style={HELPER_STYLE}>
              Select the Datadog region your account uses. US1 (datadoghq.com) is the default.
            </p>
          </div>

          {/* API key */}
          <div>
            <label htmlFor="datadog-api-key" style={LABEL_STYLE}>API Key</label>
            <input
              id="datadog-api-key"
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="Datadog API key"
              disabled={submitting}
              autoComplete="new-password"
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Datadog → Organization Settings → API Keys. Stored encrypted; never returned by the backend.
            </p>
          </div>

          {/* Application key */}
          <div>
            <label htmlFor="datadog-app-key" style={LABEL_STYLE}>Application Key</label>
            <input
              id="datadog-app-key"
              type="password"
              value={appKey}
              onChange={(e) => setAppKey(e.target.value)}
              placeholder="Datadog Application key"
              disabled={submitting}
              autoComplete="new-password"
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Datadog → Organization Settings → Application Keys → New Application Key.
              Use a read-only scoped key when possible. Stored encrypted; never returned by the backend.
            </p>
          </div>

          {/* Trust note */}
          <p style={{ margin: 0, fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
            ConfigTrace stores Datadog credentials encrypted and uses them only to
            read selected configuration metadata. It does not store API key values,
            application key values, OAuth tokens, webhook secrets, raw monitor
            queries, raw dashboard JSON, logs, traces, metric values, incident
            text, emails, destination handles, customer data, or PII in findings.
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
                background: submitting ? "#2a3050" : "#632ca6",
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
              {submitting ? "Connecting…" : "Connect Datadog"}
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
