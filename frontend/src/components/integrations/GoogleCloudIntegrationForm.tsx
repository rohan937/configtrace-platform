"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface GoogleCloudIntegrationFormProps {
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
 * Inline form for connecting a Google Cloud project via a service account JSON.
 *
 * The entire service account JSON (including the embedded private_key) is
 * sent to the backend once and immediately cleared from state on success.
 * It is never logged, never stored in localStorage or sessionStorage, and
 * never rendered after submission.
 *
 * SECURITY: only configuration metadata is monitored. Private keys, OAuth
 * tokens, principal emails, raw IAM payloads, secret payloads, and
 * customer/workload data are never accessed or stored.
 */
export default function GoogleCloudIntegrationForm({
  onCreated,
  onCancel,
}: GoogleCloudIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [projectId, setProjectId] = useState("");
  const [serviceAccountJson, setServiceAccountJson] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const { getToken } = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim() || !serviceAccountJson.trim()) {
      setError("Display name and service account JSON are required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider: "google_cloud",
          display_name: displayName.trim(),
          google_cloud_project_id: projectId.trim() || undefined,
          // SECURITY: sent once; entire JSON string is secret material.
          google_cloud_service_account_json: serviceAccountJson,
        },
        token,
      );

      // Clear sensitive field immediately — do not keep it in state.
      setServiceAccountJson("");
      setSuccessMsg("Google Cloud project connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your service account JSON and try again.",
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
        Connect Google Cloud Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="gcp-display-name" style={LABEL_STYLE}>Display Name</label>
            <input
              id="gcp-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production GCP"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* Project ID (optional) */}
          <div>
            <label htmlFor="gcp-project-id" style={LABEL_STYLE}>
              Project ID{" "}
              <span style={{ color: "#565b6e", fontWeight: 400, textTransform: "none", letterSpacing: 0 }}>
                (optional)
              </span>
            </label>
            <input
              id="gcp-project-id"
              type="text"
              value={projectId}
              onChange={(e) => setProjectId(e.target.value)}
              placeholder="e.g. my-project-12345"
              disabled={submitting}
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Optional — if omitted, the backend reads <code>project_id</code> from the service account JSON.
            </p>
          </div>

          {/* Service Account JSON */}
          <div>
            <label htmlFor="gcp-service-account" style={LABEL_STYLE}>Service Account JSON</label>
            <textarea
              id="gcp-service-account"
              value={serviceAccountJson}
              onChange={(e) => setServiceAccountJson(e.target.value)}
              placeholder="Paste the full service account JSON file contents here"
              disabled={submitting}
              rows={10}
              autoComplete="off"
              spellCheck={false}
              style={{
                ...INPUT_STYLE,
                fontFamily: "monospace",
                fontSize: "12px",
                lineHeight: 1.5,
                resize: "vertical",
                opacity: submitting ? 0.6 : 1,
              }}
            />
            <p style={HELPER_STYLE}>
              IAM &amp; Admin → Service Accounts → Keys → Create new key → JSON.
              The entire JSON (including the private_key) is stored encrypted
              and never returned by the backend.
            </p>
          </div>

          {/* Trust note */}
          <p style={{ margin: 0, fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
            ConfigTrace stores Google Cloud credentials encrypted and uses them
            only to read selected configuration metadata. It does not store
            private keys, OAuth tokens, principal emails, raw IAM payloads,
            secret payloads, or customer data in findings.
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
              {submitting ? "Connecting…" : "Connect Google Cloud"}
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
