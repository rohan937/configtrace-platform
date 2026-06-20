"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";
import type { IntegrationCreateRequest } from "@/types";

interface TerraformCloudIntegrationFormProps {
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
 * Inline form for connecting a Terraform Cloud organization.
 *
 * Requires a Terraform Cloud team or user API token. The token is sent to the
 * backend once and immediately cleared from state on success. It is never
 * logged, never stored in localStorage or sessionStorage, and never rendered
 * after submission.
 *
 * SECURITY: only organization and workspace configuration metadata is
 * monitored. API token values, organization names (in records), workspace
 * names, project names, variable names or values, state file contents,
 * plan/apply logs, VCS URLs, branch names, team names, user emails, usernames,
 * and customer infrastructure data are never accessed or stored.
 */
export default function TerraformCloudIntegrationForm({
  onCreated,
  onCancel,
}: TerraformCloudIntegrationFormProps) {
  const [displayName, setDisplayName]   = useState("");
  const [apiToken, setApiToken]         = useState("");
  const [organization, setOrganization] = useState("");
  const [baseUrl, setBaseUrl]           = useState("");
  const [submitting, setSubmitting]     = useState(false);
  const [error, setError]               = useState<string | null>(null);
  const [successMsg, setSuccessMsg]     = useState<string | null>(null);
  const { getToken }                    = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim()) {
      setError("Display name is required.");
      return;
    }
    if (!apiToken.trim()) {
      setError("Terraform Cloud API token is required.");
      return;
    }
    if (!organization.trim()) {
      setError("Terraform Cloud organization is required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      const payload: IntegrationCreateRequest = {
        provider:                       "terraform_cloud",
        display_name:                   displayName.trim(),
        terraform_cloud_api_token:      apiToken,      // sent once; cleared below
        terraform_cloud_organization:   organization.trim(),
      };
      if (baseUrl.trim()) {
        payload.terraform_cloud_base_url = baseUrl.trim();
      }
      await createIntegration(payload, token);

      // Clear sensitive field immediately — do not keep it in state.
      setApiToken("");
      setSuccessMsg("Terraform Cloud connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your API token and organization name and try again.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  const canSubmit =
    !!displayName.trim() && !!apiToken.trim() && !!organization.trim();

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
        Connect Terraform Cloud Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="tc-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="tc-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Terraform Cloud"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* API token */}
          <div>
            <label htmlFor="tc-api-token" style={LABEL_STYLE}>
              API Token
            </label>
            <input
              id="tc-api-token"
              type="password"
              value={apiToken}
              onChange={(e) => setApiToken(e.target.value)}
              placeholder="••••••••••••••••"
              disabled={submitting}
              autoComplete="new-password"
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Team or user API token from{" "}
              <strong style={{ color: "#8b90a0" }}>
                app.terraform.io → User Settings → Tokens
              </strong>
              . Stored encrypted — never returned in any response.
            </p>
          </div>

          {/* Organization */}
          <div>
            <label htmlFor="tc-organization" style={LABEL_STYLE}>
              Organization
            </label>
            <input
              id="tc-organization"
              type="text"
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
              placeholder="your-org-name"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Your Terraform Cloud organization name slug. Used only as an API
              path parameter — never stored in configuration records.
            </p>
          </div>

          {/* Base URL (optional) */}
          <div>
            <label htmlFor="tc-base-url" style={LABEL_STYLE}>
              Base URL{" "}
              <span style={{ color: "#3a3d4a", fontWeight: 400 }}>(optional)</span>
            </label>
            <input
              id="tc-base-url"
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://app.terraform.io"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Leave blank for Terraform Cloud (app.terraform.io). For Terraform
              Enterprise or self-managed, enter your instance URL.
            </p>
          </div>

          {/* Error / success */}
          {error && (
            <p style={{ margin: 0, fontSize: "13px", color: "#f87171" }}>
              {error}
            </p>
          )}
          {successMsg && (
            <p style={{ margin: 0, fontSize: "13px", color: "#4ade80" }}>
              {successMsg}
            </p>
          )}

          {/* Actions */}
          <div
            style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}
          >
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
                background: "#7B42BC",
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
              {submitting ? "Connecting…" : "Connect Terraform Cloud"}
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
        ConfigTrace stores Terraform Cloud credentials encrypted and uses them only to read
        selected configuration metadata. It does not store API token values, organization
        names, workspace names, project names, variable set names, variable names, variable
        values, state file contents, plan/apply logs, VCS repository URLs, branch names,
        team names, user emails, usernames, or customer infrastructure data.
        Terraform Cloud drift snapshots and risk classification are in foundation stage.
        Security rules planned next.
      </p>
    </div>
  );
}
