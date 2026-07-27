"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";
import type { IntegrationCreateRequest } from "@/types";

interface OktaIntegrationFormProps {
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
 * Inline form for connecting an Okta org.
 *
 * The API token is sent to the backend once and immediately cleared from
 * state on success. It is never logged, never stored in localStorage or
 * sessionStorage, and never rendered after submission — after a successful
 * connect only "API token configured" is shown, never the token itself.
 *
 * SECURITY: Okta API tokens inherit the exact permissions of the admin
 * account that generated them — there is no separate token-scoping
 * mechanism. ConfigTrace never requests broader access than that account
 * already has.
 */
export default function OktaIntegrationForm({
  onCreated,
  onCancel,
}: OktaIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [orgUrl, setOrgUrl] = useState("");
  const [apiToken, setApiToken] = useState("");
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
    if (!orgUrl.trim()) {
      setError("Okta org URL is required.");
      return;
    }
    if (!apiToken.trim()) {
      setError("API token is required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      const payload: IntegrationCreateRequest = {
        provider: "okta",
        display_name: displayName.trim(),
        okta_org_url: orgUrl.trim(),
        okta_api_token: apiToken, // sent once; cleared below
      };
      await createIntegration(payload, token);

      // Clear the sensitive field immediately — do not keep it in state.
      setApiToken("");
      setSuccessMsg("API token configured. Okta org connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your org URL and API token and try again."
      );
    } finally {
      setSubmitting(false);
    }
  }

  const canSubmit = !!displayName.trim() && !!orgUrl.trim() && !!apiToken.trim();

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
        Connect Okta Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="okta-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="okta-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Okta Org"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* Least-privilege notice */}
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
              Use a dedicated, least-privileged admin account to generate this token.
              Do not use a Super Admin account unless your org has no narrower option.
            </span>
            Okta API tokens inherit the exact permissions of the administrator
            account that generated them — there is no separate scoping
            mechanism for classic API tokens. Create a dedicated service
            account assigned the built-in{" "}
            <code style={{ fontSize: "10px" }}>Read-Only Administrator</code>{" "}
            role (or a custom admin role with equivalent read access to
            Users, Groups, Applications, Authentication Policies, and
            Administrator Role assignments), then generate the API token
            from that account.
            <br />
            <span style={{ color: "#3a3d4a", marginTop: "4px", display: "block" }}>
              A least-privileged role may not be able to read every optional
              family (e.g. custom admin roles) — that is expected and does
              not block the connection; coverage diagnostics are shown after
              the first sync.
            </span>
          </div>

          {/* Org URL */}
          <div>
            <label htmlFor="okta-org-url" style={LABEL_STYLE}>
              Okta Org URL
            </label>
            <input
              id="okta-org-url"
              type="text"
              value={orgUrl}
              onChange={(e) => setOrgUrl(e.target.value)}
              placeholder="https://example.okta.com"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Your Okta org base URL, including a custom domain if you use one.
            </p>
          </div>

          {/* API token */}
          <div>
            <label htmlFor="okta-api-token" style={LABEL_STYLE}>
              API Token
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
              id="okta-api-token"
              type="password"
              value={apiToken}
              onChange={(e) => setApiToken(e.target.value)}
              placeholder="Okta API token"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Generate from Security → API → Tokens in the Okta Admin
              Console. Never echoed back after saving — only &ldquo;API
              token configured&rdquo; is shown once connected.
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
                background: "#007DC1",
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
              {submitting ? "Validating…" : "Connect Okta"}
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
        ConfigTrace stores your Okta API token encrypted and uses it only to
        read org configuration metadata. It does not store the token value,
        passwords, password hashes, recovery answers, MFA secrets, OTP seeds,
        session/refresh/access tokens, private keys, or System Log payloads.
        Coverage may be partial if some API families are not readable by the
        supplied credential — connection diagnostics are shown after the
        first sync.
      </p>
    </div>
  );
}
