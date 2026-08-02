"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";
import type { IntegrationCreateRequest } from "@/types";

interface SentryIntegrationFormProps {
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
 * Inline form for connecting a Sentry organization (SaaS, sentry.io only —
 * no self-hosted, no custom base URL).
 *
 * The auth token is sent to the backend once and immediately cleared from
 * state on success. It is never logged, never stored in localStorage or
 * sessionStorage, and never rendered after submission — after a successful
 * connect only "Auth token configured" is shown, never the token itself.
 *
 * Validation (organization-identity query + bounded capability probes)
 * runs synchronously at creation time — an Invalid credential (rejected
 * token, malformed slug, or zero readable core families) is rejected here
 * instead of silently creating a seemingly healthy integration. Partial
 * coverage (some extended family unavailable to a narrowly-scoped token)
 * is accepted.
 */
export default function SentryIntegrationForm({
  onCreated,
  onCancel,
}: SentryIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [organizationSlug, setOrganizationSlug] = useState("");
  const [authToken, setAuthToken] = useState("");
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
    if (!organizationSlug.trim()) {
      setError("Sentry organization slug is required.");
      return;
    }
    if (!authToken.trim()) {
      setError("Sentry auth token is required.");
      return;
    }

    setSubmitting(true);

    try {
      const clerkToken = await getToken();
      const payload: IntegrationCreateRequest = {
        provider: "sentry",
        display_name: displayName.trim(),
        sentry_organization_slug: organizationSlug.trim(),
        sentry_auth_token: authToken, // sent once; cleared below
      };
      await createIntegration(payload, clerkToken);

      // Clear the sensitive field immediately — do not keep it in state.
      setAuthToken("");
      setSuccessMsg("Auth token configured. Sentry organization connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your organization slug and auth token, then try again."
      );
    } finally {
      setSubmitting(false);
    }
  }

  const canSubmit =
    !!displayName.trim() && !!organizationSlug.trim() && !!authToken.trim();

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
        Connect Sentry Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="sentry-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="sentry-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Sentry Organization"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* Least-privilege / setup notice */}
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
              Use an organization-owned internal integration token with
              read-only scopes. Do not use a personal token.
            </span>
            1. In Sentry, go to Settings → Developer Settings → New Internal
            Integration.
            <br />
            2. Give it a name (e.g. &ldquo;ConfigTrace Monitor&rdquo;) and add
            the permissions below.
            <br />
            3. Save the integration, then copy the generated token.
            <br />
            4. Paste the organization slug and token here.
            <br />
            <span style={{ color: "#3a3d4a", marginTop: "4px", display: "block" }}>
              Core scopes (recommended minimum): <code style={{ fontSize: "10px" }}>org: Read</code>,{" "}
              <code style={{ fontSize: "10px" }}>member: Read</code>. Extended
              scopes (optional, unlock additional coverage): <code style={{ fontSize: "10px" }}>alerts: Read</code>,{" "}
              <code style={{ fontSize: "10px" }}>project: Read</code>. ConfigTrace never
              needs write scopes. If a scope is missing, the connection still
              succeeds with Partial coverage — diagnostics show exactly which
              families are unavailable. Sentry SaaS (sentry.io) only — self-hosted
              Sentry is not supported.
            </span>
          </div>

          {/* Organization slug */}
          <div>
            <label htmlFor="sentry-organization-slug" style={LABEL_STYLE}>
              Sentry Organization Slug
            </label>
            <input
              id="sentry-organization-slug"
              type="text"
              value={organizationSlug}
              onChange={(e) => setOrganizationSlug(e.target.value)}
              placeholder="e.g. my-organization"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              The organization slug from your Sentry URL, e.g.{" "}
              <code style={{ fontSize: "10px" }}>sentry.io/organizations/my-organization/</code>.
              Not a URL — do not include <code style={{ fontSize: "10px" }}>https://</code>.
            </p>
          </div>

          {/* Auth token */}
          <div>
            <label htmlFor="sentry-auth-token" style={LABEL_STYLE}>
              Sentry Auth Token
              <span
                style={{
                  marginLeft: "6px",
                  background: "rgba(54,45,89,0.15)",
                  color: "#a996e8",
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
              id="sentry-auth-token"
              type="password"
              value={authToken}
              onChange={(e) => setAuthToken(e.target.value)}
              placeholder="Organization auth token"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              An organization-owned internal integration token, scoped to
              read-only permissions. Never echoed back after saving — only
              &ldquo;Auth token configured&rdquo; is shown once connected.
              Rotate or revoke it in Sentry whenever needed.
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
                background: "#362D59",
                border: "none",
                borderRadius: "6px",
                color: "#f1eefa",
                fontSize: "13px",
                fontWeight: 600,
                padding: "7px 16px",
                cursor: submitting ? "not-allowed" : "pointer",
                opacity: submitting ? 0.7 : 1,
              }}
            >
              {submitting ? "Validating…" : "Connect Sentry"}
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
        ConfigTrace stores your Sentry auth token encrypted and uses it only
        to read configuration metadata via read-only GET requests — it never
        modifies your Sentry organization. The token value is never included
        in snapshots, Findings, Changes, diagnostics, or logs. Coverage may
        be Partial if some metadata families are not readable by the
        supplied token — grouped connection diagnostics are shown once
        connected. Only Sentry SaaS (sentry.io) is supported; ConfigTrace
        does not ingest issue events, error data, stack traces, breadcrumbs,
        session replays, performance spans, or DSNs.
      </p>
    </div>
  );
}
