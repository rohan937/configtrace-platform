"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";
import type { IntegrationCreateRequest } from "@/types";

interface SnowflakeIntegrationFormProps {
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
 * Inline form for connecting a Snowflake account.
 *
 * The Programmatic Access Token is sent to the backend once and
 * immediately cleared from state on success. It is never logged, never
 * stored in localStorage or sessionStorage, and never rendered after
 * submission — after a successful connect only "Programmatic Access
 * Token configured" is shown, never the token itself.
 *
 * Validation (account-identity query + bounded capability probes) runs
 * synchronously at creation time — an Invalid credential (rejected PAT,
 * malformed account/username/role, or zero readable core families) is
 * rejected here instead of silently creating a seemingly healthy
 * integration. Partial coverage (some optional/elevated-visibility
 * family unavailable to the monitoring role) is accepted.
 */
export default function SnowflakeIntegrationForm({
  onCreated,
  onCancel,
}: SnowflakeIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [accountIdentifier, setAccountIdentifier] = useState("");
  const [username, setUsername] = useState("");
  const [token, setToken] = useState("");
  const [role, setRole] = useState("");
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
    if (!accountIdentifier.trim()) {
      setError("Snowflake account identifier is required.");
      return;
    }
    if (!username.trim()) {
      setError("Snowflake username is required.");
      return;
    }
    if (!token.trim()) {
      setError("Programmatic Access Token is required.");
      return;
    }
    if (!role.trim()) {
      setError("Snowflake monitoring role is required.");
      return;
    }

    setSubmitting(true);

    try {
      const clerkToken = await getToken();
      const payload: IntegrationCreateRequest = {
        provider: "snowflake",
        display_name: displayName.trim(),
        snowflake_account_identifier: accountIdentifier.trim(),
        snowflake_username: username.trim(),
        snowflake_programmatic_access_token: token, // sent once; cleared below
        snowflake_role: role.trim(),
      };
      await createIntegration(payload, clerkToken);

      // Clear the sensitive field immediately — do not keep it in state.
      setToken("");
      setSuccessMsg("Programmatic Access Token configured. Snowflake account connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your account identifier, username, token, and role, then try again."
      );
    } finally {
      setSubmitting(false);
    }
  }

  const canSubmit =
    !!displayName.trim() &&
    !!accountIdentifier.trim() &&
    !!username.trim() &&
    !!token.trim() &&
    !!role.trim();

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
        Connect Snowflake Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="snowflake-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="snowflake-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Snowflake Account"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* Least-privilege / dedicated service-user notice */}
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
              Use a dedicated Snowflake service user, a dedicated read-only
              monitoring role, and a role-restricted Programmatic Access
              Token. Do not use ACCOUNTADMIN or SECURITYADMIN for routine
              monitoring.
            </span>
            1. Create a dedicated Snowflake service user.
            <br />
            2. Create a read-only monitoring role.
            <br />
            3. Grant the role access to the metadata ConfigTrace should
            monitor.
            <br />
            4. Grant the monitoring role to the service user.
            <br />
            5. Create a Programmatic Access Token restricted to the
            monitoring role.
            <br />
            <span style={{ color: "#3a3d4a", marginTop: "4px", display: "block" }}>
              ConfigTrace does not require an administrative role for
              normal operation, though some metadata families (network
              policies, authentication policies, security/storage/
              external-access integrations, and full grant visibility) may
              require additional visibility grants — that is expected and
              does not block the connection; the integration connects with
              Partial coverage and diagnostics show exactly which families
              are unavailable. No active warehouse is required for the
              current ConfigTrace Snowflake connector.
            </span>
          </div>

          {/* Account identifier */}
          <div>
            <label htmlFor="snowflake-account-identifier" style={LABEL_STYLE}>
              Snowflake Account Identifier
            </label>
            <input
              id="snowflake-account-identifier"
              type="text"
              value={accountIdentifier}
              onChange={(e) => setAccountIdentifier(e.target.value)}
              placeholder="e.g. myorg-myaccount"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              The organization-name/account-name form (preferred) or a
              legacy account-locator form. Not a URL — do not include{" "}
              <code style={{ fontSize: "10px" }}>https://</code> or{" "}
              <code style={{ fontSize: "10px" }}>.snowflakecomputing.com</code>.
            </p>
          </div>

          {/* Username */}
          <div>
            <label htmlFor="snowflake-username" style={LABEL_STYLE}>
              Snowflake Username
            </label>
            <input
              id="snowflake-username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. CONFIGTRACE_MONITOR"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              The dedicated service user the Programmatic Access Token
              belongs to.
            </p>
          </div>

          {/* Programmatic Access Token */}
          <div>
            <label htmlFor="snowflake-pat" style={LABEL_STYLE}>
              Programmatic Access Token
              <span
                style={{
                  marginLeft: "6px",
                  background: "rgba(41,181,232,0.15)",
                  color: "#29B5E8",
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
              id="snowflake-pat"
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="Programmatic Access Token"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Restrict this token to the monitoring role below. Never
              echoed back after saving — only &ldquo;Programmatic Access
              Token configured&rdquo; is shown once connected. Rotate or
              revoke it in Snowflake whenever needed.
            </p>
          </div>

          {/* Monitoring role */}
          <div>
            <label htmlFor="snowflake-role" style={LABEL_STYLE}>
              Snowflake Monitoring Role
            </label>
            <input
              id="snowflake-role"
              type="text"
              value={role}
              onChange={(e) => setRole(e.target.value)}
              placeholder="e.g. CONFIGTRACE_MONITOR"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Use a dedicated read-only role with access to the metadata
              ConfigTrace should monitor.
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
                background: "#29B5E8",
                border: "none",
                borderRadius: "6px",
                color: "#0b1a1f",
                fontSize: "13px",
                fontWeight: 600,
                padding: "7px 16px",
                cursor: submitting ? "not-allowed" : "pointer",
                opacity: submitting ? 0.7 : 1,
              }}
            >
              {submitting ? "Validating…" : "Connect Snowflake"}
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
        ConfigTrace stores your Snowflake Programmatic Access Token
        encrypted and uses it only to read configuration metadata via
        read-only SHOW/DESCRIBE/SELECT statements over the Snowflake SQL
        API — it never runs CREATE, ALTER, DROP, GRANT, REVOKE, or any
        other mutating statement. The token value is never included in
        snapshots, Findings, Changes, diagnostics, or logs. Coverage may
        be Partial if some metadata families are not readable by the
        supplied role — grouped connection diagnostics are shown once
        connected, without listing every low-level statement.
      </p>
    </div>
  );
}
