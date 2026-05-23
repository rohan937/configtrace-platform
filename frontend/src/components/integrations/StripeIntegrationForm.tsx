"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface StripeIntegrationFormProps {
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
 * Inline form for connecting a Stripe account integration.
 *
 * The API key is sent to the backend once and immediately cleared from
 * state on success.  It is never logged, never stored in localStorage or
 * sessionStorage, and never rendered after submission.
 *
 * SECURITY: Only account-level configuration is monitored.  Customer PII,
 * payment data (charges, invoices, subscriptions), and webhook signing
 * secrets are NEVER fetched or stored by ConfigTrace.
 */
export default function StripeIntegrationForm({
  onCreated,
  onCancel,
}: StripeIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const { getToken } = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim() || !apiKey.trim()) {
      setError("Both fields are required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider: "stripe",
          display_name: displayName.trim(),
          stripe_api_key: apiKey,  // sent once; cleared below
        },
        token,
      );

      // Clear the sensitive field immediately — do not keep it in state.
      setApiKey("");
      setSuccessMsg("Stripe account connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your API key and try again.",
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
      {/* Section heading */}
      <div
        style={{
          fontSize: "11px",
          color: "#8b90a0",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: "16px",
        }}
      >
        Connect Stripe Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

          {/* Display name */}
          <div>
            <label htmlFor="stripe-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="stripe-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Stripe"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise
              later, e.g. &ldquo;Production Stripe&rdquo;.
            </p>
          </div>

          {/* API key — type=password to prevent shoulder-surfing */}
          <div>
            <label htmlFor="stripe-api-key" style={LABEL_STYLE}>
              Stripe API Key
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
                Restricted key recommended
              </span>
            </label>
            <input
              id="stripe-api-key"
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="rk_live_… or rk_test_…  (sk_live_… also accepted)"
              disabled={submitting}
              autoComplete="new-password"
              style={{
                ...INPUT_STYLE,
                fontFamily: "monospace",
                opacity: submitting ? 0.6 : 1,
              }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              Use a <strong style={{ color: "#8b90a0" }}>restricted key</strong> (
              <code style={{ fontSize: "11px" }}>rk_live_…</code> or{" "}
              <code style={{ fontSize: "11px" }}>rk_test_…</code>) for least-privilege
              access. Standard secret keys (<code style={{ fontSize: "11px" }}>sk_…</code>)
              are also accepted but grant broader access than needed.
            </p>

            {/* Permissions note */}
            <div
              style={{
                marginTop: "8px",
                background: "#13151a",
                border: "1px solid #2a2d38",
                borderRadius: "4px",
                padding: "10px 12px",
                fontSize: "11px",
                color: "#565b6e",
                lineHeight: 1.75,
              }}
            >
              <span style={{ color: "#8b90a0", display: "block", marginBottom: "4px", fontWeight: 500 }}>
                Minimum required permissions for restricted key (read-only):
              </span>
              <span style={{ color: "#6b7080" }}>
                ✓ Webhook Endpoints — Read
              </span>
              <br />
              <span style={{ color: "#565b6e" }}>
                ○ Account settings — Read{" "}
                <span style={{ color: "#3a3d4a", fontStyle: "italic" }}>(optional — skipped if unavailable)</span>
              </span>
              <br />
              <span style={{ color: "#565b6e" }}>
                ○ Payment Method Configurations — Read{" "}
                <span style={{ color: "#3a3d4a", fontStyle: "italic" }}>(optional)</span>
              </span>
              <br />
              <span style={{ color: "#565b6e" }}>
                ○ Payment Method Domains — Read{" "}
                <span style={{ color: "#3a3d4a", fontStyle: "italic" }}>(optional)</span>
              </span>
              <br />
              <span style={{ color: "#3a3d4a", marginTop: "4px", display: "block" }}>
                Customer data, payment history, and signing secrets are never accessed.
              </span>
            </div>
          </div>

          {/* Inline error */}
          {error && (
            <p style={{ fontSize: "13px", color: "#e84040", margin: 0 }}>
              {error}
            </p>
          )}

          {/* Inline success */}
          {successMsg && (
            <p style={{ fontSize: "13px", color: "#3ccf7e", margin: 0 }}>
              {successMsg}
            </p>
          )}

          {/* Buttons */}
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
              {submitting ? "Validating…" : "Connect Stripe"}
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
