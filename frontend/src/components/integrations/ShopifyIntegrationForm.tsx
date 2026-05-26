"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface ShopifyIntegrationFormProps {
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

/** Normalize a Shopify shop domain the same way the backend does. */
function normalizeShopDomain(raw: string): string {
  let domain = raw.trim().toLowerCase();
  if (domain.startsWith("https://")) domain = domain.slice(8);
  if (domain.startsWith("http://"))  domain = domain.slice(7);
  return domain.replace(/\/$/, "");
}

/** Basic client-side validation for shop domain. */
function validateShopDomain(domain: string): string | null {
  if (!domain) return "Shop domain is required.";
  const blocked = [
    "localhost", "127.", "0.0.0.0", "::1",
    ".local", ".internal", ".corp", ".example", ".test", ".invalid",
  ];
  for (const b of blocked) {
    if (domain.includes(b)) {
      return `Shop domain cannot be a local or internal address (blocked: ${b}).`;
    }
  }
  // Must look like a hostname
  if (!/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) {
    return "Enter a valid shop domain, e.g. mystore.myshopify.com";
  }
  return null;
}

/**
 * Inline form for connecting a Shopify store integration.
 *
 * The Admin API access token is sent to the backend once and immediately
 * cleared from state on success.  It is never logged, never stored in
 * localStorage or sessionStorage, and never rendered after submission.
 *
 * SECURITY: Only store configuration metadata is monitored.  Orders,
 * customers, payment data, transaction records, and storefront theme
 * files are NEVER fetched or stored by ConfigTrace.
 */
export default function ShopifyIntegrationForm({
  onCreated,
  onCancel,
}: ShopifyIntegrationFormProps) {
  const [displayName, setDisplayName]   = useState("");
  const [shopDomain, setShopDomain]     = useState("");
  const [accessToken, setAccessToken]   = useState("");
  const [submitting, setSubmitting]     = useState(false);
  const [error, setError]               = useState<string | null>(null);
  const [successMsg, setSuccessMsg]     = useState<string | null>(null);
  const { getToken } = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim()) {
      setError("Display name is required.");
      return;
    }

    const normalizedDomain = normalizeShopDomain(shopDomain);
    const domainError = validateShopDomain(normalizedDomain);
    if (domainError) {
      setError(domainError);
      return;
    }

    if (!accessToken.trim()) {
      setError("Admin API access token is required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider: "shopify",
          display_name: displayName.trim(),
          shopify_shop_domain: normalizedDomain,
          // sent once; cleared below immediately after success
          shopify_access_token: accessToken.trim(),
        },
        token
      );

      // Clear the sensitive field immediately — do not keep it in state.
      setAccessToken("");
      setSuccessMsg("Shopify store connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your shop domain and access token and try again."
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
        Connect Shopify Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

          {/* Display name */}
          <div>
            <label htmlFor="shopify-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="shopify-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Shopify Store"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#96bf48"; }}
              onBlur={(e)  => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — e.g. &ldquo;Production Shopify Store&rdquo;.
            </p>
          </div>

          {/* Shop domain */}
          <div>
            <label htmlFor="shopify-shop-domain" style={LABEL_STYLE}>
              Shop Domain
            </label>
            <input
              id="shopify-shop-domain"
              type="text"
              value={shopDomain}
              onChange={(e) => setShopDomain(e.target.value)}
              placeholder="mystore.myshopify.com"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#96bf48"; }}
              onBlur={(e)  => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              Your Shopify store domain, e.g.{" "}
              <code style={{ fontSize: "11px" }}>mystore.myshopify.com</code>.
              Custom domains are also accepted. Do not include{" "}
              <code style={{ fontSize: "11px" }}>https://</code>.
            </p>
          </div>

          {/* Admin API access token */}
          <div>
            <label htmlFor="shopify-access-token" style={LABEL_STYLE}>
              Admin API Access Token
              <span
                style={{
                  marginLeft: "6px",
                  background: "rgba(150,191,72,0.15)",
                  color: "#96bf48",
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
              id="shopify-access-token"
              type="password"
              value={accessToken}
              onChange={(e) => setAccessToken(e.target.value)}
              placeholder="shpat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...INPUT_STYLE, fontFamily: "monospace", opacity: submitting ? 0.6 : 1 }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#96bf48"; }}
              onBlur={(e)  => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              Create a custom app in your Shopify admin under{" "}
              <code style={{ fontSize: "11px" }}>
                Apps → Develop apps → Create an app
              </code>
              , then generate an Admin API access token with read-only config
              permissions. Tokens beginning with{" "}
              <code style={{ fontSize: "11px" }}>shpat_</code> are recommended.
            </p>

            {/* Permissions / trust note */}
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
              <span
                style={{
                  color: "#8b90a0",
                  display: "block",
                  marginBottom: "4px",
                  fontWeight: 500,
                }}
              >
                What ConfigTrace reads (read-only):
              </span>
              <span style={{ color: "#6b7080" }}>
                ✓ Store metadata (plan, timezone, currency, locale)
              </span>
              <br />
              <span style={{ color: "#6b7080" }}>
                ✓ Storefront settings (password protection, checkout config)
              </span>
              <br />
              <span style={{ color: "#6b7080" }}>
                ✓ Webhook subscriptions (domain and topic — URL path is hashed)
              </span>
              <br />
              <span style={{ color: "#6b7080" }}>
                ✓ Store policies (presence and content hash — raw text never stored)
              </span>
              <br />
              <span
                style={{
                  color: "#3a3d4a",
                  marginTop: "4px",
                  display: "block",
                }}
              >
                Orders, customers, payment data, transaction records, gift cards,
                and storefront theme files are never accessed or stored.
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
                background: submitting ? "#2a3050" : "#96bf48",
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
              {submitting ? "Validating…" : "Connect Shopify"}
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
