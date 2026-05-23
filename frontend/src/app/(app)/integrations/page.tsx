"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import type { Integration } from "@/types";
import { getIntegrations } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import IntegrationList from "@/components/integrations/IntegrationList";
import CloudflareIntegrationForm from "@/components/integrations/CloudflareIntegrationForm";
import GitHubIntegrationForm from "@/components/integrations/GitHubIntegrationForm";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";

type Provider = "cloudflare" | "github";

// ── SetupSteps helper component ───────────────────────────────────────────────

interface StepDef {
  heading: string;
  body: React.ReactNode;
}

function SetupSteps({ steps }: { steps: StepDef[] }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
      {steps.map((step, idx) => (
        <div key={idx} style={{ display: "flex", gap: "12px", alignItems: "flex-start" }}>
          <span
            style={{
              flexShrink: 0,
              width: "18px",
              height: "18px",
              borderRadius: "50%",
              background: "#1e2030",
              border: "1px solid #3a3d4a",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: "10px",
              color: "#565b6e",
              fontWeight: 700,
              marginTop: "1px",
            }}
          >
            {idx + 1}
          </span>
          <p style={{ margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
            <span style={{ color: "#e8eaf0" }}>{step.heading}</span>{" "}
            {step.body}
          </p>
        </div>
      ))}
    </div>
  );
}

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState<Provider>("cloudflare");
  const { getToken, isLoaded } = useAuth();

  const fetchIntegrations = useCallback(async () => {
    setError(null);

    try {
      const token = await getToken();
      const data = await getIntegrations(token);
      setIntegrations(data.integrations);
      setTotal(data.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load integrations.");
    } finally {
      setLoading(false);
    }
  }, [getToken]);

  useEffect(() => {
    if (!isLoaded) return;
    fetchIntegrations();
  }, [isLoaded, fetchIntegrations]);

  function handleCreated() {
    // Hide the form and refresh the list.
    setShowForm(false);
    fetchIntegrations();
  }

  return (
    <>
      <PageHeader
        title="Integrations"
        description="Connect DNS providers, trigger manual syncs, and monitor sync status."
      />

      <div className="px-6 py-6">
        {/* ── First-time setup guide ────────────────────────────────────── */}
        {/* Shown before the user connects their first integration. Gives them
            enough context to choose a provider and gather credentials. */}
        {!loading && !error && total === 0 && !showForm && (
          <div
            className="mb-6"
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              padding: "20px 24px",
            }}
          >
            {/* Provider tabs */}
            <div style={{ display: "flex", gap: "8px", marginBottom: "18px" }}>
              {(["cloudflare", "github"] as Provider[]).map((p) => (
                <button
                  key={p}
                  onClick={() => setSelectedProvider(p)}
                  style={{
                    padding: "4px 12px",
                    borderRadius: "6px",
                    border: "1px solid",
                    fontSize: "11px",
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    cursor: "pointer",
                    fontFamily: "inherit",
                    fontWeight: selectedProvider === p ? 600 : 400,
                    background: selectedProvider === p ? "rgba(79,128,247,0.12)" : "#1c1e26",
                    color: selectedProvider === p ? "#4f80f7" : "#8b90a0",
                    borderColor: selectedProvider === p ? "rgba(79,128,247,0.35)" : "#2a2d38",
                  }}
                >
                  {p === "cloudflare" ? "Cloudflare" : "GitHub"}
                </button>
              ))}
            </div>

            {/* Cloudflare guide */}
            {selectedProvider === "cloudflare" && (
              <>
                <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
                  How to connect Cloudflare DNS
                </p>
                <SetupSteps steps={[
                  {
                    heading: "Create a scoped API token.",
                    body: <>In the Cloudflare dashboard → My Profile → API Tokens → Create Token.
                      Use the <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Edit zone DNS</code> template,
                      then restrict permissions to <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Zone → DNS → Read</code> and scope it to a specific zone only.</>,
                  },
                  {
                    heading: "Find your Zone ID.",
                    body: <>Cloudflare dashboard → select your domain → Overview page → scroll to the right sidebar. It&apos;s a 32-character hex string.</>,
                  },
                  {
                    heading: "Connect below.",
                    body: <>Paste both into the form. ConfigTrace validates the token against the live Cloudflare API before saving.</>,
                  },
                ]} />
                <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
                  Your token is encrypted before storage and never returned in any API response.
                  ConfigTrace only requests read-only access — it cannot modify your DNS records.
                </p>
              </>
            )}

            {/* GitHub guide */}
            {selectedProvider === "github" && (
              <>
                <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
                  How to connect a GitHub repository
                </p>
                <SetupSteps steps={[
                  {
                    heading: "Create a fine-grained Personal Access Token.",
                    body: <>GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token.
                      Set the resource owner, choose &ldquo;Only select repositories&rdquo;, and pick your repository.</>,
                  },
                  {
                    heading: "Grant the minimum required permissions.",
                    body: <>Under Repository permissions set:
                      {" "}<code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Metadata: Read</code>,
                      {" "}<code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Administration: Read</code>,
                      {" "}<code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Secrets: Read</code>,
                      {" "}<code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Variables: Read</code>.
                      Leave all other permissions at &ldquo;No access&rdquo;.</>,
                  },
                  {
                    heading: "Connect below.",
                    body: <>Enter the repository owner, repository name, and paste the token. ConfigTrace validates access before saving.</>,
                  },
                ]} />
                <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
                  Your token is encrypted before storage and never returned in any API response.
                  ConfigTrace uses read-only permissions — it cannot modify your repository.
                </p>
              </>
            )}
          </div>
        )}

        {/* ── Connect form (toggle) ─────────────────────────────────────── */}
        {!showForm ? (
          <div className="mb-6" style={{ display: "flex", gap: "8px" }}>
            <button
              onClick={() => { setSelectedProvider("cloudflare"); setShowForm(true); }}
              style={{
                background: "#4f80f7",
                color: "#ffffff",
                border: "none",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 500,
                cursor: "pointer",
                fontFamily: "inherit",
              }}
            >
              Add Cloudflare Integration
            </button>
            <button
              onClick={() => { setSelectedProvider("github"); setShowForm(true); }}
              style={{
                background: "#1e2030",
                color: "#b0b5c4",
                border: "1px solid #3a3d4a",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 500,
                cursor: "pointer",
                fontFamily: "inherit",
              }}
            >
              Add GitHub Integration
            </button>
          </div>
        ) : selectedProvider === "cloudflare" ? (
          <CloudflareIntegrationForm
            onCreated={handleCreated}
            onCancel={() => setShowForm(false)}
          />
        ) : (
          <GitHubIntegrationForm
            onCreated={handleCreated}
            onCancel={() => setShowForm(false)}
          />
        )}

        {/* ── Integration count + scheduled-sync notice ─────────────────── */}
        {/* The hourly-sync hint appears only when at least one integration
            exists — for empty-state users the setup guide above covers context. */}
        {!loading && !error && total > 0 && (
          <div
            className="mb-4 flex flex-wrap items-center"
            style={{ gap: "10px", fontSize: "12px", color: "#8b90a0" }}
          >
            <span>
              {total} integration{total === 1 ? "" : "s"} connected
            </span>
            <span style={{ color: "#3a3d4a" }}>·</span>
            <span title="Celery Beat fires at minute 0 of every UTC hour">
              Hourly sync: active
            </span>
            <span style={{ color: "#3a3d4a" }}>·</span>
            <span style={{ color: "#565b6e" }} title="Requires RESEND_API_KEY and ALERTS_FROM_EMAIL configured in Render">
              Email alerts: high-risk and critical changes only
            </span>
          </div>
        )}

        {/* ── Content ───────────────────────────────────────────────────── */}
        {loading && <LoadingState />}
        {!loading && error && (
          <div>
            <ErrorState message={error} />
            <div className="flex justify-center mt-4">
              <button
                onClick={fetchIntegrations}
                style={{
                  background: "transparent",
                  border: "1px solid #4f80f7",
                  color: "#4f80f7",
                  borderRadius: "6px",
                  padding: "6px 14px",
                  fontSize: "13px",
                  cursor: "pointer",
                  fontFamily: "inherit",
                }}
              >
                Retry
              </button>
            </div>
          </div>
        )}
        {!loading && !error && (
          <IntegrationList
            integrations={integrations}
            onSyncComplete={fetchIntegrations}
          />
        )}
      </div>
    </>
  );
}
