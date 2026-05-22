"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import type { Integration } from "@/types";
import { getIntegrations } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import IntegrationList from "@/components/integrations/IntegrationList";
import CloudflareIntegrationForm from "@/components/integrations/CloudflareIntegrationForm";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
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
            everything they need to gather credentials without leaving the page. */}
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
            <p
              style={{
                margin: "0 0 14px",
                fontSize: "13px",
                fontWeight: 600,
                color: "#e8eaf0",
              }}
            >
              How to connect Cloudflare DNS
            </p>

            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              {/* Step 1 */}
              <div style={{ display: "flex", gap: "12px", alignItems: "flex-start" }}>
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
                  1
                </span>
                <p style={{ margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
                  <span style={{ color: "#e8eaf0" }}>Create a scoped API token.</span>
                  {" "}In the Cloudflare dashboard → My Profile → API Tokens → Create Token.
                  Use the{" "}
                  <span style={{ fontFamily: "monospace", color: "#b0b5c4" }}>
                    Edit zone DNS
                  </span>{" "}
                  template, then restrict permissions to{" "}
                  <span style={{ fontFamily: "monospace", color: "#b0b5c4" }}>
                    Zone → DNS → Read
                  </span>{" "}
                  and scope it to a specific zone only.
                </p>
              </div>

              {/* Step 2 */}
              <div style={{ display: "flex", gap: "12px", alignItems: "flex-start" }}>
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
                  2
                </span>
                <p style={{ margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
                  <span style={{ color: "#e8eaf0" }}>Find your Zone ID.</span>
                  {" "}Cloudflare dashboard → select your domain → Overview page →
                  scroll to the right sidebar. It&apos;s a 32-character hex string.
                </p>
              </div>

              {/* Step 3 */}
              <div style={{ display: "flex", gap: "12px", alignItems: "flex-start" }}>
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
                  3
                </span>
                <p style={{ margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
                  <span style={{ color: "#e8eaf0" }}>Connect below.</span>
                  {" "}Paste both into the form. ConfigTrace validates the token
                  against the live Cloudflare API before saving — if it lacks the
                  right permissions, you&apos;ll see an error before anything is stored.
                </p>
              </div>
            </div>

            {/* Safety note */}
            <p
              style={{
                margin: "14px 0 0",
                fontSize: "11px",
                color: "#3a3d4a",
                lineHeight: 1.6,
              }}
            >
              Your token is encrypted before storage and never returned in any API response.
              ConfigTrace only requests read-only access — it cannot modify your DNS records.
            </p>
          </div>
        )}

        {/* ── Connect form (toggle) ─────────────────────────────────────── */}
        {!showForm ? (
          <div className="mb-6">
            <button
              onClick={() => setShowForm(true)}
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
              Add New Integration
            </button>
          </div>
        ) : (
          <CloudflareIntegrationForm
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
