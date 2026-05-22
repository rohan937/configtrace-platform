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
        {/* ── First-time onboarding note ────────────────────────────────── */}
        {/* Only shown when the user has zero integrations connected. Gives
            them the bare-minimum mental model before they click Add. */}
        {!loading && !error && total === 0 && !showForm && (
          <div
            className="mb-6"
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              padding: "16px 20px",
              fontSize: "13px",
              color: "#8b90a0",
              lineHeight: 1.6,
            }}
          >
            <p style={{ color: "#e8eaf0", marginBottom: "6px", fontWeight: 500 }}>
              ConfigTrace MVP — Cloudflare DNS
            </p>
            <p style={{ margin: 0 }}>
              The current MVP tracks Cloudflare DNS zones. You&apos;ll need a
              scoped Cloudflare API token with Zone DNS Read access and the Zone
              ID from your domain&apos;s Overview page. The token is encrypted
              before storage. The first sync creates a baseline; later syncs
              detect changes against it.
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

        {/* ── Integration count ─────────────────────────────────────────── */}
        {!loading && !error && total > 0 && (
          <p className="mb-4" style={{ fontSize: "13px", color: "#8b90a0" }}>
            {total} integration{total === 1 ? "" : "s"} connected
          </p>
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
