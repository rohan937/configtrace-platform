"use client";

import { useEffect, useState } from "react";
import type { Integration } from "@/types";
import { getIntegrations } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import IntegrationList from "@/components/integrations/IntegrationList";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    getIntegrations()
      .then((data) => {
        if (!cancelled) {
          setIntegrations(data.integrations);
          setTotal(data.total);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load integrations.");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => { cancelled = true; };
  }, []);

  return (
    <>
      <PageHeader
        title="Integrations"
        description="Manage connected DNS providers and trigger syncs."
      />

      <div className="px-6 py-6">
        {!loading && !error && total > 0 && (
          <p className="mb-4" style={{ fontSize: "13px", color: "#8b90a0" }}>
            {total} integration{total === 1 ? "" : "s"} configured
          </p>
        )}

        {loading && <LoadingState />}
        {!loading && error && <ErrorState message={error} />}
        {!loading && !error && <IntegrationList integrations={integrations} />}
      </div>
    </>
  );
}
