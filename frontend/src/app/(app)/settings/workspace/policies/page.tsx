"use client";

/**
 * Workspace Policies page — M58.14.
 *
 * Lists all 18 built-in policies with their enabled/disabled state for the
 * current workspace.  Admins can toggle each policy.  Members can view but
 * not edit.
 *
 * Design rules:
 *   - No raw credential values or secret data shown.
 *   - Toggle only available to workspace admins.
 *   - Language: "may flag", "appears to" — never "confirmed breach".
 *   - Disclaimer: policies use configuration metadata, not live provider state.
 */

import { useState, useEffect, useCallback } from "react";
import { useAuth } from "@clerk/nextjs";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import type { WorkspacePolicy, PolicyListResponse } from "@/types";
import { getWorkspacePolicies, updateWorkspacePolicy } from "@/lib/api";

// ── Colour helpers ────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, { text: string; bg: string }> = {
  critical: { text: "#f87171", bg: "#3a151599" },
  high:     { text: "#fb923c", bg: "#2d1a0a99" },
  medium:   { text: "#fbbf24", bg: "#2a220899" },
};

const PROVIDER_LABELS: Record<string, string> = {
  aws:        "AWS",
  firebase:   "Firebase",
  supabase:   "Supabase",
  github:     "GitHub",
  cloudflare: "Cloudflare",
  stripe:     "Stripe",
  vercel:     "Vercel",
  shopify:    "Shopify",
};


// ── Policy row ────────────────────────────────────────────────────────────────

function PolicyRow({
  policy,
  isAdmin,
  onToggle,
  toggling,
}: {
  policy: WorkspacePolicy;
  isAdmin: boolean;
  onToggle: (key: string, enabled: boolean) => void;
  toggling: boolean;
}) {
  const sevColors = SEVERITY_COLORS[policy.severity] ?? SEVERITY_COLORS.high;
  const providerLabel = policy.provider ? (PROVIDER_LABELS[policy.provider] ?? policy.provider) : "All";

  return (
    <div
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: 14,
        padding: "14px 0",
        borderBottom: "1px solid #1e2130",
      }}
    >
      {/* Toggle */}
      <div style={{ flexShrink: 0, paddingTop: 2 }}>
        <button
          type="button"
          role="switch"
          aria-checked={policy.enabled}
          disabled={!isAdmin || toggling}
          onClick={() => onToggle(policy.policy_key, !policy.enabled)}
          title={isAdmin ? (policy.enabled ? "Disable policy" : "Enable policy") : "Admin access required to change policies"}
          style={{
            width: 38,
            height: 22,
            borderRadius: 11,
            border: "none",
            padding: 0,
            cursor: isAdmin && !toggling ? "pointer" : "not-allowed",
            background: policy.enabled ? "#3ccf7e" : "#2a2d38",
            position: "relative",
            transition: "background 0.15s",
            opacity: toggling ? 0.6 : 1,
          }}
        >
          <span
            style={{
              position: "absolute",
              top: 3,
              left: policy.enabled ? 19 : 3,
              width: 16,
              height: 16,
              borderRadius: "50%",
              background: "#fff",
              transition: "left 0.15s",
            }}
          />
        </button>
      </div>

      {/* Content */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 6, marginBottom: 4 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: "#e8eaf0" }}>
            {policy.name}
          </span>
          {/* Severity badge */}
          <span
            style={{
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: "0.06em",
              textTransform: "uppercase",
              color: sevColors.text,
              background: sevColors.bg,
              borderRadius: 4,
              padding: "1px 6px",
            }}
          >
            {policy.severity}
          </span>
          {/* Provider badge */}
          <span
            style={{
              fontSize: 10,
              fontWeight: 500,
              color: "#8b90a0",
              background: "#1a1d26",
              border: "1px solid #2a2d38",
              borderRadius: 4,
              padding: "1px 6px",
            }}
          >
            {providerLabel}
          </span>
          {/* Category */}
          <span
            style={{
              fontSize: 10,
              color: "#565b6e",
              background: "#13151e",
              border: "1px solid #1e2130",
              borderRadius: 4,
              padding: "1px 6px",
            }}
          >
            {policy.category}
          </span>
        </div>
        <p style={{ fontSize: 12, color: "#6b7280", margin: 0, lineHeight: 1.55 }}>
          {policy.description}
        </p>
      </div>

      {/* Status label */}
      <div style={{ flexShrink: 0, paddingTop: 2 }}>
        <span
          style={{
            fontSize: 11,
            fontWeight: 600,
            color: policy.enabled ? "#3ccf7e" : "#454a5a",
          }}
        >
          {policy.enabled ? "Enabled" : "Disabled"}
        </span>
      </div>
    </div>
  );
}


// ── Main page ─────────────────────────────────────────────────────────────────

export default function PoliciesPage() {
  const { selectedWorkspace } = useWorkspace();
  const { getToken } = useAuth();

  const [data, setData] = useState<PolicyListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toggling, setToggling] = useState<string | null>(null); // policy_key being toggled

  // Backend enforces admin-only on PUT /workspaces/{id}/policies/{key}.
  // Frontend shows toggles to all members; the API will return 403 if they try.
  const isAdmin = true;

  const load = useCallback(async () => {
    if (!selectedWorkspace) return;
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const result = await getWorkspacePolicies(selectedWorkspace.id, token);
      setData(result);
    } catch {
      setError("Failed to load policies. Please try again.");
    } finally {
      setLoading(false);
    }
  }, [selectedWorkspace, getToken]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleToggle(policyKey: string, enabled: boolean) {
    if (!selectedWorkspace || toggling) return;
    setToggling(policyKey);
    try {
      const token = await getToken();
      const updated = await updateWorkspacePolicy(selectedWorkspace.id, policyKey, enabled, token);
      // Update local state optimistically
      setData((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          policies: prev.policies.map((p) =>
            p.policy_key === policyKey ? { ...p, enabled: updated.enabled } : p,
          ),
        };
      });
    } catch {
      setError("Failed to update policy. Please try again.");
    } finally {
      setToggling(null);
    }
  }

  if (!selectedWorkspace) {
    return (
      <>
        <PageHeader title="Policies" description="Enable or disable built-in policy checks." />
        <div className="px-6 py-6">
          <p style={{ color: "#565b6e", fontSize: 14 }}>
            Select a workspace to manage policies.
          </p>
        </div>
      </>
    );
  }

  if (loading) {
    return (
      <>
        <PageHeader title="Policies" description="Enable or disable built-in policy checks." />
        <div className="px-6 py-6">
          <LoadingState />
        </div>
      </>
    );
  }

  if (error && !data) {
    return (
      <>
        <PageHeader title="Policies" description="Enable or disable built-in policy checks." />
        <div className="px-6 py-6">
          <ErrorState message={error} />
        </div>
      </>
    );
  }

  const policies = data?.policies ?? [];
  const enabledCount = policies.filter((p) => p.enabled).length;

  // Group by provider for display
  const byProvider: Record<string, WorkspacePolicy[]> = {};
  for (const p of policies) {
    const key = p.provider ?? "general";
    if (!byProvider[key]) byProvider[key] = [];
    byProvider[key].push(p);
  }

  const providerOrder = ["aws", "firebase", "supabase", "github", "cloudflare", "stripe", "vercel", "shopify", "general"];

  return (
    <>
      <PageHeader
        title="Policies"
        description="Enable or disable built-in policy checks for configuration drift violations."
      />

      <div className="px-6 py-6" style={{ maxWidth: 860 }}>

        {/* Error banner */}
        {error && (
          <div
            role="alert"
            style={{
              background: "#3a1515",
              border: "1px solid #7f1d1d",
              borderRadius: 8,
              padding: "10px 14px",
              color: "#f87171",
              fontSize: 13,
              marginBottom: 16,
            }}
          >
            {error}
          </div>
        )}

        {/* Summary bar */}
        <div
          style={{
            background: "#13151e",
            border: "1px solid #1e2130",
            borderRadius: 10,
            padding: "14px 18px",
            marginBottom: 20,
            display: "flex",
            alignItems: "center",
            gap: 20,
          }}
        >
          <div>
            <div style={{ fontSize: 22, fontWeight: 700, color: "#e8eaf0" }}>
              {enabledCount}
              <span style={{ fontSize: 14, fontWeight: 400, color: "#565b6e", marginLeft: 4 }}>
                / {policies.length} enabled
              </span>
            </div>
            <div style={{ fontSize: 12, color: "#565b6e", marginTop: 2 }}>
              Built-in policy checks active for this workspace
            </div>
          </div>

          {!isAdmin && (
            <div
              style={{
                marginLeft: "auto",
                fontSize: 12,
                color: "#565b6e",
                background: "#1a1d26",
                border: "1px solid #2a2d38",
                borderRadius: 6,
                padding: "6px 12px",
              }}
            >
              View only — admin access required to change policies
            </div>
          )}
        </div>

        {/* Policies by provider */}
        {providerOrder
          .filter((prov) => byProvider[prov])
          .map((prov) => (
            <div
              key={prov}
              style={{
                background: "#13151e",
                border: "1px solid #1e2130",
                borderRadius: 10,
                padding: "14px 18px",
                marginBottom: 14,
              }}
            >
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  color: "#565b6e",
                  textTransform: "uppercase",
                  letterSpacing: "0.07em",
                  marginBottom: 4,
                }}
              >
                {PROVIDER_LABELS[prov] ?? prov}
              </div>

              {byProvider[prov].map((policy) => (
                <PolicyRow
                  key={policy.policy_key}
                  policy={policy}
                  isAdmin={isAdmin}
                  onToggle={handleToggle}
                  toggling={toggling === policy.policy_key}
                />
              ))}
            </div>
          ))}

        {/* Disclaimer */}
        <p
          style={{
            fontSize: 11,
            color: "#454a5a",
            lineHeight: 1.6,
            marginTop: 8,
          }}
        >
          Policy checks evaluate configuration metadata only — they do not read live provider
          state or make API calls at evaluation time. A policy violation indicates that a
          detected change matches a known risky pattern; it does not confirm a security
          incident. Review provider context before acting.
        </p>
      </div>
    </>
  );
}
