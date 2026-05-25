"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@clerk/nextjs";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import {
  getWorkspaceBilling,
  createCheckoutSession,
  createPortalSession,
} from "@/lib/api";
import type { WorkspaceBilling, BillingPlan } from "@/types";

// ── Plan display config ───────────────────────────────────────────────────────

interface PlanConfig {
  name: string;
  monthlyPriceUsd: string;
  features: string[];
  priceId: string | null; // null = free (no Stripe price)
}

const PLANS: Record<BillingPlan, PlanConfig> = {
  free: {
    name: "Free",
    monthlyPriceUsd: "$0",
    features: [
      "3 integrations",
      "1 member (owner only)",
      "60-min sync interval",
      "30 days history",
    ],
    priceId: null,
  },
  pro: {
    name: "Pro",
    monthlyPriceUsd: "$29",
    features: [
      "20 integrations",
      "5 members",
      "15-min sync interval",
      "180 days history",
    ],
    priceId: process.env.NEXT_PUBLIC_STRIPE_PRICE_PRO_MONTHLY ?? null,
  },
  team: {
    name: "Team",
    monthlyPriceUsd: "$79",
    features: [
      "100 integrations",
      "25 members",
      "5-min sync interval",
      "365 days history",
    ],
    priceId: process.env.NEXT_PUBLIC_STRIPE_PRICE_TEAM_MONTHLY ?? null,
  },
};

// ── Status label helpers ──────────────────────────────────────────────────────

function statusLabel(status: string): string {
  const labels: Record<string, string> = {
    active: "Active",
    trialing: "Trial",
    past_due: "Past due",
    canceled: "Canceled",
    unpaid: "Unpaid",
  };
  return labels[status] ?? status;
}

function statusColor(status: string): string {
  if (status === "active" || status === "trialing") return "#4ade80";
  if (status === "past_due" || status === "unpaid") return "#f87171";
  return "#8b90a0";
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

// ── Usage bar ─────────────────────────────────────────────────────────────────

function UsageBar({
  label,
  used,
  max,
}: {
  label: string;
  used: number;
  max: number;
}) {
  const pct = max === 0 ? 100 : Math.min(100, (used / max) * 100);
  const color = pct >= 100 ? "#f87171" : pct >= 80 ? "#fbbf24" : "#4f80f7";
  return (
    <div style={{ marginBottom: 12 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          fontSize: 12,
          color: "#c4c8d4",
          marginBottom: 4,
        }}
      >
        <span>{label}</span>
        <span style={{ color: pct >= 100 ? "#f87171" : "#8b90a0" }}>
          {used} / {max}
        </span>
      </div>
      <div
        style={{
          height: 4,
          background: "#2a2d38",
          borderRadius: 2,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${pct}%`,
            background: color,
            borderRadius: 2,
            transition: "width 0.3s ease",
          }}
        />
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function BillingPage() {
  const { getToken } = useAuth();
  const router = useRouter();
  const { selectedWorkspace } = useWorkspace();

  const [billing, setBilling] = useState<WorkspaceBilling | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Read checkout result from query string (Stripe redirects back here).
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    if (params.get("checkout") === "success") {
      setSuccessMsg(
        "Subscription activated! It may take a moment to reflect here.",
      );
      // Clean the query string without a full reload.
      window.history.replaceState(
        {},
        "",
        window.location.pathname,
      );
    } else if (params.get("checkout") === "canceled") {
      setError("Checkout was canceled. No changes were made.");
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, []);

  const load = useCallback(async () => {
    if (!selectedWorkspace) return;
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const data = await getWorkspaceBilling(selectedWorkspace.id, token);
      setBilling(data);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load billing info.",
      );
    } finally {
      setLoading(false);
    }
  }, [selectedWorkspace, getToken]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleUpgrade(plan: BillingPlan) {
    if (!selectedWorkspace) return;
    const planConfig = PLANS[plan];
    if (!planConfig.priceId) {
      setError("Price ID not configured. Contact support.");
      return;
    }
    setActionBusy(true);
    setError(null);
    try {
      const token = await getToken();
      const { checkout_url } = await createCheckoutSession(
        selectedWorkspace.id,
        planConfig.priceId,
        token,
      );
      window.location.href = checkout_url;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start checkout.");
      setActionBusy(false);
    }
  }

  async function handleManage() {
    if (!selectedWorkspace) return;
    setActionBusy(true);
    setError(null);
    try {
      const token = await getToken();
      const { portal_url } = await createPortalSession(
        selectedWorkspace.id,
        token,
      );
      window.location.href = portal_url;
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to open billing portal.",
      );
      setActionBusy(false);
    }
  }

  if (!selectedWorkspace) {
    return (
      <main style={{ padding: "32px 24px", color: "#8b90a0" }}>
        No workspace selected.
      </main>
    );
  }

  return (
    <main style={{ maxWidth: 720, margin: "0 auto", padding: "32px 24px" }}>
      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          marginBottom: 24,
        }}
      >
        <button
          onClick={() => router.push("/settings/workspace")}
          style={{
            background: "none",
            border: "none",
            color: "#8b90a0",
            cursor: "pointer",
            fontSize: 18,
            padding: 0,
          }}
          aria-label="Back"
        >
          ←
        </button>
        <div>
          <h1
            style={{
              fontSize: 20,
              fontWeight: 600,
              color: "#e2e5ef",
              margin: 0,
            }}
          >
            Billing &amp; Plan
          </h1>
          <div style={{ fontSize: 12, color: "#565b6e", marginTop: 2 }}>
            {selectedWorkspace.name}
          </div>
        </div>
      </div>

      {/* Messages */}
      {error && (
        <div
          style={{
            background: "#2a1a1a",
            border: "1px solid #7a2a2a",
            borderRadius: 6,
            padding: "10px 14px",
            color: "#f87171",
            fontSize: 13,
            marginBottom: 16,
          }}
        >
          {error}
        </div>
      )}
      {successMsg && (
        <div
          style={{
            background: "#1a2a1a",
            border: "1px solid #2a5a2a",
            borderRadius: 6,
            padding: "10px 14px",
            color: "#4ade80",
            fontSize: 13,
            marginBottom: 16,
          }}
        >
          {successMsg}
        </div>
      )}

      {loading ? (
        <div style={{ color: "#565b6e", fontSize: 13, padding: "20px 0" }}>
          Loading…
        </div>
      ) : billing ? (
        <>
          {/* Current plan card */}
          <section
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: 8,
              padding: 20,
              marginBottom: 20,
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: 16,
              }}
            >
              <div>
                <div style={{ fontSize: 11, color: "#565b6e", marginBottom: 2 }}>
                  Current plan
                </div>
                <div
                  style={{
                    fontSize: 22,
                    fontWeight: 700,
                    color: "#e2e5ef",
                    textTransform: "capitalize",
                  }}
                >
                  {PLANS[billing.plan]?.name ?? billing.plan}
                </div>
              </div>
              <span
                style={{
                  fontSize: 11,
                  color: statusColor(billing.status),
                  background: "#1a1d28",
                  border: `1px solid ${statusColor(billing.status)}`,
                  borderRadius: 4,
                  padding: "3px 10px",
                  fontWeight: 500,
                }}
              >
                {statusLabel(billing.status)}
              </span>
            </div>

            {/* Period dates */}
            {billing.current_period_end && (
              <div style={{ fontSize: 12, color: "#8b90a0", marginBottom: 12 }}>
                {billing.cancel_at_period_end
                  ? `Cancels on ${formatDate(billing.current_period_end)}`
                  : `Renews on ${formatDate(billing.current_period_end)}`}
              </div>
            )}

            {/* Usage bars */}
            <UsageBar
              label="Integrations"
              used={billing.usage.integrations}
              max={billing.limits.max_integrations}
            />
            <UsageBar
              label="Members"
              used={billing.usage.members}
              max={billing.limits.max_members}
            />

            {/* Manage subscription */}
            {billing.stripe_subscription_id && (
              <button
                onClick={handleManage}
                disabled={actionBusy}
                style={{
                  marginTop: 8,
                  fontSize: 12,
                  color: "#8b90a0",
                  background: "none",
                  border: "1px solid #2a2d38",
                  borderRadius: 5,
                  padding: "6px 14px",
                  cursor: "pointer",
                }}
              >
                Manage subscription →
              </button>
            )}
          </section>

          {/* Plan cards */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
              gap: 14,
            }}
          >
            {(["free", "pro", "team"] as BillingPlan[]).map((planKey) => {
              const plan = PLANS[planKey];
              const isCurrent = billing.plan === planKey;
              const isUpgrade = planKey !== "free" && planKey !== billing.plan;

              return (
                <div
                  key={planKey}
                  style={{
                    background: isCurrent ? "#1a1d28" : "#13151a",
                    border: `1px solid ${isCurrent ? "#4f80f7" : "#2a2d38"}`,
                    borderRadius: 8,
                    padding: 16,
                  }}
                >
                  <div
                    style={{
                      fontSize: 14,
                      fontWeight: 600,
                      color: "#e2e5ef",
                      marginBottom: 4,
                    }}
                  >
                    {plan.name}
                  </div>
                  <div
                    style={{
                      fontSize: 22,
                      fontWeight: 700,
                      color: "#4f80f7",
                      marginBottom: 12,
                    }}
                  >
                    {plan.monthlyPriceUsd}
                    <span
                      style={{
                        fontSize: 12,
                        color: "#565b6e",
                        fontWeight: 400,
                      }}
                    >
                      /mo
                    </span>
                  </div>
                  <ul
                    style={{
                      margin: "0 0 16px 0",
                      padding: 0,
                      listStyle: "none",
                    }}
                  >
                    {plan.features.map((f) => (
                      <li
                        key={f}
                        style={{
                          fontSize: 12,
                          color: "#8b90a0",
                          marginBottom: 5,
                          paddingLeft: 14,
                          position: "relative",
                        }}
                      >
                        <span
                          style={{
                            position: "absolute",
                            left: 0,
                            color: "#4ade80",
                          }}
                        >
                          ✓
                        </span>
                        {f}
                      </li>
                    ))}
                  </ul>
                  {isCurrent ? (
                    <div
                      style={{
                        fontSize: 12,
                        color: "#4f80f7",
                        fontWeight: 500,
                        textAlign: "center",
                      }}
                    >
                      ✓ Current plan
                    </div>
                  ) : isUpgrade ? (
                    <button
                      onClick={() => handleUpgrade(planKey)}
                      disabled={actionBusy}
                      style={{
                        width: "100%",
                        background: "#4f80f7",
                        color: "#fff",
                        border: "none",
                        borderRadius: 5,
                        padding: "7px 0",
                        fontSize: 13,
                        cursor: actionBusy ? "not-allowed" : "pointer",
                        opacity: actionBusy ? 0.6 : 1,
                      }}
                    >
                      Upgrade to {plan.name}
                    </button>
                  ) : null}
                </div>
              );
            })}
          </div>

          {/* Limits reference */}
          <section
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: 8,
              padding: 16,
              marginTop: 20,
            }}
          >
            <div
              style={{
                fontSize: 11,
                fontWeight: 500,
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                marginBottom: 10,
              }}
            >
              Plan limits (current)
            </div>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
                gap: 10,
              }}
            >
              {[
                {
                  label: "Max integrations",
                  value: billing.limits.max_integrations,
                },
                { label: "Max members", value: billing.limits.max_members },
                {
                  label: "Min sync interval",
                  value: `${billing.limits.min_sync_interval_minutes} min`,
                },
                {
                  label: "History retention",
                  value: `${billing.limits.history_retention_days} days`,
                },
              ].map(({ label, value }) => (
                <div key={label}>
                  <div style={{ fontSize: 11, color: "#565b6e" }}>{label}</div>
                  <div
                    style={{ fontSize: 16, fontWeight: 600, color: "#e2e5ef" }}
                  >
                    {value}
                  </div>
                </div>
              ))}
            </div>
          </section>
        </>
      ) : null}
    </main>
  );
}
