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
import PageHeader from "@/components/common/PageHeader";

// ── Plan metadata ─────────────────────────────────────────────────────────────
// Limits must stay in sync with backend/app/services/billing_service.py PLAN_LIMITS.

interface PlanMeta {
  name: string;
  monthlyPriceUsd: string;
  features: string[];
  priceId: string | null;
}

const PLAN_META: Record<BillingPlan, PlanMeta> = {
  free: {
    name: "Free",
    monthlyPriceUsd: "$0",
    features: [
      "3 integrations",
      "1 member (owner only)",
      "Monitoring cadence: every 1 hour",
      "30-day history",
    ],
    priceId: null,
  },
  pro: {
    name: "Pro",
    monthlyPriceUsd: "$29",
    features: [
      "20 integrations",
      "5 members",
      "Monitoring cadence: every 15 min",
      "180-day history",
    ],
    priceId: process.env.NEXT_PUBLIC_STRIPE_PRICE_PRO_MONTHLY ?? null,
  },
  team: {
    name: "Team",
    monthlyPriceUsd: "$79",
    features: [
      "100 integrations",
      "25 members",
      "Monitoring cadence: every 5 min",
      "365-day history",
      "Workspace audit logs",
    ],
    priceId: process.env.NEXT_PUBLIC_STRIPE_PRICE_TEAM_MONTHLY ?? null,
  },
};

// ── Error classification helpers ──────────────────────────────────────────────

function isPermissionError(msg: string): boolean {
  return msg.includes("HTTP 403") || msg.toLowerCase().includes("not authorized") || msg.toLowerCase().includes("permission");
}

function isStripeNotConfigured(msg: string): boolean {
  return (
    msg.toLowerCase().includes("price id") ||
    msg.toLowerCase().includes("stripe") && msg.toLowerCase().includes("configured") ||
    msg.toLowerCase().includes("not configured")
  );
}

function friendlyBillingError(msg: string): string {
  if (isPermissionError(msg)) {
    return "Only workspace owners and admins can manage billing.";
  }
  if (isStripeNotConfigured(msg)) {
    return "Billing is not fully configured yet. Contact support or try again later.";
  }
  // Strip the "HTTP NNN: " prefix for display
  return msg.replace(/^HTTP \d{3}:\s*/, "");
}

// ── Date helper ───────────────────────────────────────────────────────────────

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

// ── Status display helpers ────────────────────────────────────────────────────

interface StatusDisplay {
  label: string;
  color: string;
  borderColor: string;
  bg: string;
}

function getStatusDisplay(status: string, plan: BillingPlan): StatusDisplay {
  if (plan === "free") {
    return { label: "Free plan", color: "#8b90a0", borderColor: "#2a2d38", bg: "#1a1d28" };
  }
  switch (status) {
    case "active":
      return { label: "Active subscription", color: "#4ade80", borderColor: "rgba(74,222,128,0.30)", bg: "rgba(74,222,128,0.06)" };
    case "trialing":
      return { label: "Trial active", color: "#60a5fa", borderColor: "rgba(96,165,250,0.30)", bg: "rgba(96,165,250,0.06)" };
    case "past_due":
      return { label: "Payment issue", color: "#f87171", borderColor: "rgba(248,113,113,0.30)", bg: "rgba(248,113,113,0.06)" };
    case "unpaid":
      return { label: "Payment required", color: "#f87171", borderColor: "rgba(248,113,113,0.30)", bg: "rgba(248,113,113,0.06)" };
    case "canceled":
      return { label: "Subscription canceled", color: "#8b90a0", borderColor: "#2a2d38", bg: "#1a1d28" };
    default:
      return { label: status, color: "#8b90a0", borderColor: "#2a2d38", bg: "#1a1d28" };
  }
}

function getStatusBodyText(billing: WorkspaceBilling): string {
  const { plan, status, current_period_end, cancel_at_period_end, trial_end } = billing;

  if (plan === "free") {
    return "Upgrade when you need more integrations, team members, or a faster monitoring cadence.";
  }
  if (status === "trialing" && trial_end) {
    return `Trial ends on ${formatDate(trial_end)}.`;
  }
  if (status === "past_due") {
    return "Update your billing information to avoid losing access to paid plan limits.";
  }
  if (status === "unpaid") {
    return "An invoice is past due. Update billing to restore access.";
  }
  if (status === "canceled") {
    return "Your subscription has ended. You are now on the Free plan limits.";
  }
  if (cancel_at_period_end && current_period_end) {
    return `Access continues until ${formatDate(current_period_end)}, then reverts to Free.`;
  }
  if (current_period_end) {
    return `Renews on ${formatDate(current_period_end)}.`;
  }
  return "";
}

// ── Usage bar ─────────────────────────────────────────────────────────────────

function UsageBar({
  used,
  max,
  label,
}: {
  used: number;
  max: number;
  label: string;
}) {
  const pct   = max === 0 ? 100 : Math.min(100, (used / max) * 100);
  const atMax = used >= max;
  const nearMax = !atMax && pct >= 80;
  const barColor = atMax ? "#f87171" : nearMax ? "#fbbf24" : "#4f80f7";

  return (
    <div
      role="group"
      aria-label={label}
      style={{ marginBottom: "12px" }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "5px",
        }}
      >
        <span style={{ fontSize: "12px", color: "#c4c8d4" }}>{label}</span>
        <span
          style={{
            fontSize: "12px",
            color: atMax ? "#f87171" : nearMax ? "#fbbf24" : "#8b90a0",
            fontWeight: atMax ? 600 : 400,
          }}
          aria-live="polite"
        >
          {used} / {max}
          {atMax && <span aria-label=" (at limit)"> · At limit</span>}
        </span>
      </div>
      <div
        role="progressbar"
        aria-valuenow={used}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-label={`${label}: ${used} of ${max} used`}
        style={{
          height: "4px",
          background: "#2a2d38",
          borderRadius: "2px",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${pct}%`,
            background: barColor,
            borderRadius: "2px",
            transition: "width 0.3s ease",
          }}
        />
      </div>
    </div>
  );
}

// ── Over-limit banner ─────────────────────────────────────────────────────────

function OverLimitBanner({
  billing,
  onUpgrade,
}: {
  billing: WorkspaceBilling;
  onUpgrade: () => void;
}) {
  const atIntegrations = billing.usage.integrations >= billing.limits.max_integrations;
  const atMembers      = billing.usage.members      >= billing.limits.max_members;

  if (!atIntegrations && !atMembers) return null;

  const planLabel = (PLAN_META[billing.plan]?.name ?? billing.plan);
  const blocked: string[] = [];
  if (atIntegrations) blocked.push("new integrations");
  if (atMembers)      blocked.push("new member invites");

  return (
    <div
      role="alert"
      style={{
        background: "rgba(245,166,35,0.08)",
        border: "1px solid rgba(245,166,35,0.35)",
        borderRadius: "8px",
        padding: "14px 16px",
        marginBottom: "20px",
      }}
    >
      <p
        style={{
          margin: "0 0 4px",
          fontSize: "13px",
          fontWeight: 600,
          color: "#fbbf24",
        }}
      >
        You have reached your {planLabel} plan limit.
      </p>
      <p style={{ margin: "0 0 12px", fontSize: "12px", color: "#c4c8d4", lineHeight: 1.6 }}>
        Existing integrations and members continue to work.{" "}
        {blocked.length > 0 && (
          <>
            Adding {blocked.join(" and ")} is blocked until you upgrade.
          </>
        )}
      </p>
      {billing.plan === "free" && (
        <button
          onClick={onUpgrade}
          style={{
            background: "#4f80f7",
            color: "#fff",
            border: "none",
            borderRadius: "5px",
            padding: "6px 16px",
            fontSize: "12px",
            fontWeight: 500,
            cursor: "pointer",
            fontFamily: "inherit",
          }}
        >
          Upgrade plan →
        </button>
      )}
    </div>
  );
}

// ── Plan card ─────────────────────────────────────────────────────────────────

function PlanCard({
  planKey,
  billing,
  actionBusy,
  onUpgrade,
  onManage,
}: {
  planKey: BillingPlan;
  billing: WorkspaceBilling;
  actionBusy: boolean;
  onUpgrade: (plan: BillingPlan) => void;
  onManage: () => void;
}) {
  const plan      = PLAN_META[planKey];
  const isCurrent = billing.plan === planKey;
  const hasSub    = !!billing.stripe_subscription_id;

  // Determine action button state
  let action: "current" | "upgrade" | "manage" | "none" = "none";
  if (isCurrent && hasSub) action = "manage";
  else if (isCurrent)      action = "current";
  else if (planKey !== "free" && (billing.plan === "free" || planKey === "team" && billing.plan === "pro")) {
    action = "upgrade";
  }

  return (
    <div
      style={{
        background: isCurrent ? "#1a1d28" : "#13151a",
        border: `1px solid ${isCurrent ? "#4f80f7" : "#2a2d38"}`,
        borderRadius: "8px",
        padding: "16px",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          marginBottom: "10px",
        }}
      >
        <h3 style={{ margin: 0, fontSize: "14px", fontWeight: 600, color: "#e8eaf0" }}>
          {plan.name}
        </h3>
        {isCurrent && (
          <span
            style={{
              fontSize: "10px",
              color: "#4f80f7",
              background: "rgba(79,128,247,0.12)",
              border: "1px solid rgba(79,128,247,0.30)",
              borderRadius: "3px",
              padding: "1px 6px",
              fontWeight: 600,
              letterSpacing: "0.04em",
            }}
          >
            CURRENT
          </span>
        )}
      </div>

      <div style={{ marginBottom: "14px" }}>
        <span style={{ fontSize: "22px", fontWeight: 700, color: "#4f80f7" }}>
          {plan.monthlyPriceUsd}
        </span>
        <span style={{ fontSize: "12px", color: "#565b6e", fontWeight: 400 }}>/mo</span>
      </div>

      <ul
        role="list"
        style={{ margin: "0 0 16px", padding: 0, listStyle: "none", flex: 1 }}
      >
        {plan.features.map((f) => (
          <li
            key={f}
            style={{
              fontSize: "12px",
              color: "#8b90a0",
              marginBottom: "5px",
              paddingLeft: "14px",
              position: "relative",
              lineHeight: 1.5,
            }}
          >
            <span
              aria-hidden="true"
              style={{ position: "absolute", left: 0, color: "#4ade80" }}
            >
              ✓
            </span>
            {f}
          </li>
        ))}
      </ul>

      {action === "current" && (
        <div
          style={{
            fontSize: "12px",
            color: "#4f80f7",
            fontWeight: 500,
            textAlign: "center",
            padding: "6px 0",
          }}
        >
          ✓ Current plan
        </div>
      )}

      {action === "manage" && (
        <button
          onClick={onManage}
          disabled={actionBusy}
          aria-label="Manage billing in Stripe portal"
          style={{
            width: "100%",
            background: "transparent",
            color: "#4f80f7",
            border: "1px solid rgba(79,128,247,0.40)",
            borderRadius: "5px",
            padding: "7px 0",
            fontSize: "12px",
            fontWeight: 500,
            cursor: actionBusy ? "not-allowed" : "pointer",
            opacity: actionBusy ? 0.6 : 1,
            fontFamily: "inherit",
          }}
        >
          {actionBusy ? "Opening portal…" : "Manage billing"}
        </button>
      )}

      {action === "upgrade" && (
        <button
          onClick={() => onUpgrade(planKey)}
          disabled={actionBusy}
          aria-label={`Upgrade to ${plan.name} plan`}
          style={{
            width: "100%",
            background: "#4f80f7",
            color: "#fff",
            border: "none",
            borderRadius: "5px",
            padding: "7px 0",
            fontSize: "12px",
            fontWeight: 500,
            cursor: actionBusy ? "not-allowed" : "pointer",
            opacity: actionBusy ? 0.6 : 1,
            fontFamily: "inherit",
          }}
        >
          {actionBusy ? "Creating checkout…" : `Upgrade to ${plan.name}`}
        </button>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function BillingPage() {
  const { getToken } = useAuth();
  const router = useRouter();
  const { selectedWorkspace } = useWorkspace();

  const [billing, setBilling]       = useState<WorkspaceBilling | null>(null);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Read Stripe redirect result from query string.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    if (params.get("checkout") === "success") {
      setSuccessMsg("Subscription activated! It may take a moment to reflect here.");
      window.history.replaceState({}, "", window.location.pathname);
    } else if (params.get("checkout") === "canceled") {
      setActionError("Checkout was canceled. No changes were made.");
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, []);

  const load = useCallback(async () => {
    if (!selectedWorkspace) return;
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const data  = await getWorkspaceBilling(selectedWorkspace.id, token);
      setBilling(data);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to load billing info.";
      setError(friendlyBillingError(msg));
    } finally {
      setLoading(false);
    }
  }, [selectedWorkspace, getToken]);

  useEffect(() => { load(); }, [load]);

  async function handleUpgrade(plan: BillingPlan) {
    if (!selectedWorkspace) return;
    const meta = PLAN_META[plan];
    if (!meta.priceId) {
      setActionError("Billing is not fully configured yet. Contact support or try again later.");
      return;
    }
    setActionBusy(true);
    setActionError(null);
    try {
      const token = await getToken();
      const { checkout_url } = await createCheckoutSession(
        selectedWorkspace.id,
        meta.priceId,
        token,
      );
      window.location.href = checkout_url;
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to start checkout.";
      setActionError(friendlyBillingError(msg));
      setActionBusy(false);
    }
  }

  async function handleManage() {
    if (!selectedWorkspace) return;
    setActionBusy(true);
    setActionError(null);
    try {
      const token = await getToken();
      const { portal_url } = await createPortalSession(selectedWorkspace.id, token);
      window.location.href = portal_url;
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to open billing portal.";
      setActionError(friendlyBillingError(msg));
      setActionBusy(false);
    }
  }

  // ── No workspace guard ──────────────────────────────────────────────────────

  if (!selectedWorkspace) {
    return (
      <main style={{ padding: "32px 24px", color: "#8b90a0" }}>
        No workspace selected.{" "}
        <button
          onClick={() => router.push("/settings/workspace")}
          style={{
            background: "none",
            border: "none",
            color: "#4f80f7",
            cursor: "pointer",
            fontSize: "inherit",
            padding: 0,
            fontFamily: "inherit",
          }}
        >
          Go to Workspace settings
        </button>
        {" "}to select one.
      </main>
    );
  }

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <>
      <PageHeader
        title="Billing & Plan"
        description="Manage workspace usage, limits, and billing."
      />

      <div className="px-6 pb-8" style={{ maxWidth: "720px" }}>
        {/* Back link */}
        <button
          onClick={() => router.push("/settings/workspace")}
          style={{
            background: "none",
            border: "none",
            color: "#8b90a0",
            cursor: "pointer",
            fontSize: "13px",
            padding: "0 0 20px 0",
            display: "flex",
            alignItems: "center",
            gap: "6px",
            fontFamily: "inherit",
          }}
        >
          ← Back to Workspace
        </button>

        {/* Checkout success */}
        {successMsg && (
          <div
            role="status"
            aria-live="polite"
            style={{
              background: "#1a2a1a",
              border: "1px solid #2a5a2a",
              borderRadius: "6px",
              padding: "10px 14px",
              color: "#4ade80",
              fontSize: "13px",
              marginBottom: "16px",
            }}
          >
            {successMsg}
          </div>
        )}

        {/* Action error */}
        {actionError && (
          <div
            role="alert"
            style={{
              background: isPermissionError(actionError) ? "rgba(79,128,247,0.06)" : "#2a1a1a",
              border: `1px solid ${isPermissionError(actionError) ? "rgba(79,128,247,0.25)" : "#7a2a2a"}`,
              borderRadius: "6px",
              padding: "10px 14px",
              color: isPermissionError(actionError) ? "#8b90a0" : "#f87171",
              fontSize: "13px",
              marginBottom: "16px",
            }}
          >
            {actionError}
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div
            role="status"
            aria-live="polite"
            style={{ color: "#565b6e", fontSize: "13px", padding: "20px 0" }}
          >
            Loading billing information…
          </div>
        )}

        {/* Load error */}
        {!loading && error && (
          <div
            role="alert"
            style={{
              background: isPermissionError(error) ? "rgba(79,128,247,0.06)" : "#2a1a1a",
              border: `1px solid ${isPermissionError(error) ? "rgba(79,128,247,0.25)" : "#7a2a2a"}`,
              borderRadius: "6px",
              padding: "16px",
              color: isPermissionError(error) ? "#8b90a0" : "#f87171",
              fontSize: "13px",
            }}
          >
            {error}
            {!isPermissionError(error) && (
              <button
                onClick={load}
                style={{
                  marginLeft: "12px",
                  background: "none",
                  border: "none",
                  color: "#4f80f7",
                  cursor: "pointer",
                  fontSize: "13px",
                  padding: 0,
                  fontFamily: "inherit",
                }}
              >
                Retry
              </button>
            )}
          </div>
        )}

        {!loading && !error && billing && (
          <>
            {/* ── Over-limit banner ──────────────────────────────────── */}
            <OverLimitBanner
              billing={billing}
              onUpgrade={() => {
                const upgradeTarget = document.getElementById("plan-cards");
                upgradeTarget?.scrollIntoView({ behavior: "smooth" });
              }}
            />

            {/* ── Current plan card ──────────────────────────────────── */}
            <section
              aria-labelledby="section-plan"
              style={{
                background: "#13151a",
                border: "1px solid #2a2d38",
                borderRadius: "8px",
                padding: "20px",
                marginBottom: "20px",
              }}
            >
              {(() => {
                const sd      = getStatusDisplay(billing.status, billing.plan);
                const bodyText = getStatusBodyText(billing);
                const planName = PLAN_META[billing.plan]?.name ?? billing.plan;
                return (
                  <>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "flex-start",
                        justifyContent: "space-between",
                        marginBottom: "12px",
                        gap: "12px",
                      }}
                    >
                      <div>
                        <p style={{ margin: "0 0 3px", fontSize: "11px", color: "#565b6e" }}>
                          Current plan
                        </p>
                        <h2
                          id="section-plan"
                          style={{
                            margin: 0,
                            fontSize: "22px",
                            fontWeight: 700,
                            color: "#e8eaf0",
                          }}
                        >
                          {planName}
                        </h2>
                      </div>

                      <span
                        style={{
                          flexShrink: 0,
                          fontSize: "11px",
                          fontWeight: 500,
                          color: sd.color,
                          background: sd.bg,
                          border: `1px solid ${sd.borderColor}`,
                          borderRadius: "4px",
                          padding: "3px 10px",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {sd.label}
                      </span>
                    </div>

                    {bodyText && (
                      <p
                        style={{
                          margin: "0 0 16px",
                          fontSize: "13px",
                          color: billing.status === "past_due" || billing.status === "unpaid"
                            ? "#f5a623"
                            : "#8b90a0",
                          lineHeight: 1.6,
                        }}
                      >
                        {bodyText}
                      </p>
                    )}

                    {/* Manage subscription button — inside the plan card */}
                    {billing.stripe_subscription_id && (
                      <button
                        onClick={handleManage}
                        disabled={actionBusy}
                        aria-label="Manage subscription in Stripe portal"
                        style={{
                          fontSize: "12px",
                          color: "#8b90a0",
                          background: "none",
                          border: "1px solid #2a2d38",
                          borderRadius: "5px",
                          padding: "6px 14px",
                          cursor: actionBusy ? "not-allowed" : "pointer",
                          opacity: actionBusy ? 0.6 : 1,
                          fontFamily: "inherit",
                        }}
                      >
                        {actionBusy ? "Opening portal…" : "Manage subscription →"}
                      </button>
                    )}
                  </>
                );
              })()}
            </section>

            {/* ── Usage section ──────────────────────────────────────── */}
            <section
              aria-labelledby="section-usage"
              style={{
                background: "#13151a",
                border: "1px solid #2a2d38",
                borderRadius: "8px",
                padding: "20px",
                marginBottom: "20px",
              }}
            >
              <h2
                id="section-usage"
                style={{
                  margin: "0 0 16px",
                  fontSize: "13px",
                  fontWeight: 600,
                  color: "#c4c8d4",
                }}
              >
                Usage
              </h2>

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

              {/* Read-only limits */}
              <div
                style={{
                  marginTop: "16px",
                  paddingTop: "16px",
                  borderTop: "1px solid #1e2030",
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: "12px",
                }}
              >
                {[
                  {
                    label: "Minimum sync interval",
                    value:
                      billing.limits.min_sync_interval_minutes >= 60
                        ? `${billing.limits.min_sync_interval_minutes / 60} hour`
                        : `${billing.limits.min_sync_interval_minutes} min`,
                  },
                  {
                    label: "History retention",
                    value: `${billing.limits.history_retention_days} days`,
                  },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <div style={{ fontSize: "11px", color: "#565b6e", marginBottom: "3px" }}>
                      {label}
                    </div>
                    <div style={{ fontSize: "14px", fontWeight: 600, color: "#e8eaf0" }}>
                      {value}
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* ── Plan cards ─────────────────────────────────────────── */}
            <section id="plan-cards" aria-labelledby="section-plans">
              <h2
                id="section-plans"
                style={{
                  margin: "0 0 12px",
                  fontSize: "13px",
                  fontWeight: 600,
                  color: "#c4c8d4",
                }}
              >
                Plans
              </h2>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(3, 1fr)",
                  gap: "12px",
                  marginBottom: "20px",
                }}
              >
                {(["free", "pro", "team"] as BillingPlan[]).map((planKey) => (
                  <PlanCard
                    key={planKey}
                    planKey={planKey}
                    billing={billing}
                    actionBusy={actionBusy}
                    onUpgrade={handleUpgrade}
                    onManage={handleManage}
                  />
                ))}
              </div>

              {/* Stripe not configured note */}
              {!PLAN_META.pro.priceId && !PLAN_META.team.priceId && (
                <p style={{ fontSize: "12px", color: "#565b6e", margin: "0 0 16px" }}>
                  Paid plan upgrades are not available in this environment.
                  Contact the workspace owner or check back later.
                </p>
              )}
            </section>
          </>
        )}
      </div>
    </>
  );
}
