"use client";

/**
 * Cases / Investigations (M66.8).
 *
 * A case is a HUMAN-MANAGED investigation container grouping GitHub incident
 * evidence — Incident Signals, Configuration Risks, Activity Events, and
 * Correlations. (Replaces the M61.5 read-only incident-review page.)
 *
 * CLAIM DISCIPLINE: cases are investigation workspaces. This page never states
 * that a breach, attacker, compromise, or unauthorized access has been confirmed.
 * "Confirmed by user" / "Dismissed" are human actions.
 */

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import type { SecurityCase } from "@/types";
import {
  getSecurityCases,
  createSecurityCase,
  seedIncidentDemo,
  clearIncidentDemo,
} from "@/lib/api";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { formatRelativeTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";
import { SeverityBadge } from "@/components/security/findingDisplay";
import { CaseStatusBadge } from "@/components/security/signalDisplay";

const STATUS_OPTIONS = ["open", "investigating", "confirmed_by_user", "dismissed", "resolved"];
const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];

// M75B — single source of truth for the per-provider demo cards. Each entry
// renders one admin-only "Try the <Label> demo" banner on this page. Keep
// description copy short, in the shape:
//   "Seed a <Label> demo to review <provider-specific risk surface>,
//    activity evidence, generated signals, correlations, and a case report."
// The seed/clear button labels are pinned by tests (see M75A): GitHub uses
// "Load GitHub incident demo" / "Clear demo"; others use
// "Load <Label> security demo" / "Clear <Label> demo".
type DemoProvider =
  | "github" | "aws" | "cloudflare" | "vercel"
  | "supabase" | "firebase" | "stripe" | "shopify" | "azure"
  | "google_cloud" | "twilio" | "sendgrid" | "auth0";

interface ProviderDemoCard {
  provider: DemoProvider;
  label: string;
  /** Strong intro sentence (rendered inside <strong>). */
  intro: string;
  /** Body copy following the intro — kept short and consistent. */
  description: string;
  seedButton: string;
  clearButton: string;
  /** Accent color for the seed button. */
  seedColor: string;
}

const PROVIDER_DEMO_CARDS: ProviderDemoCard[] = [
  {
    provider: "github",
    label: "GitHub",
    intro: "Try the GitHub incident demo:",
    description:
      "seed a sample GitHub evidence chain across configuration risk, audit activity, Incident Signals, correlations, and a case report (clearly marked demo, no real GitHub sync).",
    seedButton: "Load GitHub incident demo",
    clearButton: "Clear demo",
    seedColor: "#6b9cf8",
  },
  {
    provider: "aws",
    label: "AWS",
    intro: "Try the AWS security demo:",
    description:
      "seed a sample AWS evidence chain across configuration risk, provider findings, CloudTrail / S3 / VPC Flow activity, signals, correlations, and a case report (clearly marked demo, no real AWS sync).",
    seedButton: "Load AWS security demo",
    clearButton: "Clear AWS demo",
    seedColor: "#f5a623",
  },
  {
    provider: "cloudflare",
    label: "Cloudflare",
    intro: "Try the Cloudflare security demo:",
    description:
      "seed a sample Cloudflare evidence chain across configuration risk, audit + WAF/security activity, signals, correlations, and a case report (clearly marked demo, no real Cloudflare sync).",
    seedButton: "Load Cloudflare security demo",
    clearButton: "Clear Cloudflare demo",
    seedColor: "#f6821f",
  },
  {
    provider: "vercel",
    label: "Vercel",
    intro: "Try the Vercel security demo:",
    description:
      "seed a Vercel demo to review project posture, activity evidence, generated signals, correlations, and a case report (clearly marked demo, no real Vercel sync).",
    seedButton: "Load Vercel security demo",
    clearButton: "Clear Vercel demo",
    seedColor: "#cbd5e1",
  },
  {
    provider: "supabase",
    label: "Supabase",
    intro: "Try the Supabase security demo:",
    description:
      "seed a Supabase demo to review database access posture, activity evidence, generated signals, correlations, and a case report (clearly marked demo, no real Supabase sync).",
    seedButton: "Load Supabase security demo",
    clearButton: "Clear Supabase demo",
    seedColor: "#3ecf8e",
  },
  {
    provider: "firebase",
    label: "Firebase",
    intro: "Try the Firebase security demo:",
    description:
      "seed a Firebase demo to review security rules posture, activity evidence, generated signals, correlations, and a case report (clearly marked demo, no real Firebase sync).",
    seedButton: "Load Firebase security demo",
    clearButton: "Clear Firebase demo",
    seedColor: "#ffca28",
  },
  {
    provider: "stripe",
    label: "Stripe",
    intro: "Try the Stripe security demo:",
    description:
      "seed a Stripe demo to review webhook, payment link, portal, and account configuration evidence, generated signals, correlations, and a case report (clearly marked demo, no real Stripe sync).",
    seedButton: "Load Stripe security demo",
    clearButton: "Clear Stripe demo",
    seedColor: "#cbd5e1",
  },
  {
    provider: "shopify",
    label: "Shopify",
    intro: "Try the Shopify security demo:",
    description:
      "seed a Shopify demo to review webhook, domain, app-permission, and policy configuration evidence, generated signals, correlations, and a case report (clearly marked demo, no real Shopify sync).",
    seedButton: "Load Shopify security demo",
    clearButton: "Clear Shopify demo",
    seedColor: "#a3e635",
  },
  {
    provider: "azure",
    label: "Azure",
    intro: "Try the Azure security demo:",
    description:
      "seed a review-safe Azure security demo with drift findings (NSG, Storage, Key Vault, broad role assignment), Activity Log evidence, signals, correlations, and a case (clearly marked demo, no real Azure sync).",
    seedButton: "Load Azure security demo",
    clearButton: "Clear Azure demo",
    seedColor: "#0078d4",
  },
  {
    provider: "google_cloud",
    label: "Google Cloud",
    intro: "Try the Google Cloud security demo:",
    description:
      "seed a review-safe Google Cloud security demo with drift findings (IAM, firewall, Cloud Storage, Cloud SQL, Cloud Run, GKE, service account keys, Secret Manager), Audit Log evidence, activity signals, risk × activity correlations, and a case (clearly marked demo, no real Google Cloud sync).",
    seedButton: "Load Google Cloud security demo",
    clearButton: "Clear Google Cloud demo",
    seedColor: "#4285f4",
  },
  {
    provider: "twilio",
    label: "Twilio",
    intro: "Try the Twilio security demo:",
    description:
      "seed a review-safe Twilio security demo with configuration drift findings, control-plane activity evidence, activity signals, risk × activity correlations, and a case (clearly marked demo, no real Twilio sync, no message bodies, no call logs, no recordings, no raw webhook URLs, no full phone numbers).",
    seedButton: "Load Twilio security demo",
    clearButton: "Clear Twilio demo",
    seedColor: "#f22f46",
  },
  {
    provider: "sendgrid",
    label: "SendGrid",
    intro: "Try the SendGrid security demo:",
    description:
      "Seed a review-safe SendGrid security demo with configuration drift findings, control-plane activity evidence, activity signals, risk × activity correlations, and a case. No real SendGrid sync, email bodies, subject lines, recipient emails, mail event payloads, raw webhook URLs, or API keys are stored.",
    seedButton: "Load SendGrid security demo",
    clearButton: "Clear SendGrid demo",
    seedColor: "#1a82e2",
  },
  {
    provider: "auth0",
    label: "Auth0",
    intro: "Try the Auth0 security demo:",
    description:
      "Seed a review-safe Auth0 security demo with configuration drift findings, control-plane activity evidence, activity signals, risk × activity correlations, and a case. No real Auth0 sync, client secrets, management tokens, JWTs, raw callback URLs, raw origins, rule/action code, user emails, login history, IP addresses, or raw Auth0 logs are stored.",
    seedButton: "Load Auth0 security demo",
    clearButton: "Clear Auth0 demo",
    seedColor: "#eb5424",
  },
];

export default function CasesPage() {
  const { getToken } = useAuth();
  const { isAdmin } = useWorkspace();
  const router = useRouter();

  const [demoBusy, setDemoBusy] = useState(false);
  const [demoNote, setDemoNote] = useState<string | null>(null);

  const [cases, setCases] = useState<SecurityCase[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");

  const [creating, setCreating] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const res = await getSecurityCases(
        { status: status || undefined, severity: severity || undefined, page_size: 100 },
        token,
      );
      setCases(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch {
      setError("Could not load cases. Please try again.");
    } finally {
      setLoading(false);
    }
  }, [getToken, status, severity]);

  useEffect(() => {
    void load();
  }, [load]);

  const onCreate = useCallback(async () => {
    if (!newTitle.trim()) return;
    setCreating(true);
    setCreateError(null);
    try {
      const token = await getToken();
      const created = await createSecurityCase({ title: newTitle.trim() }, token);
      router.push(`/security/cases/${created.id}`);
    } catch {
      setCreateError("Could not create case. Please try again.");
      setCreating(false);
    }
  }, [getToken, newTitle, router]);

  const onSeedDemo = useCallback(async (provider: "github" | "aws" | "cloudflare" | "vercel" | "supabase" | "firebase" | "stripe" | "shopify" | "azure" | "google_cloud" | "twilio" | "sendgrid" | "auth0") => {
    setDemoBusy(true);
    setDemoNote(null);
    try {
      const token = await getToken();
      const res = await seedIncidentDemo(token, provider);
      if (res.case_id) {
        router.push(`/security/cases/${res.case_id}`);
      } else {
        setDemoNote("Demo seeded.");
        await load();
        setDemoBusy(false);
      }
    } catch {
      setDemoNote("Could not load the demo. Please try again.");
      setDemoBusy(false);
    }
  }, [getToken, router, load]);

  const onClearDemo = useCallback(async (provider: "github" | "aws" | "cloudflare" | "vercel" | "supabase" | "firebase" | "stripe" | "shopify" | "azure" | "google_cloud" | "twilio" | "sendgrid" | "auth0") => {
    setDemoBusy(true);
    setDemoNote(null);
    try {
      const token = await getToken();
      await clearIncidentDemo(token, provider);
      setDemoNote(
        provider === "aws"
          ? "AWS demo data cleared."
          : provider === "cloudflare"
            ? "Cloudflare demo data cleared."
            : provider === "vercel"
              ? "Vercel demo data cleared."
              : provider === "supabase"
                ? "Supabase demo data cleared."
                : provider === "firebase"
                  ? "Firebase demo data cleared."
                  : provider === "stripe"
                    ? "Stripe demo data cleared."
                    : provider === "shopify"
                      ? "Shopify demo data cleared."
                      : provider === "azure"
                        ? "Azure demo data cleared."
                        : provider === "google_cloud"
                          ? "Google Cloud demo data cleared."
                          : provider === "twilio"
                            ? "Twilio demo data cleared."
                            : provider === "sendgrid"
                              ? "SendGrid demo data cleared."
                              : provider === "auth0"
                                ? "Auth0 demo data cleared."
                                : "Demo data cleared.",
      );
      await load();
    } catch {
      setDemoNote("Could not clear the demo. Please try again.");
    } finally {
      setDemoBusy(false);
    }
  }, [getToken, load]);

  return (
    <div>
      <Hero />

      {/* M75B — provider demo cards rendered from PROVIDER_DEMO_CARDS.
          Each card seeds/clears one provider's incident demo on a hidden
          demo integration. Copy is review-safe ("evidence for review", no
          fraud/breach/compromise claims). The shared status note attaches
          to the first (GitHub) card so it doesn't double-render. */}
      {isAdmin && PROVIDER_DEMO_CARDS.map((card, idx) => (
        <div
          key={card.provider}
          className="bg-surface1 border border-border"
          style={{ borderRadius: "12px", padding: "12px 16px", marginBottom: "20px", display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center" }}
        >
          <span style={{ fontSize: "12.5px", color: "#8b90a0", flex: 1, minWidth: "200px" }}>
            <strong style={{ color: "#e8eaf0" }}>{card.intro}</strong>{" "}
            {card.description}
          </span>
          <button
            onClick={() => onSeedDemo(card.provider)}
            disabled={demoBusy}
            style={{ fontSize: "12.5px", fontWeight: 500, color: "#0b0d12", background: card.seedColor, border: "none", padding: "7px 14px", borderRadius: "8px", cursor: demoBusy ? "not-allowed" : "pointer", opacity: demoBusy ? 0.7 : 1, whiteSpace: "nowrap" }}
          >
            {demoBusy ? "Working…" : card.seedButton}
          </button>
          <button
            onClick={() => onClearDemo(card.provider)}
            disabled={demoBusy}
            className="bg-surface1 border border-border"
            style={{ fontSize: "12.5px", fontWeight: 500, color: "#c4c8d4", borderRadius: "8px", padding: "7px 14px", cursor: demoBusy ? "not-allowed" : "pointer", opacity: demoBusy ? 0.7 : 1, whiteSpace: "nowrap" }}
          >
            {card.clearButton}
          </button>
          {idx === 0 && demoNote && (
            <span style={{ fontSize: "12px", color: "#3ccf7e", width: "100%" }}>{demoNote}</span>
          )}
        </div>
      ))}

      {/* Create case */}
      <div
        className="bg-surface1 border border-border"
        style={{ borderRadius: "12px", padding: "14px 16px", marginBottom: "20px", display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center" }}
      >
        <input
          value={newTitle}
          onChange={(e) => setNewTitle(e.target.value)}
          placeholder="New investigation title…"
          className="bg-surface2 border border-border"
          style={{ flex: 1, minWidth: "200px", fontSize: "13px", color: "#e8eaf0", borderRadius: "8px", padding: "8px 12px" }}
        />
        <button
          onClick={onCreate}
          disabled={creating || !newTitle.trim()}
          style={{
            fontSize: "13px",
            fontWeight: 500,
            color: newTitle.trim() ? "#0b0d12" : "#565b6e",
            background: newTitle.trim() ? "#6b9cf8" : "#1e2030",
            border: "none",
            padding: "8px 16px",
            borderRadius: "8px",
            cursor: creating || !newTitle.trim() ? "not-allowed" : "pointer",
            whiteSpace: "nowrap",
          }}
        >
          {creating ? "Creating…" : "Create case"}
        </button>
        {createError && <span style={{ fontSize: "12px", color: "#e84040" }}>{createError}</span>}
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center", marginBottom: "18px" }}>
        <Select label="Status" value={status} onChange={setStatus} options={STATUS_OPTIONS} />
        <Select label="Severity" value={severity} onChange={setSeverity} options={SEVERITY_OPTIONS} />
      </div>

      {loading ? (
        <LoadingState />
      ) : error ? (
        <ErrorState message={error} />
      ) : cases.length === 0 ? (
        <EmptyState />
      ) : (
        <>
          <SectionLabel>
            {total} case{total === 1 ? "" : "s"}
          </SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {cases.map((c) => (
              <Row key={c.id} c={c} />
            ))}
          </div>
        </>
      )}

      <p style={{ margin: "26px 0 0", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
        Cases are investigation workspaces. ConfigTrace does not automatically
        confirm breaches or unauthorized access — confirmation and dismissal are
        human actions.
      </p>
    </div>
  );
}

function Hero() {
  return (
    <>
      <PageHeader
        title="Cases"
        description="Group incident signals, configuration risks, activity events, and correlations into human-reviewed investigations."
      />
      <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px", marginBottom: "20px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>GitHub · AWS · Cloudflare beta</span>
          <Badge>Beta</Badge>
        </div>
        <p style={{ margin: 0, fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
          Cases are investigation workspaces for GitHub, AWS, and Cloudflare
          evidence. ConfigTrace does not automatically confirm breaches or
          unauthorized access.
        </p>
      </div>
    </>
  );
}

function Row({ c }: { c: SecurityCase }) {
  return (
    <Link
      href={`/security/cases/${c.id}`}
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", textDecoration: "none", display: "block", padding: "14px 16px" }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
        <SeverityBadge severity={c.severity} />
        <span style={{ fontSize: "14px", fontWeight: 600, color: "#e8eaf0", flex: 1, minWidth: 0 }}>{c.title}</span>
        <span style={{ fontSize: "12px", color: "#6b9cf8" }}>View case →</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap", marginTop: "9px", fontSize: "12px", color: "#8b90a0" }}>
        <CaseStatusBadge status={c.status} />
        <span>{c.link_count} linked</span>
        {c.provider && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <span>{c.provider}</span>
          </>
        )}
        <span style={{ color: "#3a3d48" }}>·</span>
        <span>updated {formatRelativeTime(c.updated_at)}</span>
      </div>
    </Link>
  );
}

function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: string[] }) {
  return (
    <label style={{ fontSize: "12px", color: "#8b90a0", display: "flex", alignItems: "center", gap: "6px" }}>
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="bg-surface1 border border-border"
        style={{ fontSize: "12px", color: "#c4c8d4", borderRadius: "6px", padding: "5px 8px" }}
      >
        <option value="">All</option>
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

function Badge({ children }: { children: React.ReactNode }) {
  return (
    <span style={{ fontSize: "9px", fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase", color: "#6b9cf8", border: "1px solid rgba(107,156,248,0.4)", borderRadius: "5px", padding: "1px 6px" }}>
      {children}
    </span>
  );
}

function EmptyState() {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "32px 24px", textAlign: "center" }}>
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#e8eaf0" }}>No cases yet.</div>
      <p style={{ margin: "8px auto 0", maxWidth: "470px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
        Create a case above, or open an incident signal or correlation and choose
        “Create case” to start an investigation.
      </p>
    </div>
  );
}
