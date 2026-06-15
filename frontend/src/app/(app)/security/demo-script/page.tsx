"use client";

/**
 * Security Demo Script (M63.7).
 *
 * A founder/team presenter talk track for Configuration Risk — distinct from the
 * user-facing SecurityDemoWalkthrough widget. Frontend-only, deterministic
 * content from lib/securityDemoScript. Read-only except the explicit, opt-in
 * "Load demo data" action (admin/owner only, mirroring M63.5). No AI, no
 * auto-load, careful demo-safe wording.
 */

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import { getSecurityDemoDataStatus, seedSecurityDemoData, getSecurityFindings, getSecurityCoverage } from "@/lib/api";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { canManageDemoData } from "@/lib/workspacePermissions";
import {
  buildDemoReadiness,
  type DemoReadiness,
  type DemoStep,
  DEMO_SCRIPT_3MIN,
  DEMO_SCRIPT_5MIN,
  DEMO_SCRIPT_INCIDENT,
  DEMO_SCRIPT_AWS_INCIDENT,
  DEMO_SCRIPT_CLOUDFLARE_INCIDENT,
  DEMO_OBJECTIONS,
  DEMO_WORDING_GUIDE,
  DEMO_QUICK_LINKS,
} from "@/lib/securityDemoScript";

import PageHeader from "@/components/common/PageHeader";
import { SectionLabel } from "@/components/security/previews";

export default function SecurityDemoScriptPage() {
  const { getToken } = useAuth();
  const { role } = useWorkspace();
  const canLoadDemo = canManageDemoData(role);

  const [readiness, setReadiness] = useState<DemoReadiness | null>(null);
  const [demoLoaded, setDemoLoaded] = useState<boolean | null>(null);
  const [seeding, setSeeding] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const token = await getToken();
      const [demo, all, active, coverage] = await Promise.allSettled([
        getSecurityDemoDataStatus(token),
        getSecurityFindings({ page_size: 1 }, token),
        getSecurityFindings({ status: "active", page_size: 1 }, token),
        getSecurityCoverage(token),
      ]);
      const val = <T,>(r: PromiseSettledResult<T>): T | null => (r.status === "fulfilled" ? r.value : null);
      const exists = val(demo)?.exists ?? null;
      setDemoLoaded(exists);
      setReadiness(
        buildDemoReadiness({
          demoLoaded: exists,
          findingCount: val(all)?.total ?? null,
          activeCount: val(active)?.total ?? null,
          connectedProviders: val(coverage)?.summary?.connected_providers ?? null,
        }),
      );
    } catch {
      // Non-fatal: the script content still renders without live readiness data.
      setReadiness(buildDemoReadiness({ demoLoaded: null, findingCount: null, activeCount: null, connectedProviders: null }));
    }
  }, [getToken]);

  useEffect(() => {
    void load();
  }, [load]);

  const onSeed = useCallback(async () => {
    setSeeding(true);
    setNote(null);
    try {
      const token = await getToken();
      await seedSecurityDemoData(token);
      setNote("Demo data loaded. Open Security Overview to present sample findings.");
      await load();
    } catch {
      setNote("Could not load demo data. Please try again.");
    } finally {
      setSeeding(false);
    }
  }, [getToken, load]);

  return (
    <div>
      <PageHeader
        title="Security Demo Script"
        description="A guided talk track for presenting Configuration Risk."
      />

      <p style={{ margin: "-12px 0 22px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6, maxWidth: "820px" }}>
        Use this script to walk through Configuration Risk with demo data or connected
        provider data. The script uses careful language and avoids claims of breach
        detection or formal compliance.
      </p>

      {/* 1. Readiness checklist */}
      <SectionLabel>Demo readiness</SectionLabel>
      <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "14px 16px", margin: "10px 0 24px" }}>
        {readiness ? (
          <>
            <div style={{ fontSize: "12px", color: "#565b6e", marginBottom: "10px" }}>
              {readiness.readyCount} of {readiness.total} ready
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {readiness.items.map((it) => (
                <div key={it.id} style={{ display: "flex", alignItems: "flex-start", gap: "10px" }}>
                  <span style={{ color: it.ready ? "#3ccf7e" : "#f5a623", fontSize: "13px", marginTop: "1px" }}>
                    {it.ready ? "✓" : "○"}
                  </span>
                  <div>
                    <div style={{ fontSize: "13px", color: "#e8eaf0", fontWeight: 600 }}>{it.label}</div>
                    <div style={{ fontSize: "12px", color: "#8b90a0", lineHeight: 1.5 }}>{it.detail}</div>
                  </div>
                </div>
              ))}
            </div>
            {readiness.needsDemoData ? (
              <div style={{ marginTop: "14px", display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                {canLoadDemo ? (
                  <button type="button" onClick={onSeed} disabled={seeding} style={primaryBtn(seeding)}>
                    {seeding ? "Loading…" : "Load demo data"}
                  </button>
                ) : (
                  <span style={{ fontSize: "12.5px", color: "#8b90a0" }}>
                    Ask a workspace admin to load demo data.
                  </span>
                )}
                {demoLoaded === false ? (
                  <span style={{ fontSize: "12px", color: "#565b6e" }}>
                    Demo data is opt-in and never loads automatically.
                  </span>
                ) : null}
              </div>
            ) : null}
            {note ? <div style={{ fontSize: "12px", color: "#6b9cf8", marginTop: "10px" }}>{note}</div> : null}
          </>
        ) : (
          <div style={{ fontSize: "12.5px", color: "#565b6e" }}>Loading readiness…</div>
        )}
      </div>

      {/* 2. 3-minute script */}
      <SectionLabel>3-minute demo script</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px", margin: "10px 0 24px" }}>
        {DEMO_SCRIPT_3MIN.map((s, i) => (
          <StepCard key={s.id} step={s} index={i + 1} />
        ))}
      </div>

      {/* 3. 5-minute deeper script */}
      <SectionLabel>5-minute deeper demo script</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px", margin: "10px 0 24px" }}>
        {DEMO_SCRIPT_5MIN.map((s, i) => (
          <StepCard key={s.id} step={s} index={i + 1} />
        ))}
      </div>

      {/* 3a. GitHub incident evidence script */}
      <SectionLabel>GitHub incident evidence demo script</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px", margin: "10px 0 24px" }}>
        {DEMO_SCRIPT_INCIDENT.map((s, i) => (
          <StepCard key={s.id} step={s} index={i + 1} />
        ))}
      </div>

      {/* 3b. AWS incident evidence script */}
      <SectionLabel>AWS incident evidence demo script</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px", margin: "10px 0 24px" }}>
        {DEMO_SCRIPT_AWS_INCIDENT.map((s, i) => (
          <StepCard key={s.id} step={s} index={i + 1} />
        ))}
      </div>

      {/* 3c. Cloudflare incident evidence script */}
      <SectionLabel>Cloudflare incident evidence demo script</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px", margin: "10px 0 24px" }}>
        {DEMO_SCRIPT_CLOUDFLARE_INCIDENT.map((s, i) => (
          <StepCard key={s.id} step={s} index={i + 1} />
        ))}
      </div>

      {/* 4. Objection handling */}
      <SectionLabel>Objection handling</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: "8px", margin: "10px 0 24px" }}>
        {DEMO_OBJECTIONS.map((o) => (
          <details key={o.question} className="bg-surface1 border border-border" style={{ borderRadius: "10px", padding: "12px 14px" }}>
            <summary style={{ fontSize: "13px", fontWeight: 600, color: "#e8eaf0", cursor: "pointer" }}>{o.question}</summary>
            <p style={{ fontSize: "12.5px", color: "#c4c8d4", lineHeight: 1.6, margin: "8px 0 0" }}>{o.answer}</p>
          </details>
        ))}
      </div>

      {/* 5. Wording guide */}
      <SectionLabel>Demo-safe wording guide</SectionLabel>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "14px", margin: "10px 0 24px" }}>
        <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "14px 16px" }}>
          <div style={{ fontSize: "12px", color: "#3ccf7e", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.04em" }}>Use</div>
          <ul style={{ margin: "8px 0 0", paddingLeft: "16px", display: "flex", flexDirection: "column", gap: "3px" }}>
            {DEMO_WORDING_GUIDE.use.map((w) => (
              <li key={w} style={{ fontSize: "12.5px", color: "#c4c8d4" }}>{w}</li>
            ))}
          </ul>
        </div>
        <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "14px 16px" }}>
          <div style={{ fontSize: "12px", color: "#f5632a", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.04em" }}>Avoid</div>
          <ul style={{ margin: "8px 0 0", paddingLeft: "16px", display: "flex", flexDirection: "column", gap: "3px" }}>
            {DEMO_WORDING_GUIDE.avoid.map((w) => (
              <li key={w} style={{ fontSize: "12.5px", color: "#8b90a0" }}>{w}</li>
            ))}
          </ul>
        </div>
      </div>

      {/* M75C — Provider capability matrix */}
      <SectionLabel>Provider capability matrix</SectionLabel>
      <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "14px 16px", marginBottom: "24px" }}>
        <p style={{ margin: "0 0 12px", fontSize: "12.5px", color: "#8b90a0", lineHeight: 1.6 }}>
          Shows which providers currently support drift monitoring, security configuration
          risk rules, activity evidence ingestion, Incident Signals, correlations, and
          demo cases. 8 providers are dual-stack complete. Azure and Google Cloud are demo-ready through drift findings, activity evidence, signals, risk × activity correlations, and case evidence, and remain tracked as partial providers. Twilio launched in M79A with drift-only partial state — drift snapshots are active, security rules and activity ingestion are planned for M79B+.{" "}
          <span style={{ color: "#565b6e" }}>
            Future providers should follow the dual-stack template: drift foundation →
            security rules → activity ingestion → signals → correlations → demo + QA.
          </span>
        </p>
        <div style={{ overflowX: "auto" }}>
          <table style={{ borderCollapse: "collapse", width: "100%", fontSize: "12px" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #2a2d38" }}>
                {["Provider", "Category", "Drift", "Security rules", "Activity", "Signals", "Correlations", "Demo/case"].map((h) => (
                  <th key={h} style={{ textAlign: "left", padding: "5px 10px 7px 0", color: "#565b6e", fontWeight: 500, whiteSpace: "nowrap" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {PROVIDER_CAPABILITY_TABLE.map(({ provider, label, category, drift, security, signals, correlations, demo }) => (
                <tr key={provider} style={{ borderBottom: "1px solid #1e2030" }}>
                  <td style={{ padding: "6px 10px 6px 0", color: "#e8eaf0", fontWeight: 600 }}>{label}</td>
                  <td style={{ padding: "6px 10px 6px 0", color: "#8b90a0" }}>{category}</td>
                  <td style={{ padding: "6px 10px 6px 0" }}><Dot on={drift} /></td>
                  <td style={{ padding: "6px 10px 6px 0" }}><Dot on={security} /></td>
                  <td style={{ padding: "6px 10px 6px 0" }}><Dot on={true} /></td>
                  <td style={{ padding: "6px 10px 6px 0" }}><Dot on={signals} /></td>
                  <td style={{ padding: "6px 10px 6px 0" }}><Dot on={correlations} /></td>
                  <td style={{ padding: "6px 10px 6px 0" }}><Dot on={demo} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p style={{ margin: "10px 0 0", fontSize: "11px", color: "#565b6e" }}>
          ● = supported · ○ = partial / planned · Drift = snapshot + diff + risk + review workflow.
        </p>
      </div>

      {/* M76 — Next-provider expansion template */}
      <SectionLabel>Next-provider expansion template</SectionLabel>
      <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "14px 16px", marginBottom: "24px" }}>
        <p style={{ margin: "0 0 10px", fontSize: "12.5px", color: "#8b90a0", lineHeight: 1.6 }}>
          Future providers should ship through the same dual-stack path:{" "}
          <span style={{ color: "#e8eaf0", fontWeight: 500 }}>
            drift foundation → security rules → activity ingestion → signals → correlations → demo + QA.
          </span>
          {" "}Each stage has canonical backend/frontend touchpoints, required tests, privacy constraints, and claim-discipline requirements.
        </p>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "12px" }}>
          {EXPANSION_STAGES_BRIEF.map((s, i) => (
            <span key={s} style={{ fontSize: "11.5px", fontWeight: 500, color: "#6b9cf8", background: "#0e1422", border: "1px solid #1e2a44", borderRadius: "6px", padding: "3px 10px", whiteSpace: "nowrap" }}>
              {i + 1}. {s}
            </span>
          ))}
        </div>
        <p style={{ margin: "0 0 6px", fontSize: "12px", color: "#8b90a0" }}>
          <strong style={{ color: "#e8eaf0" }}>Recommended next providers</strong> — in suggested onboarding order:
        </p>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
          {NEXT_PROVIDERS_BRIEF.map(({ label, category, milestone }) => (
            <div key={label} style={{ fontSize: "12px", background: "#1e2030", border: "1px solid #2a2d38", borderRadius: "8px", padding: "6px 12px" }}>
              <div style={{ color: "#e8eaf0", fontWeight: 600 }}>{label}</div>
              <div style={{ color: "#565b6e", fontSize: "11px" }}>{category} · {milestone}</div>
            </div>
          ))}
        </div>
        <p style={{ margin: "10px 0 0", fontSize: "11px", color: "#565b6e" }}>
          See <code style={{ color: "#8b90a0" }}>GET /security/provider-expansion-framework</code> for the full stage checklist, privacy requirements, and provider queue.
        </p>
      </div>

      {/* 6. Quick links */}
      <SectionLabel>Quick links</SectionLabel>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "10px" }}>
        {DEMO_QUICK_LINKS.map((l) => (
          <Link key={l.href} href={l.href} style={quickLink}>
            {l.label} →
          </Link>
        ))}
      </div>

      <p style={{ marginTop: "24px", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
        Presenter mode is for the team. The user-facing guided walkthrough lives in the
        floating widget on Security pages.
      </p>
    </div>
  );
}

// M76 — Expansion template stage labels (ordered, short names for the pill row).
const EXPANSION_STAGES_BRIEF: string[] = [
  "Drift Foundation",
  "Security Rules",
  "Activity Ingestion",
  "Signals",
  "Correlations",
  "Demo + QA",
];

// M76 — Recommended next providers (compact display data).
// NOTE: Twilio launched in M79A and moved into PROVIDER_CAPABILITY_TABLE below.
// SendGrid is now the head of the recommended queue.
const NEXT_PROVIDERS_BRIEF: Array<{ label: string; category: string; milestone: string }> = [
  { label: "SendGrid",  category: "communications", milestone: "M80A" },
  { label: "Auth0",     category: "auth",           milestone: "M80B" },
  { label: "Datadog",   category: "observability",  milestone: "M80C" },
  { label: "Clerk",     category: "auth",           milestone: "M80A" },
];

// M75C — Static capability table data. Source of truth lives in the backend
// service (provider_capability_matrix_service.py) and the GET
// /security/provider-capabilities endpoint. This local copy keeps the UI
// rendering without an extra network call so the demo-script page stays fast.
const PROVIDER_CAPABILITY_TABLE: Array<{
  provider: string;
  label: string;
  category: string;
  drift: boolean;
  security: boolean;
  signals: boolean;
  correlations: boolean;
  demo: boolean;
}> = [
  { provider: "github",     label: "GitHub",     category: "devops",             drift: true, security: true, signals: true, correlations: true, demo: true },
  { provider: "aws",        label: "AWS",         category: "cloud",              drift: true, security: true, signals: true, correlations: true, demo: true },
  { provider: "cloudflare", label: "Cloudflare",  category: "edge / network",     drift: true, security: true, signals: true, correlations: true, demo: true },
  { provider: "vercel",     label: "Vercel",      category: "devops",             drift: true, security: true, signals: true, correlations: true, demo: true },
  { provider: "supabase",   label: "Supabase",    category: "database / backend", drift: true, security: true, signals: true, correlations: true, demo: true },
  { provider: "firebase",   label: "Firebase",    category: "database / backend", drift: true, security: true, signals: true, correlations: true, demo: true },
  { provider: "stripe",     label: "Stripe",      category: "payments",           drift: true, security: true, signals: true, correlations: true, demo: true },
  { provider: "shopify",    label: "Shopify",     category: "ecommerce",          drift: true, security: true, signals: true, correlations: true, demo: true },
  { provider: "azure",      label: "Azure",       category: "cloud",              drift: true, security: true,  signals: true,  correlations: true,  demo: true  },
  { provider: "google_cloud", label: "Google Cloud", category: "cloud",            drift: true, security: true,  signals: true,  correlations: true,  demo: true  },
  { provider: "twilio",    label: "Twilio",      category: "communications",     drift: true, security: false, signals: false, correlations: false, demo: false },
];

function Dot({ on }: { on: boolean }) {
  return (
    <span style={{ color: on ? "#3ccf7e" : "#565b6e", fontSize: "14px" }}>
      {on ? "●" : "○"}
    </span>
  );
}

// ── Subcomponents ────────────────────────────────────────────────────────────

function StepCard({ step, index }: { step: DemoStep; index: number }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(step.talkTrack);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable — non-fatal */
    }
  };
  return (
    <details className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "14px 16px" }}>
      <summary style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }}>
        <span style={{ fontSize: "11px", fontWeight: 700, color: "#6b9cf8", background: "rgba(107,156,248,0.12)", border: "1px solid rgba(107,156,248,0.4)", borderRadius: "6px", padding: "1px 7px" }}>
          {index}
        </span>
        <span style={{ fontSize: "13.5px", fontWeight: 600, color: "#e8eaf0" }}>{step.title}</span>
      </summary>

      <p style={{ fontSize: "13px", color: "#c4c8d4", lineHeight: 1.6, margin: "12px 0 0" }}>{step.talkTrack}</p>

      <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "12px" }}>
        <ScriptLine label="Click" value={step.whatToClick} color="#8b90a0" />
        <ScriptLine label="Emphasize" value={step.emphasize} color="#3ccf7e" />
        <ScriptLine label="Avoid" value={step.avoid} color="#f5632a" />
      </div>

      <div style={{ display: "flex", gap: "8px", marginTop: "12px", flexWrap: "wrap" }}>
        <Link href={step.href} style={quickLink}>{step.cta} →</Link>
        <button type="button" onClick={copy} style={copyBtn}>
          {copied ? "Copied ✓" : "Copy talk track"}
        </button>
      </div>
    </details>
  );
}

function ScriptLine({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div style={{ fontSize: "12px", color: "#c4c8d4", lineHeight: 1.5 }}>
      <span style={{ color, fontWeight: 700, textTransform: "uppercase", fontSize: "10px", letterSpacing: "0.04em", marginRight: "8px" }}>
        {label}
      </span>
      {value}
    </div>
  );
}

const quickLink: React.CSSProperties = {
  fontSize: "12px",
  fontWeight: 600,
  color: "#6b9cf8",
  textDecoration: "none",
  border: "1px solid #2a2d38",
  borderRadius: "8px",
  padding: "5px 12px",
  whiteSpace: "nowrap",
};

const copyBtn: React.CSSProperties = {
  fontSize: "12px",
  fontWeight: 600,
  color: "#c4c8d4",
  background: "transparent",
  border: "1px solid #2a2d38",
  borderRadius: "8px",
  padding: "5px 12px",
  cursor: "pointer",
  fontFamily: "inherit",
};

function primaryBtn(busy: boolean): React.CSSProperties {
  return {
    fontSize: "13px",
    fontWeight: 600,
    color: "#fff",
    background: "#6b9cf8",
    border: "1px solid #6b9cf8",
    borderRadius: "8px",
    padding: "8px 16px",
    cursor: busy ? "wait" : "pointer",
    opacity: busy ? 0.6 : 1,
    fontFamily: "inherit",
  };
}
