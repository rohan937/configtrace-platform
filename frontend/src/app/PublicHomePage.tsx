/**
 * PublicHomePage — public, unauthenticated overview of ConfigTrace.
 *
 * Rendered at `/` for signed-out visitors (see ./page.tsx, which redirects
 * signed-in users to /dashboard instead). This exists so external
 * reviewers — e.g. Paddle's domain-verification crawler — can see what
 * ConfigTrace is without hitting an auth wall.
 *
 * Fully static: no client-side hooks, no calls to our backend API, no
 * workspace/session state. Every link either goes to a Clerk-hosted auth
 * route (/sign-in, /sign-up) or to the public marketing site
 * (configtrace.org/*). Nothing here renders customer or workspace data.
 */

import Link from "next/link";

const CAPABILITIES: { title: string; description: string }[] = [
  {
    title: "Continuous configuration snapshots",
    description:
      "ConfigTrace connects to your cloud and SaaS providers on a schedule and takes point-in-time snapshots of their configuration — no agents to install.",
  },
  {
    title: "Change detection & diffing",
    description:
      "Every new snapshot is diffed against the last one. Additions, removals, and modifications are captured as structured, resource-level changes.",
  },
  {
    title: "Risk classification",
    description:
      "Detected changes are classified by risk — from routine to critical — so the ones that matter surface first instead of getting lost in noise.",
  },
  {
    title: "Unified change timeline",
    description:
      "A single timeline correlates changes across every connected provider, making it easier to diagnose incidents caused by configuration drift.",
  },
  {
    title: "Security posture & findings",
    description:
      "Beyond drift, ConfigTrace evaluates provider-specific configuration against a rules engine to surface exposed resources, weak policies, and privilege risks.",
  },
  {
    title: "Broad provider coverage",
    description:
      "Cloud infrastructure (AWS, Azure, Google Cloud, Kubernetes, Cloudflare, Terraform Cloud), identity (Okta, Microsoft Entra ID, Auth0), and SaaS tools (GitHub, GitLab, Stripe, Snowflake, Sentry, Datadog, PagerDuty, Linear, Jira, and more).",
  },
];

const LEGAL_LINKS = [
  { label: "Pricing", href: "https://configtrace.org/pricing/" },
  { label: "Terms of Service", href: "https://configtrace.org/terms/" },
  { label: "Privacy Policy", href: "https://configtrace.org/privacy/" },
  { label: "Refund Policy", href: "https://configtrace.org/refunds/" },
];

export default function PublicHomePage() {
  return (
    <div style={{ minHeight: "100vh", background: "#0e0f11", color: "#e8eaf0" }}>
      {/* ── Top nav ─────────────────────────────────────────────────────── */}
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "20px 32px",
          borderBottom: "1px solid #2a2d38",
        }}
      >
        <span style={{ fontSize: 18, fontWeight: 700, color: "#e8eaf0", letterSpacing: "-0.01em" }}>
          ConfigTrace
        </span>
        <nav style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <Link
            href="/sign-in"
            style={{
              padding: "8px 16px",
              borderRadius: 6,
              fontSize: 14,
              fontWeight: 500,
              color: "#e8eaf0",
              border: "1px solid #2a2d38",
              textDecoration: "none",
            }}
          >
            Sign in
          </Link>
          <Link
            href="/sign-up"
            style={{
              padding: "8px 16px",
              borderRadius: 6,
              fontSize: 14,
              fontWeight: 600,
              color: "#fff",
              background: "#4f80f7",
              textDecoration: "none",
            }}
          >
            Get started
          </Link>
        </nav>
      </header>

      {/* ── Hero ────────────────────────────────────────────────────────── */}
      <main style={{ maxWidth: 880, margin: "0 auto", padding: "72px 24px 96px" }}>
        <h1
          style={{
            fontSize: 40,
            fontWeight: 700,
            lineHeight: 1.15,
            letterSpacing: "-0.02em",
            marginBottom: 20,
          }}
        >
          Configuration drift and security posture monitoring, in one place.
        </h1>
        <p style={{ fontSize: 18, color: "#8b90a0", lineHeight: 1.6, maxWidth: 680, marginBottom: 36 }}>
          ConfigTrace monitors your cloud infrastructure and SaaS tools for
          configuration drift and security posture risk. It snapshots
          configuration on a schedule, detects what changed, classifies the
          risk, and gives your team a single timeline to diagnose incidents
          and catch risky changes before they become outages.
        </p>
        <div style={{ display: "flex", gap: 12, marginBottom: 64 }}>
          <Link
            href="/sign-up"
            style={{
              padding: "12px 24px",
              borderRadius: 8,
              fontSize: 15,
              fontWeight: 600,
              color: "#fff",
              background: "#4f80f7",
              textDecoration: "none",
            }}
          >
            Create account
          </Link>
          <Link
            href="/sign-in"
            style={{
              padding: "12px 24px",
              borderRadius: 8,
              fontSize: 15,
              fontWeight: 600,
              color: "#e8eaf0",
              border: "1px solid #2a2d38",
              textDecoration: "none",
            }}
          >
            Sign in
          </Link>
        </div>

        {/* ── Read-only access ──────────────────────────────────────────── */}
        <section
          style={{
            background: "#13151a",
            border: "1px solid #2a2d38",
            borderRadius: 12,
            padding: "24px 28px",
            marginBottom: 56,
          }}
        >
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 8, color: "#e8eaf0" }}>
            Read-only by design
          </h2>
          <p style={{ fontSize: 14.5, color: "#8b90a0", lineHeight: 1.6 }}>
            Every provider connection uses read-only, scoped credentials.
            ConfigTrace only ever reads configuration state to build
            snapshots, detect changes, and evaluate security posture — it
            never modifies resources in a connected cloud or SaaS account.
          </p>
        </section>

        {/* ── Capabilities ───────────────────────────────────────────────── */}
        <section style={{ marginBottom: 64 }}>
          <h2 style={{ fontSize: 22, fontWeight: 700, marginBottom: 24 }}>What ConfigTrace does</h2>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
              gap: 20,
            }}
          >
            {CAPABILITIES.map((cap) => (
              <div
                key={cap.title}
                style={{
                  background: "#13151a",
                  border: "1px solid #2a2d38",
                  borderRadius: 10,
                  padding: "18px 20px",
                }}
              >
                <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 8, color: "#e8eaf0" }}>
                  {cap.title}
                </h3>
                <p style={{ fontSize: 13.5, color: "#8b90a0", lineHeight: 1.55, margin: 0 }}>
                  {cap.description}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* ── Support ────────────────────────────────────────────────────── */}
        <section style={{ marginBottom: 8 }}>
          <p style={{ fontSize: 14, color: "#8b90a0" }}>
            Questions? Reach us at{" "}
            <a href="mailto:support@configtrace.org" style={{ color: "#4f80f7", textDecoration: "none" }}>
              support@configtrace.org
            </a>
          </p>
        </section>
      </main>

      {/* ── Footer ─────────────────────────────────────────────────────── */}
      <footer
        style={{
          borderTop: "1px solid #2a2d38",
          padding: "28px 32px",
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 16,
        }}
      >
        <span style={{ fontSize: 13, color: "#565b6e" }}>
          &copy; {new Date().getFullYear()} ConfigTrace
        </span>
        <nav style={{ display: "flex", flexWrap: "wrap", gap: 20 }}>
          {LEGAL_LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              style={{ fontSize: 13, color: "#8b90a0", textDecoration: "none" }}
            >
              {link.label}
            </a>
          ))}
        </nav>
      </footer>
    </div>
  );
}
