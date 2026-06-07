import PageHeader from "@/components/common/PageHeader";
import {
  PreviewBanner,
  SectionLabel,
  StatCard,
} from "@/components/security/previews";

/**
 * Security Overview (M60.1 placeholder).
 *
 * The landing page for the Security Exposure product mode. Polished, but no
 * real data — the findings engine arrives in M60.3/M60.4.
 */
export default function SecurityOverviewPage() {
  return (
    <div>
      <PageHeader
        title="Security Exposure"
        description="Find risky current states across connected cloud and SaaS tools."
      />

      {/* Positioning statement */}
      <div
        className="bg-surface1 border border-border"
        style={{ borderRadius: "12px", padding: "20px 22px", marginBottom: "24px" }}
      >
        <p style={{ margin: 0, fontSize: "15px", color: "#c4c8d4", lineHeight: 1.6 }}>
          <span style={{ color: "#e8eaf0", fontWeight: 600 }}>
            Drift Detection tells you what changed. Security Exposure tells you
            what is dangerous right now.
          </span>{" "}
          ConfigTrace evaluates the current state of your connected providers and
          surfaces security-relevant configuration exposure — weak controls,
          internet-facing risks, and settings that leave production open.
        </p>
      </div>

      <PreviewBanner>
        Security exposure findings will appear here after M60.3/M60.4 adds the
        findings engine. The cards below are a preview of what this overview will
        track.
      </PreviewBanner>

      {/* Metric cards */}
      <SectionLabel>Exposure summary</SectionLabel>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "14px",
        }}
      >
        <StatCard label="Active exposures" accent="#f5632a" hint="Awaiting engine" />
        <StatCard label="Critical exposures" accent="#e84040" hint="Awaiting engine" />
        <StatCard
          label="High-risk controls weakened"
          accent="#f5a623"
          hint="Awaiting engine"
        />
        <StatCard
          label="Internet-facing risks"
          accent="#6b9cf8"
          hint="Awaiting engine"
        />
        <StatCard label="Recently resolved" accent="#3ccf7e" hint="Awaiting engine" />
      </div>

      {/* What's coming */}
      <div style={{ marginTop: "32px" }}>
        <SectionLabel>What Security Exposure will do</SectionLabel>
        <div
          className="bg-surface1 border border-border"
          style={{ borderRadius: "12px", padding: "18px 20px" }}
        >
          <ul
            style={{
              margin: 0,
              paddingLeft: "18px",
              color: "#8b90a0",
              fontSize: "13.5px",
              lineHeight: 1.9,
            }}
          >
            <li>Evaluate connected provider settings against security rules</li>
            <li>Flag risky current states (not just changes) as active exposures</li>
            <li>Track each exposure through its lifecycle until resolved</li>
            <li>
              Reuse your existing integrations and alert channels — no new setup
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}
