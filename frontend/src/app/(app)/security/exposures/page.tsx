import PageHeader from "@/components/common/PageHeader";
import {
  ExposureRow,
  PreviewBanner,
  SectionLabel,
} from "@/components/security/previews";

/**
 * Active Exposures (M60.1 placeholder).
 *
 * Preview of the live exposure list. All rows are clearly labelled examples —
 * real findings arrive with the engine in M60.3/M60.4.
 */
export default function ActiveExposuresPage() {
  return (
    <div>
      <PageHeader
        title="Active Exposures"
        description="Current risky states that may expose production systems or weaken security controls."
      />

      <PreviewBanner>
        These are preview examples, not real findings. Live exposures will appear
        here after M60.3/M60.4 adds the findings engine.
      </PreviewBanner>

      <SectionLabel>Example exposures</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
        <ExposureRow
          severity="critical"
          title="GitHub webhook uses HTTP"
          provider="GitHub"
          detail="Webhook delivery URL is plain http:// — payloads may be sent in cleartext"
        />
        <ExposureRow
          severity="critical"
          title="AWS security group exposes admin port"
          provider="AWS"
          detail="Port 22 open to 0.0.0.0/0 — administrative access reachable from the internet"
        />
        <ExposureRow
          severity="high"
          title="Cloudflare WAF rule disabled"
          provider="Cloudflare"
          detail="A managed WAF ruleset is turned off — known attack patterns no longer blocked"
        />
        <ExposureRow
          severity="high"
          title="Supabase RLS disabled"
          provider="Supabase"
          detail="Row Level Security is off on a public table — rows may be broadly readable"
        />
      </div>

      <p
        style={{
          marginTop: "20px",
          fontSize: "12px",
          color: "#565b6e",
          lineHeight: 1.6,
        }}
      >
        ConfigTrace reports security-relevant configuration exposure. It does not
        detect breaches or monitor live traffic.
      </p>
    </div>
  );
}
