import PageHeader from "@/components/common/PageHeader";
import {
  PreviewBanner,
  RuleRow,
  SectionLabel,
} from "@/components/security/previews";

/**
 * Security Rules (M60.1 placeholder).
 *
 * Preview of the rule catalog that will evaluate provider settings for risky
 * security states. The rules engine itself arrives in M60.3/M60.4.
 */
export default function SecurityRulesPage() {
  return (
    <div>
      <PageHeader
        title="Security Rules"
        description="Rules that will evaluate connected provider settings for risky security states."
      />

      <PreviewBanner>
        Rules are previews of the planned catalog and are not active yet. The
        engine that evaluates them lands in M60.3/M60.4.
      </PreviewBanner>

      <SectionLabel>Planned rule catalog</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        <RuleRow
          title="Webhook endpoint uses HTTP"
          severity="critical"
          providers="GitHub · Stripe"
        />
        <RuleRow
          title="Branch protection missing"
          severity="high"
          providers="GitHub"
        />
        <RuleRow
          title="Public admin port exposed"
          severity="critical"
          providers="AWS"
        />
        <RuleRow title="WAF disabled" severity="high" providers="Cloudflare" />
        <RuleRow title="RLS disabled" severity="high" providers="Supabase" />
        <RuleRow
          title="Public bucket policy detected"
          severity="medium"
          providers="AWS"
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
        Rules evaluate configuration state only. They use your existing,
        metadata-only provider connections — no new access is required.
      </p>
    </div>
  );
}
