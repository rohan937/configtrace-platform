import PageHeader from "@/components/common/PageHeader";
import {
  LifecycleFlow,
  PreviewBanner,
  SectionLabel,
} from "@/components/security/previews";

/**
 * Exposure Timeline (M60.1 placeholder).
 *
 * Preview of the exposure lifecycle view. Real lifecycle events arrive with the
 * findings engine in M60.3/M60.4.
 */
export default function ExposureTimelinePage() {
  return (
    <div>
      <PageHeader
        title="Exposure Timeline"
        description="Track when exposures open, change, get accepted, or resolve."
      />

      <PreviewBanner>
        The exposure timeline will populate after M60.3/M60.4 adds the findings
        engine. Below is the lifecycle each exposure will follow.
      </PreviewBanner>

      <SectionLabel>Exposure lifecycle</SectionLabel>
      <div
        className="bg-surface1 border border-border"
        style={{ borderRadius: "12px", padding: "22px", marginBottom: "28px" }}
      >
        <LifecycleFlow
          steps={["Exposure opened", "Alert sent", "Reviewed", "Resolved"]}
        />
      </div>

      <SectionLabel>What the timeline will record</SectionLabel>
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
          <li>When an exposure first opens and which rule flagged it</li>
          <li>When an alert was sent and to which channel</li>
          <li>When a teammate reviewed or accepted the exposure</li>
          <li>When the underlying setting was fixed and the exposure resolved</li>
        </ul>
      </div>
    </div>
  );
}
