import React from "react";
import { AbsoluteFill, Easing, interpolate, useCurrentFrame } from "remotion";
import { COLORS, FONT_MONO, FONT_SANS } from "./theme";
import { SceneShell, Caption, useEntrance } from "./components/SceneShell";
import { ProductFrame } from "./components/ProductFrame";
import { AnimatedCursor } from "./components/AnimatedCursor";
import { Card, SectionLabel, hexA } from "./components/ui-mocks";
import {
  ProviderGrid,
  SnapshotEnginePanel,
  DriftDiffPanel,
  DriftRow,
  MetricCard,
  GlowBadge,
} from "./components/v2-mocks";
import {
  RiskBoard,
  RiskColumn,
  ActivityTimeline,
  ActivityEvent,
  EvidenceGraph,
  CaseReportPanel,
  ProviderCoverageMatrix,
  SystemMap,
  ControlPlaneMap,
  Finding,
} from "./components/v2-graph";

/* helpers ------------------------------------------------------------------ */

const Center: React.FC<{ children: React.ReactNode; top?: number }> = ({ children, top = 100 }) => (
  <AbsoluteFill style={{ alignItems: "center", justifyContent: "flex-start", paddingTop: top }}>
    {children}
  </AbsoluteFill>
);

const entrance = (frame: number, delay = 0, distance = 24): React.CSSProperties => {
  const t = interpolate(frame, [delay, delay + 16], [0, 1], {
    easing: Easing.out(Easing.cubic),
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  return { opacity: t, transform: `translateY(${(1 - t) * distance}px)` };
};

const Heading: React.FC<{
  lines: string[];
  appearAt?: number;
  accentIndex?: number;
  size?: number;
}> = ({ lines, appearAt = 3, accentIndex = -1, size = 46 }) => {
  const frame = useCurrentFrame();
  return (
    <div style={{ textAlign: "center" }}>
      {lines.map((l, i) => {
        const o = interpolate(frame, [appearAt + i * 9, appearAt + i * 9 + 16], [0, 1], {
          extrapolateLeft: "clamp",
          extrapolateRight: "clamp",
        });
        const ty = interpolate(frame, [appearAt + i * 9, appearAt + i * 9 + 16], [16, 0], {
          easing: Easing.out(Easing.cubic),
          extrapolateLeft: "clamp",
          extrapolateRight: "clamp",
        });
        return (
          <div
            key={l}
            style={{
              fontFamily: FONT_SANS,
              fontSize: size,
              fontWeight: 800,
              letterSpacing: -1.1,
              color: i === accentIndex ? COLORS.blueBright : COLORS.text,
              opacity: o,
              transform: `translateY(${ty}px)`,
              lineHeight: 1.18,
            }}
          >
            {l}
          </div>
        );
      })}
    </div>
  );
};

const Subtext: React.FC<{ children: React.ReactNode; appearAt?: number }> = ({ children, appearAt = 24 }) => {
  const frame = useCurrentFrame();
  const o = interpolate(frame, [appearAt, appearAt + 14], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return (
    <div style={{ textAlign: "center", opacity: o, marginTop: 12 }}>
      <span style={{ fontFamily: FONT_SANS, fontSize: 19, fontWeight: 500, color: COLORS.textMuted }}>{children}</span>
    </div>
  );
};

/* ==========================================================================
   Scene 1 — Hook: code is not the only thing that changes
   ========================================================================== */

export const HookScene: React.FC = () => {
  return (
    <SceneShell glow="blue">
      <div style={{ position: "absolute", top: 66, left: 0, right: 0 }}>
        <Heading lines={["Code is not the only thing that changes."]} appearAt={2} size={48} />
      </div>
      <Center top={188}>
        <ControlPlaneMap width={780} height={600} />
      </Center>
      <Caption appearAt={120}>Someone changed the configuration around the code.</Caption>
    </SceneShell>
  );
};

/* ==========================================================================
   Scene 2 — The hidden control plane (provider grid)
   ========================================================================== */

export const ControlPlaneScene: React.FC = () => {
  const frame = useCurrentFrame();
  const progress = interpolate(frame, [12, 150], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return (
    <SceneShell glow="cyan">
      <div style={{ position: "absolute", top: 48, left: 0, right: 0 }}>
        <Heading lines={["Your risk lives across dozens of control planes."]} appearAt={2} size={40} />
        <Subtext appearAt={18}>ConfigTrace turns those settings into one reviewable system.</Subtext>
      </div>
      <Center top={196}>
        <div style={{ width: 1640 }}>
          <ProviderGrid progress={progress} columns={3} />
        </div>
      </Center>
    </SceneShell>
  );
};

/* ==========================================================================
   Scene 3 — Configuration snapshot engine
   ========================================================================== */

export const SnapshotScene: React.FC = () => {
  const frame = useCurrentFrame();
  const reveal = interpolate(frame, [22, 220], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const ent = useEntrance(4);
  return (
    <SceneShell glow="cyan">
      <Center top={170}>
        <div style={ent}>
          <ProductFrame
            width={1560}
            height={600}
            url="app.configtrace.org/snapshots"
            header={<EngineHeader title="Configuration Snapshot Engine" subtitle="Normalized, metadata-only config records" />}
          >
            <SnapshotEnginePanel
              metrics={[
                { label: "Providers connected", value: "20", accent: COLORS.blueBright },
                { label: "Control planes monitored", value: "20", accent: COLORS.cyan },
                { label: "Risk surfaces tracked", value: "340+", accent: COLORS.violet },
                { label: "Open findings", value: "18", accent: COLORS.amber },
              ]}
              reveal={reveal}
              visibleCount={7}
            />
          </ProductFrame>
        </div>
      </Center>
      <Caption appearAt={18}>ConfigTrace snapshots the settings production depends on.</Caption>
    </SceneShell>
  );
};

/* ==========================================================================
   Scene 4 — Drift detection (diff panel + cursor)
   ========================================================================== */

const DRIFT_ROWS: DriftRow[] = [
  { label: "Stripe webhook changed", provider: "Stripe", before: "status: enabled · has_secret: true", after: "status: enabled · has_secret: false", severity: "warning" },
  { label: "GitHub branch protection weakened", provider: "GitHub", before: "required_reviews: 2", after: "required_reviews: 0", severity: "warning" },
  { label: "Cloudflare DNS record removed", provider: "Cloudflare", before: "record: api.example.com (present)", after: "record: api.example.com (removed)", severity: "warning" },
  { label: "PagerDuty escalation path changed", provider: "PagerDuty", before: "escalation: tier-1 → tier-2", after: "escalation: tier-1 only", severity: "warning" },
  { label: "Jira permission scheme broadened", provider: "Jira", before: "grants: scoped (12 holders)", after: "grants: broadened (org-wide)", severity: "critical" },
  { label: "Terraform workspace variable changed", provider: "Terraform Cloud", before: "auto_apply: false", after: "auto_apply: true", severity: "info" },
];

export const DriftScene: React.FC = () => {
  const frame = useCurrentFrame();
  const reveal = interpolate(frame, [12, 120], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const expand = interpolate(frame, [160, 195], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const ent = useEntrance(2);
  return (
    <SceneShell glow="amber">
      <Center top={140}>
        <div style={ent}>
          <ProductFrame
            width={1480}
            height={660}
            url="app.configtrace.org/drift"
            header={<EngineHeader title="Drift Detection" subtitle="What changed across your control planes" />}
          >
            <DriftDiffPanel rows={DRIFT_ROWS} reveal={reveal} expandedIndex={4} expand={expand} />
          </ProductFrame>
        </div>
      </Center>
      <AnimatedCursor
        keys={[
          { frame: 70, x: 1300, y: 360 },
          { frame: 128, x: 1630, y: 544, hover: true },
          { frame: 150, x: 1630, y: 544, click: true, label: "View drift" },
        ]}
      />
      <Caption appearAt={16}>When settings drift, ConfigTrace shows what changed.</Caption>
    </SceneShell>
  );
};

/* ==========================================================================
   Scene 5 — Risk classification (findings board + cursor)
   ========================================================================== */

const RISK_COLUMNS: RiskColumn[] = [
  {
    level: "High",
    findings: [
      { severity: "critical", title: "Jira permission scheme may allow broad access", provider: "Jira" },
      { severity: "critical", title: "Cloudflare DNS record deleted", provider: "Cloudflare" },
    ],
  },
  {
    level: "Medium",
    findings: [
      { severity: "warning", title: "GitLab protected branch rule weakened", provider: "GitLab" },
      { severity: "warning", title: "Auth0 callback configuration changed", provider: "Auth0" },
      { severity: "warning", title: "PagerDuty escalation policy changed", provider: "PagerDuty" },
    ],
  },
  {
    level: "Low",
    findings: [
      { severity: "info", title: "Terraform workspace variable requires review", provider: "Terraform Cloud" },
      { severity: "info", title: "Stripe webhook missing secret indicator", provider: "Stripe" },
    ],
  },
];

export const RiskScene: React.FC = () => {
  const frame = useCurrentFrame();
  const progress = interpolate(frame, [12, 160], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const active = frame >= 230 ? { col: 0, row: 0 } : undefined;
  const ent = useEntrance(2);
  return (
    <SceneShell glow="blue">
      <Center top={170}>
        <div style={ent}>
          <ProductFrame
            width={1480}
            height={600}
            url="app.configtrace.org/findings"
            header={<EngineHeader title="Risk Classification" subtitle="Configuration risk — without claiming a breach" />}
          >
            <RiskBoard columns={RISK_COLUMNS} progress={progress} activeCard={active} />
          </ProductFrame>
        </div>
      </Center>
      <AnimatedCursor
        keys={[
          { frame: 175, x: 900, y: 320 },
          { frame: 215, x: 478, y: 405, hover: true },
          { frame: 230, x: 478, y: 405, click: true, label: "Open finding" },
        ]}
      />
      <Caption appearAt={16}>Every finding is review-safe and evidence-backed.</Caption>
    </SceneShell>
  );
};

/* ==========================================================================
   Scene 6 — Activity evidence (timeline + finding link + cursor)
   ========================================================================== */

const ACTIVITY_EVENTS: ActivityEvent[] = [
  { provider: "GitHub", title: "GitHub repository settings updated", time: "2m ago" },
  { provider: "Stripe", title: "Stripe webhook configuration updated", time: "14m ago" },
  { provider: "PagerDuty", title: "PagerDuty service route updated", time: "38m ago" },
  { provider: "Linear", title: "Linear workflow state updated", time: "1h ago" },
  { provider: "Jira", title: "Jira permission scheme updated", time: "1h ago" },
  { provider: "Terraform Cloud", title: "Terraform workspace setting updated", time: "2h ago" },
];

const JIRA_FINDING: Finding = {
  severity: "critical",
  title: "Jira permission scheme may allow broad access",
  provider: "Jira",
};

export const ActivityScene: React.FC = () => {
  const frame = useCurrentFrame();
  const progress = interpolate(frame, [12, 140], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const edge = interpolate(frame, [150, 185], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const popoverReveal = interpolate(frame, [210, 245], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const ent = useEntrance(2);
  return (
    <SceneShell glow="cyan">
      <Center top={160}>
        <div style={ent}>
          <ProductFrame
            width={1480}
            height={620}
            url="app.configtrace.org/activity"
            header={<EngineHeader title="Activity Evidence" subtitle="Findings tied to control-plane activity" />}
          >
            <div style={{ display: "flex", gap: 26, height: "100%" }}>
              {/* left: linked finding */}
              <div style={{ width: 360, flexShrink: 0, display: "flex", flexDirection: "column", gap: 14 }}>
                <SectionLabel color={COLORS.red}>Finding</SectionLabel>
                <Card severity="critical" glow={0.3} style={{ padding: 16 }}>
                  <div style={{ fontFamily: FONT_SANS, fontSize: 15, fontWeight: 700, color: COLORS.text, lineHeight: 1.4 }}>
                    {JIRA_FINDING.title}
                  </div>
                  <div style={{ fontFamily: FONT_MONO, fontSize: 11.5, color: COLORS.textMuted, marginTop: 8 }}>
                    Jira · permission scheme
                  </div>
                </Card>
                <div style={{ opacity: edge }}>
                  <GlowBadge color={COLORS.cyan} glow={0.3 * edge}>+ related activity evidence</GlowBadge>
                </div>
                <div style={{ fontFamily: FONT_SANS, fontSize: 12.5, color: COLORS.textFaint, lineHeight: 1.6, marginTop: 4 }}>
                  Findings + activity = a reviewable story.
                </div>
              </div>

              {/* right: activity timeline */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <SectionLabel color={COLORS.cyan}>Control-plane activity</SectionLabel>
                <div style={{ marginTop: 14 }}>
                  <ActivityTimeline
                    events={ACTIVITY_EVENTS}
                    progress={progress}
                    popoverIndex={4}
                    popoverReveal={popoverReveal}
                  />
                </div>
              </div>
            </div>
          </ProductFrame>
        </div>
      </Center>

      {/* finding → activity connector (scene-level overlay) */}
      <svg width={1920} height={1080} style={{ position: "absolute", inset: 0, pointerEvents: "none" }}>
        <path
          d={`M 606 366 C 700 420, 600 590, 662 593`}
          stroke={hexA(COLORS.cyan, 0.7)}
          strokeWidth={2}
          strokeDasharray="4 5"
          fill="none"
          strokeDashoffset={(1 - edge) * 360}
          opacity={edge}
        />
      </svg>

      <AnimatedCursor
        keys={[
          { frame: 150, x: 1100, y: 360 },
          { frame: 205, x: 1280, y: 593, hover: true, label: "evidence" },
          { frame: 250, x: 1280, y: 593, hover: true },
        ]}
        color={COLORS.cyanBright}
      />
      <Caption appearAt={16}>Risk becomes more useful when it is tied to activity evidence.</Caption>
    </SceneShell>
  );
};

/* ==========================================================================
   Scene 7 — Case graph + report (cursor clicks Generate report)
   ========================================================================== */

export const CaseGraphScene: React.FC = () => {
  const frame = useCurrentFrame();
  const graphProgress = interpolate(frame, [12, 150], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const generateHot = frame >= 205 && frame <= 240;
  const reportReveal = interpolate(frame, [215, 260], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const ent = useEntrance(2);
  return (
    <SceneShell glow="violet">
      <Center top={110}>
        <div style={ent}>
          <ProductFrame
            width={1480}
            height={720}
            url="app.configtrace.org/cases"
            header={<EngineHeader title="Security Case" subtitle="Scattered config changes, one reviewable case" />}
          >
            <div style={{ display: "flex", gap: 22, height: "100%" }}>
              <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <EvidenceGraph progress={graphProgress} width={580} height={500} />
              </div>
              <div style={{ width: 600, flexShrink: 0 }}>
                <CaseReportPanel reportReveal={reportReveal} generateHot={generateHot} />
              </div>
            </div>
          </ProductFrame>
        </div>
      </Center>
      <AnimatedCursor
        keys={[
          { frame: 150, x: 1050, y: 360 },
          { frame: 200, x: 1180, y: 770, hover: true },
          { frame: 210, x: 1180, y: 770, click: true, label: "Generate report" },
        ]}
        color={COLORS.violet}
      />
      <Caption appearAt={16}>ConfigTrace turns scattered config changes into cases your team can review.</Caption>
    </SceneShell>
  );
};

/* ==========================================================================
   Scene 8 — Cross-provider command center
   ========================================================================== */

export const CommandCenterScene: React.FC = () => {
  const frame = useCurrentFrame();
  const matrix = interpolate(frame, [44, 230], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const ent = useEntrance(2);
  const cards = [
    { label: "Connected providers", value: "20", accent: COLORS.blueBright },
    { label: "Open findings", value: "18", accent: COLORS.amber },
    { label: "Critical review items", value: "4", accent: COLORS.red },
    { label: "Recent drift events", value: "42", accent: COLORS.cyan },
    { label: "Cases created", value: "7", accent: COLORS.green },
  ];
  return (
    <SceneShell glow="blue">
      <Center top={170}>
        <div style={ent}>
          <ProductFrame
            width={1560}
            height={600}
            url="app.configtrace.org/overview"
            header={<EngineHeader title="Command Center" subtitle="One control plane for production settings" />}
          >
            <div style={{ display: "flex", flexDirection: "column", gap: 18, height: "100%" }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 14 }}>
                {cards.map((c, i) => (
                  <div key={c.label} style={entrance(frame, 8 + i * 6)}>
                    <MetricCard label={c.label} value={c.value} accent={c.accent} glow={i === 2 ? 0.25 : 0} />
                  </div>
                ))}
              </div>
              <div style={{ flex: 1, minHeight: 0 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
                  <SectionLabel color={COLORS.blueBright}>Provider coverage matrix</SectionLabel>
                </div>
                <ProviderCoverageMatrix progress={matrix} columns={5} />
              </div>
            </div>
          </ProductFrame>
        </div>
      </Center>
      <Caption appearAt={16}>One place to see what changed before production breaks.</Caption>
    </SceneShell>
  );
};

/* ==========================================================================
   Scene 9 — Final positioning + system map
   ========================================================================== */

export const FinaleScene: React.FC = () => {
  const frame = useCurrentFrame();
  const progress = interpolate(frame, [10, 110], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const headO = interpolate(frame, [118, 142], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const taglineO = interpolate(frame, [140, 162], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const discO = interpolate(frame, [165, 188], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return (
    <SceneShell glow="blue">
      <Center top={300}>
        <div style={{ width: 1560 }}>
          <div style={{ marginBottom: 44 }}>
            <SystemMap progress={progress} />
          </div>

          <div style={{ textAlign: "center", opacity: headO }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 14 }}>
              <div style={{ width: 36, height: 36, borderRadius: 9, border: `2px solid ${COLORS.blueBright}`, background: hexA(COLORS.blue, 0.16) }} />
              <span style={{ fontFamily: FONT_SANS, fontWeight: 800, fontSize: 52, color: COLORS.text, letterSpacing: -1 }}>
                ConfigTrace
              </span>
            </div>
          </div>

          <div style={{ textAlign: "center", marginTop: 22, opacity: taglineO }}>
            <span style={{ fontFamily: FONT_SANS, fontSize: 30, fontWeight: 700, color: COLORS.text, letterSpacing: -0.4 }}>
              Know what changed.{" "}
              <span style={{ color: COLORS.cyan }}>Know what is risky.</span>{" "}
              <span style={{ color: COLORS.blueBright }}>Know what needs review.</span>
            </span>
          </div>

          <div style={{ textAlign: "center", marginTop: 26, opacity: discO }}>
            <span style={{ fontFamily: FONT_SANS, fontSize: 13, color: COLORS.textFaint, letterSpacing: 0.3 }}>
              Configuration security evidence. Review required.
            </span>
          </div>
        </div>
      </Center>
    </SceneShell>
  );
};

/* ==========================================================================
   shared engine header (app window content header)
   ========================================================================== */

const EngineHeader: React.FC<{ title: string; subtitle?: string }> = ({ title, subtitle }) => (
  <div
    style={{
      height: 64,
      borderBottom: `1px solid ${COLORS.cardBorder}`,
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      padding: "0 26px",
      flexShrink: 0,
    }}
  >
    <div>
      <div style={{ fontFamily: FONT_SANS, fontWeight: 700, fontSize: 18, color: COLORS.text, letterSpacing: -0.2 }}>
        {title}
      </div>
      {subtitle ? (
        <div style={{ fontFamily: FONT_SANS, fontSize: 12, color: COLORS.textFaint, marginTop: 2 }}>{subtitle}</div>
      ) : null}
    </div>
    <GlowBadge color={COLORS.green} glow={0.15}>metadata-only</GlowBadge>
  </div>
);
