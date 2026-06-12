/**
 * securityDemoScript.ts — presenter talk track for Configuration Risk (M63.7).
 *
 * Deterministic, frontend-only content for the founder/team "Demo Script" mode
 * (distinct from the user-facing SecurityDemoWalkthrough widget). Pure data +
 * a small readiness builder — no AI, no backend, no personalization.
 *
 * Wording stays demo-safe: "configuration exposure", "risky current state",
 * "metadata-only", "needs review". Never claims breach/attack/compromise,
 * "guaranteed secure", or compliance/SOC/SIEM replacement.
 */

export interface DemoReadinessInputs {
  demoLoaded: boolean | null;
  activeCount: number | null;
  findingCount: number | null;
  connectedProviders: number | null;
}

export interface DemoReadinessItem {
  id: string;
  label: string;
  ready: boolean;
  detail: string;
}

export interface DemoReadiness {
  items: DemoReadinessItem[];
  readyCount: number;
  total: number;
  needsDemoData: boolean;
}

/** Build the demo-readiness checklist from already-fetched status data. */
export function buildDemoReadiness(inp: DemoReadinessInputs): DemoReadiness {
  const demoLoaded = !!inp.demoLoaded;
  const findingCount = inp.findingCount ?? 0;
  const activeCount = inp.activeCount ?? 0;
  const hasData = findingCount > 0 || activeCount > 0;
  const connected = (inp.connectedProviders ?? 0) > 0;

  const items: DemoReadinessItem[] = [
    {
      id: "data",
      label: "Findings available to show",
      ready: hasData,
      detail: hasData
        ? `${findingCount} findings (${activeCount} active) ready to present.`
        : "No findings yet — load demo data or sync a connected provider.",
    },
    {
      id: "demo",
      label: "Demo data status",
      ready: demoLoaded || connected,
      detail: demoLoaded
        ? "Demo dataset is loaded (sample findings, not from connected providers)."
        : connected
          ? "Connected provider data is available."
          : "No demo data loaded. You can load it from this page.",
    },
    {
      id: "reports",
      label: "Reports ready",
      ready: hasData,
      detail: "Open Reports to export a metadata-only review packet during the demo.",
    },
    {
      id: "coverage",
      label: "Coverage view ready",
      ready: true,
      detail: "Coverage explains which provider surfaces have enough data to evaluate.",
    },
  ];

  return {
    items,
    readyCount: items.filter((i) => i.ready).length,
    total: items.length,
    needsDemoData: !demoLoaded && !hasData,
  };
}

export interface DemoStep {
  id: string;
  title: string;
  href: string;
  cta: string;
  talkTrack: string;
  whatToClick: string;
  emphasize: string;
  avoid: string;
}

/** Core 3-minute demo flow. */
export const DEMO_SCRIPT_3MIN: DemoStep[] = [
  {
    id: "opening",
    title: "Opening problem",
    href: "/security",
    cta: "Open Security Overview",
    talkTrack:
      "ConfigTrace is for the settings that Git does not track. Code changes have review history, but production-critical settings across GitHub, AWS, Cloudflare, Stripe, Firebase, and other tools often change without the same discipline.",
    whatToClick: "Start on the Security Overview so the whole posture is visible at once.",
    emphasize: "The gap is configuration, not code — and it spans many providers.",
    avoid: "Don't imply we detect breaches or replace existing security tools.",
  },
  {
    id: "overview",
    title: "Security Overview",
    href: "/security",
    cta: "Open Security Overview",
    talkTrack:
      "Configuration Risk shows risky current states from configuration metadata. It does not claim a breach happened. It tells the team what deserves review now.",
    whatToClick: "Point at the posture summary: active risks, critical/high, coverage.",
    emphasize: "One place to see what currently needs review across providers.",
    avoid: "Avoid 'secure/safe' verdicts — this is a review signal, not a guarantee.",
  },
  {
    id: "exposures",
    title: "Active Risks",
    href: "/security/risks",
    cta: "View Active Risks",
    talkTrack:
      "These are the risky current states we observe right now — each tied to a specific provider setting, with a severity and a confidence level.",
    whatToClick: "Scan the list; filter by severity or provider to show focus.",
    emphasize: "Every item is a current state, not a historical alert log.",
    avoid: "Don't call these 'attacks' or 'incidents' — they are exposures to review.",
  },
  {
    id: "detail",
    title: "Risk Detail",
    href: "/security/risks",
    cta: "Open a sample exposure",
    talkTrack:
      "Opening one finding shows the evidence we read from provider metadata, the confidence and false-positive safeguards, and the review actions the team can take.",
    whatToClick: "Open one finding; show confidence & safeguards and the action buttons.",
    emphasize: "Metadata-only evidence plus a clear review workflow.",
    avoid: "Don't read out secrets/payloads — we intentionally don't store them.",
  },
  {
    id: "assets",
    title: "Affected Assets",
    href: "/security/assets",
    cta: "View Affected Assets",
    talkTrack:
      "We group exposures by the asset they affect — a repository, bucket, webhook, security group, or project — so owners can see their own surface.",
    whatToClick: "Expand an asset to show its grouped findings.",
    emphasize: "Asset-centric view maps cleanly to team ownership.",
    avoid: "Avoid implying complete asset inventory — it's the assets with exposures.",
  },
  {
    id: "timeline",
    title: "Timeline",
    href: "/security/timeline",
    cta: "Open Risk Timeline",
    talkTrack:
      "The timeline shows when exposures opened, resolved, or were acknowledged, snoozed, or accepted — the review history settings usually lack.",
    whatToClick: "Scroll the timeline to show lifecycle, not just a current snapshot.",
    emphasize: "This is the audit-style trail for configuration review.",
    avoid: "Say 'review history', not 'compliance audit trail'.",
  },
  {
    id: "rules-coverage",
    title: "Rules and Coverage",
    href: "/security/rules",
    cta: "View Security Rules",
    talkTrack:
      "Every finding comes from a transparent, metadata-only rule. Coverage shows whether each provider is returning enough data for those rules to run.",
    whatToClick: "Show the rule catalog, then jump to Coverage for the data-quality view.",
    emphasize: "Transparent rules + honest coverage build trust.",
    avoid: "Don't overstate coverage — limited coverage is shown plainly.",
  },
  {
    id: "reports",
    title: "Reports",
    href: "/security/reports",
    cta: "Open Reports",
    talkTrack:
      "In a few clicks we export a metadata-only review packet a team can share internally — Markdown, JSON, or CSV — no payloads or secrets included.",
    whatToClick: "Generate a report and download Markdown to show the artifact.",
    emphasize: "Shareable, metadata-only review packet for internal use.",
    avoid: "Don't call it a 'compliance report' or 'audit guarantee'.",
  },
  {
    id: "closing",
    title: "Closing ask",
    href: "/security",
    cta: "Back to Overview",
    talkTrack:
      "If this is useful, the next step is connecting one provider read-only and letting it surface your real configuration exposures — usually within a sync or two.",
    whatToClick: "Return to Overview; offer to connect one provider after the call.",
    emphasize: "Low-friction next step: one read-only provider connection.",
    avoid: "Don't promise outcomes or guaranteed risk reduction.",
  },
];

/** Additional depth for a 5-minute version. */
export const DEMO_SCRIPT_5MIN: DemoStep[] = [
  {
    id: "coverage-deep",
    title: "Provider coverage",
    href: "/security/coverage",
    cta: "Open Coverage",
    talkTrack:
      "Coverage is our honesty layer: it shows expected vs observed record types per provider, so you know which checks can actually run.",
    whatToClick: "Show a provider with limited coverage and its recommendation.",
    emphasize: "We tell you what we can't see, not just what we can.",
    avoid: "Don't claim full coverage of any provider.",
  },
  {
    id: "confidence-deep",
    title: "Rule confidence",
    href: "/security/rules",
    cta: "View Rules",
    talkTrack:
      "Each rule carries a confidence level and a false-positive safeguard describing exactly when it fires — so findings are explainable, not a black box.",
    whatToClick: "Open a rule and read its confidence + safeguard.",
    emphasize: "Explainable findings with built-in noise safeguards.",
    avoid: "Don't claim zero false positives.",
  },
  {
    id: "diagnostics-deep",
    title: "Permission diagnostics",
    href: "/security/coverage",
    cta: "Open Coverage diagnostics",
    talkTrack:
      "When coverage is limited, we explain whether it's likely a permission gap, a missing sync, or a provider that simply doesn't expose that surface.",
    whatToClick: "Show a provider's diagnostic messages and permission hints.",
    emphasize: "Actionable next steps to improve coverage.",
    avoid: "Use 'may need' / 'could indicate' — never assert a provider is misconfigured.",
  },
  {
    id: "workflow-deep",
    title: "Accepted risk, Snooze, Notes",
    href: "/security/risks",
    cta: "Open an exposure",
    talkTrack:
      "Teams can acknowledge, snooze, accept a risk with an owner and expiry, or leave review notes — the collaborative workflow settings usually don't have.",
    whatToClick: "On a finding, show acknowledge, snooze, accept risk, and notes.",
    emphasize: "Accepted risk records intent and an expiry — it does not mean fixed.",
    avoid: "Don't imply accepting risk resolves or secures anything.",
  },
  {
    id: "reports-feedback-deep",
    title: "Report export + feedback",
    href: "/security/reports",
    cta: "Open Reports",
    talkTrack:
      "After exporting, we ask a quick optional question — was this useful — to keep improving the beta. The feedback never includes report contents.",
    whatToClick: "Export a report and show the optional feedback prompt.",
    emphasize: "Tight feedback loop; metadata-only by design.",
    avoid: "Don't call the prompt a 'survey'.",
  },
  {
    id: "analytics-deep",
    title: "Beta Analytics (admin)",
    href: "/security/beta-analytics",
    cta: "Open Beta Analytics",
    talkTrack:
      "For workspace admins, first-party beta analytics summarize how the team uses Configuration Risk — no third-party trackers, workspace-scoped only.",
    whatToClick: "If you're an admin, show the usage summary briefly.",
    emphasize: "First-party, privacy-safe usage insight.",
    avoid: "Skip if not an admin — it's admin-only and will show a permission message.",
  },
];

/**
 * GitHub incident-workflow flow (M66.10): Activity Events → Incident Signals →
 * Correlations → Cases → Reports. The spine: ConfigTrace does not claim a breach
 * from a risky setting alone — it sees the configuration risk, connects it to
 * GitHub audit activity, then creates a review signal and a human-reviewed case.
 */
export const DEMO_SCRIPT_INCIDENT: DemoStep[] = [
  {
    id: "incident-activity",
    title: "Activity Events",
    href: "/security/activity",
    cta: "Open Activity Events",
    talkTrack:
      "This is normalized GitHub audit activity — control-plane events like a webhook or branch protection changing. It's evidence for review, not detection. Source IPs are stored only as hashes.",
    whatToClick: "Open Activity Events and one event to show the metadata-only evidence.",
    emphasize: "Control-plane audit activity, metadata-only.",
    avoid: "Don't say this proves anyone did anything malicious.",
  },
  {
    id: "incident-signals",
    title: "Incident Signals",
    href: "/security/signals",
    cta: "Open Incident Signals",
    talkTrack:
      "From that activity, ConfigTrace raises a control-plane review signal. Severity reflects review priority — it never asserts compromise. Confidence is high only because the audit event states the action happened.",
    whatToClick: "Open a signal and read the calibrated review wording.",
    emphasize: "Review signal — may require review, not a confirmed incident.",
    avoid: "Avoid 'breach detected' / 'attacker found' — these are review signals.",
  },
  {
    id: "incident-correlations",
    title: "Correlations",
    href: "/security/correlations",
    cta: "Open Correlations",
    talkTrack:
      "Here's the differentiator: ConfigTrace connects the configuration risk to GitHub audit activity on the same repository within a review window. A risky setting plus activity that followed it is stronger evidence for review.",
    whatToClick: "Open a correlation to show the linked risk + activity and the timeline.",
    emphasize: "Configuration risk aligned with audit activity — potential security impact.",
    avoid: "Don't call a correlation a confirmed compromise.",
  },
  {
    id: "incident-cases",
    title: "Cases",
    href: "/security/cases",
    cta: "Open Cases",
    talkTrack:
      "A person groups the evidence into a human-reviewed case. Confirm or dismiss is a human action — 'Confirmed by user' is a workflow status, never a 'confirmed breach'. Admins can load a sample demo here.",
    whatToClick: "Open a case (or load the GitHub incident demo) to show grouped evidence + status.",
    emphasize: "Human-reviewed investigation; confirmation is a human decision.",
    avoid: "Don't say ConfigTrace auto-confirms anything.",
  },
  {
    id: "incident-report",
    title: "Case Evidence Report",
    href: "/security/cases",
    cta: "Export from a case",
    talkTrack:
      "Finally, export the case as a metadata-only evidence packet — Markdown or JSON — for review or a customer conversation. No raw payloads, IPs, secrets, or tokens.",
    whatToClick: "On a case, use Export Markdown / Export JSON.",
    emphasize: "Defensible, metadata-only evidence for review.",
    avoid: "Don't promise it certifies compliance or proves a breach.",
  },
];

export const DEMO_SCRIPT_AWS_INCIDENT: DemoStep[] = [
  {
    id: "aws-incident-activity",
    title: "AWS Activity Events",
    href: "/security/activity?provider=aws",
    cta: "Open Activity Events (AWS)",
    talkTrack:
      "Switch the provider to AWS. These are provider-reported AWS security findings — GuardDuty and Access Analyzer — normalized into evidence for review. ConfigTrace is not reading raw customer data and is not claiming a breach.",
    whatToClick: "On Activity Events, choose AWS and open an Access Analyzer finding.",
    emphasize: "Provider-reported finding, metadata-only evidence for review.",
    avoid: "Don't say this proves data was accessed or a breach occurred.",
  },
  {
    id: "aws-incident-signals",
    title: "AWS Incident Signals",
    href: "/security/signals?provider=aws",
    cta: "Open Incident Signals (AWS)",
    talkTrack:
      "From that provider finding, ConfigTrace raises an AWS Incident Signal. Severity reflects review priority and mirrors the provider-reported severity — it never asserts compromise or that someone has access.",
    whatToClick: "Open an AWS signal and read the provider-alert evidence level.",
    emphasize: "Provider-alert review signal — evidence for review, not a confirmed incident.",
    avoid: "Avoid 'breach detected' / 'attacker found' — these are review signals.",
  },
  {
    id: "aws-incident-correlations",
    title: "AWS Correlations",
    href: "/security/correlations?provider=aws",
    cta: "Open Correlations (AWS)",
    talkTrack:
      "Here's the differentiator for AWS: ConfigTrace connects a configuration risk — a public S3 bucket policy — to a provider-reported AWS security finding for the same bucket. A risky setting aligned with a provider alert is stronger evidence for review.",
    whatToClick: "Open an AWS correlation to show the linked S3 risk + Access Analyzer finding and the timeline.",
    emphasize: "Configuration risk aligned with provider alert — potential security impact.",
    avoid: "Don't call a correlation a confirmed compromise or unauthorized access.",
  },
  {
    id: "aws-incident-cases",
    title: "AWS Case",
    href: "/security/cases",
    cta: "Load AWS incident demo",
    talkTrack:
      "A person groups the evidence into a human-reviewed case. Admins can load a sample AWS evidence chain here — a public S3 configuration risk plus an Access Analyzer provider finding. Confirm or dismiss is a human action, never an automatic 'confirmed breach'.",
    whatToClick: "Use 'Load AWS incident demo' (admin-only) to seed and open the grouped case.",
    emphasize: "Human-reviewed investigation; confirmation is a human decision.",
    avoid: "Don't say ConfigTrace auto-confirms anything or identifies attackers.",
  },
  {
    id: "aws-incident-report",
    title: "AWS Case Evidence Report",
    href: "/security/cases",
    cta: "Export from the AWS case",
    talkTrack:
      "Finally, export the AWS case as a metadata-only evidence packet — Markdown or JSON. It summarizes the S3 configuration risk, the Access Analyzer finding, the signal, and the correlation. No raw payloads, IPs, secrets, or tokens.",
    whatToClick: "On the AWS case, use Export Markdown / Export JSON.",
    emphasize: "Defensible, metadata-only evidence for review.",
    avoid: "Don't promise it certifies compliance or proves a breach.",
  },
];

export interface ObjectionAnswer {
  question: string;
  answer: string;
}

export const DEMO_OBJECTIONS: ObjectionAnswer[] = [
  {
    question: "How is this different from Git?",
    answer:
      "Git tracks code. ConfigTrace tracks the production settings that live outside Git — provider configuration that changes without the same review history.",
  },
  {
    question: "Is this a SIEM?",
    answer:
      "No. We don't ingest logs or events. We read configuration metadata and surface risky current states for review. It complements, not replaces, security tooling.",
  },
  {
    question: "Does this detect breaches?",
    answer:
      "No. We do not claim breach or attack detection. We show configuration exposures — settings that deserve review — based on provider metadata.",
  },
  {
    question: "Can this replace cloud security tools?",
    answer:
      "No. Think of it as configuration-change visibility and a review workflow across providers. It sits alongside your existing tools.",
  },
  {
    question: "What happens if a rule is noisy?",
    answer:
      "Each rule has a false-positive safeguard, and rules can be disabled per workspace. You can also snooze or accept individual findings with a reason.",
  },
  {
    question: "How do we know a rule is reliable?",
    answer:
      "Every rule is metadata-only and explainable, with a confidence level, a stated safeguard, and a versioned rule pack so you know exactly what produced a finding.",
  },
  {
    question: "What data do you store?",
    answer:
      "Configuration metadata only. We don't store payloads, secrets, tokens, or customer data, and exports/feedback are metadata-only by design.",
  },
];

export interface WordingGuide {
  use: string[];
  avoid: string[];
}

export const DEMO_WORDING_GUIDE: WordingGuide = {
  use: [
    "configuration exposure",
    "risky current state",
    "metadata-only",
    "provider settings",
    "review workflow",
    "confidence and safeguards",
  ],
  avoid: [
    "breach detected",
    "attack detected",
    "compromise",
    "guaranteed secure",
    "compliance certified",
    "SOC / SIEM replacement",
  ],
};

export interface QuickLink {
  label: string;
  href: string;
}

export const DEMO_QUICK_LINKS: QuickLink[] = [
  { label: "Security Overview", href: "/security" },
  { label: "Active Risks", href: "/security/risks" },
  { label: "Affected Assets", href: "/security/assets" },
  { label: "Timeline", href: "/security/timeline" },
  { label: "Rules", href: "/security/rules" },
  { label: "Coverage", href: "/security/coverage" },
  { label: "Reports", href: "/security/reports" },
  { label: "Beta Analytics", href: "/security/beta-analytics" },
];
