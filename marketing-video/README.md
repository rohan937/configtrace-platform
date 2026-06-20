# ConfigTrace — Configuration Security & Drift Intelligence Walkthrough

A premium, product-walkthrough marketing video for ConfigTrace, built with
[Remotion](https://www.remotion.dev/). Dark enterprise security command-center
aesthetic with animated mock UI, a provider control-plane grid, drift diff
panels, a risk board, an activity timeline, an evidence/case graph, and an
animated demo cursor. **No audio, no external APIs, no copyrighted assets, no
screenshots** — everything is animated mock UI and motion graphics.

- **Composition:** `ConfigTraceSecurityExposureWalkthroughV2`
- **Format:** 1920×1080, 30fps, 80s, MP4
- **Output:** `out/configtrace-security-exposure-walkthrough-v2.mp4`

## Commands

```bash
npm install        # first time only
npm run preview    # open Remotion Studio to scrub/preview
npm run typecheck  # tsc --noEmit
npm run render     # render the MP4 -> out/configtrace-security-exposure-walkthrough-v2.mp4
npm run still      # render a single still -> out/still.png (debugging)
```

### Preview

```bash
npm run preview
```

### Render

```bash
npm run render
```

Output path: `out/configtrace-security-exposure-walkthrough-v2.mp4`

## Story (edit timing in `src/timing.ts`)

| # | Scene | Component | Beat |
|---|-------|-----------|------|
| 1 | Hook | `HookScene` | Code is not the only thing that changes (Production control-plane map) |
| 2 | Control plane | `ControlPlaneScene` | Risk lives across dozens of control planes (provider grid by category) |
| 3 | Snapshot engine | `SnapshotScene` | Snapshots of the settings production depends on (normalized records) |
| 4 | Drift detection | `DriftScene` | When settings drift, ConfigTrace shows what changed (diff panel + cursor) |
| 5 | Risk classification | `RiskScene` | Review-safe, evidence-backed findings (High/Medium/Low board + cursor) |
| 6 | Activity evidence | `ActivityScene` | Findings tied to control-plane activity (timeline + connector + cursor) |
| 7 | Case + report | `CaseGraphScene` | Scattered changes become one reviewable case (evidence graph + cursor) |
| 8 | Command center | `CommandCenterScene` | One place to see what changed (KPIs + provider coverage matrix) |
| 9 | Finale | `FinaleScene` | Know what changed / risky / needs review (system map + lockup) |

All scene durations live in `src/timing.ts`. Change a number there and the
composition length recomputes automatically.

## Providers (`src/providers.ts`)

Active coverage (all 20 shown with ✓): Cloudflare, AWS, Azure, Google Cloud,
Vercel, GitHub, GitLab, Stripe, Shopify, Firebase, Supabase, Twilio,
SendGrid, Auth0, Clerk, Datadog, PagerDuty, Linear, Jira, Terraform Cloud.

All 20 providers are shown as connected and covered: Cloudflare, AWS, Azure,
Google Cloud, Vercel, GitHub, GitLab, Stripe, Shopify, Firebase, Supabase,
Twilio, SendGrid, Auth0, Clerk, Datadog, PagerDuty, Linear, Jira, and
Terraform Cloud.

## Design tokens

`src/theme.ts` holds the palette (dark navy/black base, electric cyan / blue /
violet accents, severity colors), fonts, radii, and shadows. Provider brand
accents and categories live in `src/providers.ts`.

## Animated cursor

`src/components/AnimatedCursor.tsx` takes keyframes
(`{ frame, x, y, click?, hover?, label? }`) and eases between them, emitting a
hover ring on `hover` keys and a click ripple + press on `click` keys. Used in
scenes 4–7 to hover a drift row and click "View drift", click a risk finding,
hover an activity event, and click "Generate report".

## Components

Reusable mock-UI in `src/components/`:
`v2-mocks.tsx` (ProviderChip, ProviderGrid, Monogram, GlowBadge, MetricCard,
NormalizedRecordRow, SnapshotEnginePanel, DriftDiffPanel) and
`v2-graph.tsx` (RiskFindingCard, RiskBoard, ActivityTimeline, EvidenceGraph,
CaseReportPanel, ProviderCoverageMatrix, SystemMap, ControlPlaneMap), plus the
window chrome (`ProductFrame`), backdrop (`SceneShell`), and shared primitives
(`ui-mocks.tsx`).

## Notes

- Self-contained: does **not** import any real ConfigTrace app components.
- No screenshots are loaded or required; there is no `public/screenshots`
  dependency and no `SafeScreenshotFrame`.
- `out/` and `node_modules/` are git-ignored.
