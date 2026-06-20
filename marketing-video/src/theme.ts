/**
 * theme.ts — ConfigTrace video design tokens.
 *
 * Security-operations / infrastructure control-plane aesthetic.
 * Dark, sharp, credible. Blue/cyan/green accents; red/amber severity.
 * Deliberately NOT a quant-research / scorecard look.
 */

export const COLORS = {
  // Backgrounds
  bgBase: "#080B10",
  bgSecondary: "#0D111A",
  bgElevated: "#111827",
  grid: "rgba(148, 163, 184, 0.06)",

  // Card surfaces
  card: "rgba(15, 23, 42, 0.78)",
  cardBorder: "rgba(148, 163, 184, 0.16)",
  cardBorderActive: "rgba(96, 165, 250, 0.55)",
  cardBorderCritical: "rgba(248, 113, 113, 0.45)",
  cardBorderWarning: "rgba(251, 191, 36, 0.42)",
  cardBorderSafe: "rgba(52, 211, 153, 0.38)",

  // Accents
  blue: "#4F7BFF",
  blueBright: "#5B7CFF",
  cyan: "#38BDF8",
  cyanBright: "#22D3EE",
  violet: "#A78BFA",
  violetBright: "#8B5CF6",
  green: "#34D399",
  greenBright: "#22C55E",
  amber: "#FBBF24",
  amberDeep: "#F59E0B",
  red: "#FF5A5F",
  redDeep: "#EF4444",
  roadmap: "#7C8BA8",

  // Text
  text: "#E5EAF2",
  textMuted: "#94A3B8",
  textFaint: "#64748B",
  textInk: "#0B1220",
} as const;

export const FONT_SANS =
  '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", "Geist", Roboto, system-ui, sans-serif';
export const FONT_MONO =
  '"SF Mono", "JetBrains Mono", "Fira Code", ui-monospace, Menlo, Consolas, monospace';

export type Severity = "critical" | "warning" | "safe" | "info";

export const severityColor = (s: Severity): string => {
  switch (s) {
    case "critical":
      return COLORS.red;
    case "warning":
      return COLORS.amber;
    case "safe":
      return COLORS.green;
    default:
      return COLORS.blue;
  }
};

export const severityBorder = (s: Severity): string => {
  switch (s) {
    case "critical":
      return COLORS.cardBorderCritical;
    case "warning":
      return COLORS.cardBorderWarning;
    case "safe":
      return COLORS.cardBorderSafe;
    default:
      return COLORS.cardBorderActive;
  }
};

/** Standard easing for product-walkthrough motion (smooth, slightly snappy). */
export const EASE = (() => {
  // cubic-bezier-ish easeOutCubic via Remotion's Easing is applied in components;
  // this object documents intent and shared radii / shadows.
  return {
    radius: 16,
    radiusSm: 10,
    radiusLg: 22,
    shadow: "0 18px 50px rgba(2, 6, 18, 0.55)",
    shadowSoft: "0 8px 24px rgba(2, 6, 18, 0.4)",
  };
})();
