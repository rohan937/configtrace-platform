/**
 * providers.ts — the ConfigTrace provider catalog (v2).
 *
 * Single source of truth for every provider chip / tile / matrix row in the
 * video. Categories follow the product's control-plane taxonomy.
 * All 20 providers are marked active and shown as fully covered.
 */

export type ProviderStatus = "active" | "roadmap";

export type ProviderCategory =
  | "Cloud / Edge"
  | "DevOps / Source"
  | "Payments / Commerce"
  | "App / Data / Backend"
  | "Messaging"
  | "Identity"
  | "Observability / Incident"
  | "Work management"
  | "Infrastructure as code";

export type Provider = {
  name: string;
  /** Short monogram for tiles (2–3 chars). */
  abbr: string;
  /** Brand-ish accent (tuned for a dark surface). */
  color: string;
  category: ProviderCategory;
  status: ProviderStatus;
};

/** Ordered by category, then by the product's launch sequence. */
export const PROVIDERS: Provider[] = [
  // Cloud / Edge
  { name: "Cloudflare", abbr: "CF", color: "#F38020", category: "Cloud / Edge", status: "active" },
  { name: "AWS", abbr: "AWS", color: "#FF9900", category: "Cloud / Edge", status: "active" },
  { name: "Azure", abbr: "AZ", color: "#3B97F6", category: "Cloud / Edge", status: "active" },
  { name: "Google Cloud", abbr: "GC", color: "#4285F4", category: "Cloud / Edge", status: "active" },
  { name: "Vercel", abbr: "VC", color: "#E5EAF2", category: "Cloud / Edge", status: "active" },

  // DevOps / Source
  { name: "GitHub", abbr: "GH", color: "#E5EAF2", category: "DevOps / Source", status: "active" },
  { name: "GitLab", abbr: "GL", color: "#FC6D26", category: "DevOps / Source", status: "active" },

  // Payments / Commerce
  { name: "Stripe", abbr: "ST", color: "#7A75FF", category: "Payments / Commerce", status: "active" },
  { name: "Shopify", abbr: "SH", color: "#95BF47", category: "Payments / Commerce", status: "active" },

  // App / Data / Backend
  { name: "Firebase", abbr: "FB", color: "#FFCA28", category: "App / Data / Backend", status: "active" },
  { name: "Supabase", abbr: "SB", color: "#3ECF8E", category: "App / Data / Backend", status: "active" },

  // Messaging
  { name: "Twilio", abbr: "TW", color: "#F22F46", category: "Messaging", status: "active" },
  { name: "SendGrid", abbr: "SG", color: "#3B82E0", category: "Messaging", status: "active" },

  // Identity
  { name: "Auth0", abbr: "A0", color: "#EB5424", category: "Identity", status: "active" },
  { name: "Clerk", abbr: "CL", color: "#7C5CFF", category: "Identity", status: "active" },

  // Observability / Incident
  { name: "Datadog", abbr: "DD", color: "#8A5CF6", category: "Observability / Incident", status: "active" },
  { name: "PagerDuty", abbr: "PD", color: "#3BB273", category: "Observability / Incident", status: "active" },

  // Work management
  { name: "Linear", abbr: "LN", color: "#7C8BF5", category: "Work management", status: "active" },
  { name: "Jira", abbr: "JR", color: "#2684FF", category: "Work management", status: "active" },

  // Infrastructure as code
  { name: "Terraform Cloud", abbr: "TF", color: "#8C6BE6", category: "Infrastructure as code", status: "active" },
];

export const ACTIVE_PROVIDERS = PROVIDERS.filter((p) => p.status === "active");
export const ROADMAP_PROVIDERS = PROVIDERS.filter((p) => p.status === "roadmap");

/** Count of shipped providers, surfaced as "18+" in the UI. */
export const ACTIVE_COUNT = ACTIVE_PROVIDERS.length;

/** Category order used when streaming tiles in by group. */
export const CATEGORY_ORDER: ProviderCategory[] = [
  "Cloud / Edge",
  "DevOps / Source",
  "Payments / Commerce",
  "App / Data / Backend",
  "Messaging",
  "Identity",
  "Observability / Incident",
  "Work management",
  "Infrastructure as code",
];

export const PROVIDERS_BY_CATEGORY: { category: ProviderCategory; providers: Provider[] }[] =
  CATEGORY_ORDER.map((category) => ({
    category,
    providers: PROVIDERS.filter((p) => p.category === category),
  }));

/** Quick lookup by name (for record rows, findings, etc.). */
export const PROVIDER_COLOR: Record<string, string> = Object.fromEntries(
  PROVIDERS.map((p) => [p.name, p.color]),
);

export const PROVIDER_ABBR: Record<string, string> = Object.fromEntries(
  PROVIDERS.map((p) => [p.name, p.abbr]),
);
