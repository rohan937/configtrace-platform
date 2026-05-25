/**
 * Central provider metadata registry for all 7 supported providers.
 *
 * Import `PROVIDERS` for the full map, or `getProviderMeta` for a safe
 * single-provider lookup that never returns undefined.
 */

export type ProviderId =
  | "cloudflare"
  | "github"
  | "vercel"
  | "stripe"
  | "aws"
  | "firebase"
  | "supabase";

export type ProviderCategory =
  | "cdn_dns"
  | "developer"
  | "hosting"
  | "payments"
  | "cloud"
  | "backend";

export interface ProviderMeta {
  id: ProviderId;
  /** Full display name, e.g. "Amazon Web Services" */
  label: string;
  /** Short label for badges and tight spaces, e.g. "AWS" */
  shortLabel: string;
  category: ProviderCategory;
  /** One-sentence description shown in the integration picker. */
  description: string;
  /** Human-readable list of configuration surfaces ConfigTrace monitors. */
  monitoredSurfaces: string[];
  /** Honest note on what ConfigTrace does NOT access (shown in the form). */
  trustNote: string;
  /** Accent color for badges (CSS colour string). */
  color: string;
  /** Background tint for badges (CSS colour string, low-opacity). */
  bgColor: string;
  /** Border color for badges (CSS colour string). */
  borderColor: string;
}

export const PROVIDERS: Record<ProviderId, ProviderMeta> = {
  cloudflare: {
    id: "cloudflare",
    label: "Cloudflare",
    shortLabel: "Cloudflare",
    category: "cdn_dns",
    description: "Monitor DNS records, WAF rules, and zone settings for drift.",
    monitoredSurfaces: [
      "DNS records (A, AAAA, CNAME, MX, TXT, …)",
      "Zone settings",
    ],
    trustNote:
      "ConfigTrace reads DNS record metadata only. Traffic content, request logs, and Analytics data are never accessed.",
    color: "#f48120",
    bgColor: "rgba(244,129,32,0.10)",
    borderColor: "rgba(244,129,32,0.25)",
  },

  github: {
    id: "github",
    label: "GitHub",
    shortLabel: "GitHub",
    category: "developer",
    description:
      "Track repository settings, branch protection, webhooks, and secrets.",
    monitoredSurfaces: [
      "Repository settings (visibility, default branch)",
      "Branch protection rules",
      "Webhooks",
      "Actions secrets (names only — never values)",
      "Deploy keys",
    ],
    trustNote:
      "ConfigTrace reads repository configuration only. Source code, commit contents, pull request bodies, issue text, and secret values are never accessed.",
    color: "#b0b5c4",
    bgColor: "rgba(176,181,196,0.08)",
    borderColor: "#2a2d38",
  },

  vercel: {
    id: "vercel",
    label: "Vercel",
    shortLabel: "Vercel",
    category: "hosting",
    description:
      "Monitor Vercel project configuration, environment variable keys, and custom domains.",
    monitoredSurfaces: [
      "Project settings (framework, build command, Node.js version)",
      "Environment variable keys (never values)",
      "Custom domains",
      "Git branch configuration",
    ],
    trustNote:
      "ConfigTrace reads project configuration only. Environment variable values, deployment logs, function source code, and build artefacts are never accessed.",
    color: "#b0b5c4",
    bgColor: "rgba(176,181,196,0.08)",
    borderColor: "#2a2d38",
  },

  stripe: {
    id: "stripe",
    label: "Stripe",
    shortLabel: "Stripe",
    category: "payments",
    description:
      "Track Stripe account settings, webhook endpoints, and payment method configuration.",
    monitoredSurfaces: [
      "Account settings (charges/payouts enabled, payout schedule)",
      "Webhook endpoints (URL, enabled events)",
      "Payment method configurations",
      "Payment method domains",
    ],
    trustNote:
      "ConfigTrace reads account configuration only. Customer data, payment card details, transaction records, and Stripe secret keys are never accessed.",
    color: "#8b90a0",
    bgColor: "rgba(99,91,255,0.10)",
    borderColor: "rgba(99,91,255,0.25)",
  },

  aws: {
    id: "aws",
    label: "Amazon Web Services",
    shortLabel: "AWS",
    category: "cloud",
    description:
      "Monitor IAM posture, S3 bucket policies, security groups, and dozens of other AWS surfaces for configuration drift.",
    monitoredSurfaces: [
      "IAM users, roles, policies, and access keys",
      "S3 bucket policies and public-access settings",
      "Security groups and VPC network config",
      "Lambda functions, API Gateway, ECS/EKS",
      "CloudTrail, GuardDuty, Security Hub",
      "RDS, KMS, Secrets Manager, and more",
    ],
    trustNote:
      "ConfigTrace reads resource metadata and configuration only. S3 object contents, database row data, Lambda function source code, and secret values are never accessed or stored.",
    color: "#f5a623",
    bgColor: "rgba(245,166,35,0.10)",
    borderColor: "rgba(245,166,35,0.25)",
  },

  firebase: {
    id: "firebase",
    label: "Firebase",
    shortLabel: "Firebase",
    category: "backend",
    description:
      "Track Firebase project configuration, Auth settings, Firestore rules, and Hosting config.",
    monitoredSurfaces: [
      "Project metadata (region, status)",
      "Authentication settings (sign-in providers, authorized domains)",
      "Firestore security rulesets (rule text hash, not query data)",
      "Storage buckets and security rulesets",
      "Hosting sites and custom domains",
      "Cloud Function metadata (names, regions — not source code)",
    ],
    trustNote:
      "ConfigTrace reads project-level configuration only. Firestore document data, Auth user PII, Storage file contents, and Function source code are never accessed.",
    color: "#ffca28",
    bgColor: "rgba(255,202,40,0.10)",
    borderColor: "rgba(255,202,40,0.25)",
  },

  supabase: {
    id: "supabase",
    label: "Supabase",
    shortLabel: "Supabase",
    category: "backend",
    description:
      "Monitor Supabase project configuration, Auth settings, RLS status, and network restrictions.",
    monitoredSurfaces: [
      "Project metadata (region, status, plan)",
      "Auth settings (sign-in methods, MFA, session config)",
      "Database pooler config",
      "Storage config",
      "Edge Function metadata (names — not source code)",
      "RLS enabled/forced flags per table (no row data)",
      "Network restrictions and custom domain",
      "OAuth provider configuration",
    ],
    trustNote:
      "ConfigTrace reads project-level configuration only. Database row data, Auth user PII, Edge Function source code, secret values, and Storage file contents are never accessed.",
    color: "#3ecf8e",
    bgColor: "rgba(62,207,142,0.10)",
    borderColor: "rgba(62,207,142,0.25)",
  },
};

/** All provider IDs in display order. */
export const PROVIDER_IDS: ProviderId[] = [
  "cloudflare",
  "github",
  "vercel",
  "stripe",
  "aws",
  "firebase",
  "supabase",
];

/**
 * Safe single-provider lookup.  Returns a minimal fallback object if the
 * provider is not in the registry (e.g. an unknown future provider).
 */
export function getProviderMeta(id: string): ProviderMeta {
  const meta = PROVIDERS[id as ProviderId];
  if (meta) return meta;
  // Fallback for unknown providers
  return {
    id: id as ProviderId,
    label: id.charAt(0).toUpperCase() + id.slice(1),
    shortLabel: id,
    category: "cloud",
    description: `${id} integration.`,
    monitoredSurfaces: [],
    trustNote: "",
    color: "#8b90a0",
    bgColor: "rgba(139,144,160,0.10)",
    borderColor: "#2a2d38",
  };
}

/**
 * Short display label for a provider string.
 * Safe to call with null/undefined — returns "Unknown" in that case.
 */
export function providerDisplayLabel(provider: string | null | undefined): string {
  if (!provider) return "Unknown";
  return getProviderMeta(provider).shortLabel;
}
