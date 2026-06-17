/**
 * Central provider metadata registry for all supported providers.
 *
 * Import `PROVIDERS` for the full map, or `getProviderMeta` for a safe
 * single-provider lookup that never returns undefined.
 *
 * M82-pre adds Azure, Google Cloud, Twilio, SendGrid, and Auth0 as
 * security-preview providers. They have a full security arc (drift rules,
 * activity ingestion, signals, correlations, demo + case evidence) but
 * the credential connect UI is not wired yet — they render with a
 * "Security preview" CTA that routes to /security/cases (the demo home)
 * instead of an integration connect form.
 */

export type ProviderId =
  | "cloudflare"
  | "github"
  | "vercel"
  | "stripe"
  | "aws"
  | "firebase"
  | "supabase"
  | "shopify"
  // ── M82-pre: security-preview providers (no connect form yet) ─────────────
  | "azure"
  | "google_cloud"
  | "twilio"
  | "sendgrid"
  | "auth0";

export type ProviderCategory =
  | "cdn_dns"
  | "developer"
  | "hosting"
  | "payments"
  | "cloud"
  | "backend"
  | "commerce"
  // ── M82-pre: new categories for completed security providers ──────────────
  | "communications"
  | "identity";

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
  /**
   * M82-pre: when true, the provider has a complete security/demo arc but
   * no credential connect UI. The integrations card renders a "Security
   * preview" CTA that routes to /security/cases (where the demo lives)
   * instead of opening a credential form.
   */
  securityPreview?: boolean;
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
      "Environment protection rules (required reviewers, branch policies)",
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
      "Deploy hooks (endpoint domain — URL path never stored)",
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
      "Billing portal configurations",
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

  shopify: {
    id: "shopify",
    label: "Shopify",
    shortLabel: "Shopify",
    category: "commerce",
    description:
      "Monitor Shopify store configuration, webhook subscriptions, and store policies for drift.",
    monitoredSurfaces: [
      "Store metadata (plan, timezone, currency, locale)",
      "Storefront access settings (password protection)",
      "Webhook subscriptions (endpoint domain, topic, HTTPS status)",
      "Store policies (presence and content hash — raw text never stored)",
      "App permission scopes (scope names — not store data)",
    ],
    trustNote:
      "ConfigTrace reads store configuration metadata only. Orders, customers, payment data, transaction records, and storefront theme files are never accessed or stored.",
    color: "#96bf48",
    bgColor: "rgba(150,191,72,0.10)",
    borderColor: "rgba(150,191,72,0.25)",
  },

  // ── M82-pre: security-preview providers ─────────────────────────────────
  // These providers have a complete security arc (drift rules, activity
  // ingestion, signals, risk × activity correlations, demo + case evidence)
  // but the credential connect UI is not wired yet. Their cards show a
  // "Security preview" CTA that routes to /security/cases instead of opening
  // a credential form. ConfigTrace never stores secrets, tokens, JWTs, raw
  // payloads, customer data, or PII for any of these providers.

  azure: {
    id: "azure",
    label: "Azure",
    shortLabel: "Azure",
    category: "cloud",
    description:
      "Track Azure identity, storage, networking, key vault, and security posture settings for review-safe drift and security evidence.",
    monitoredSurfaces: [
      "Identity and RBAC (role assignments, scope categories)",
      "Storage account exposure (public network access, secure transfer)",
      "Networking controls (NSG rule names — not raw rules)",
      "Key Vault posture (network access, soft-delete, purge protection)",
      "Security policy (Defender for Cloud plans)",
    ],
    trustNote:
      "ConfigTrace reads Azure configuration metadata only. Client secrets, access tokens, private keys, storage SAS tokens, connection strings, Key Vault secret names/values, raw policies, principal IDs, claims, customer/workload data, and PII are never accessed or stored.",
    color: "#0078d4",
    bgColor: "rgba(0,120,212,0.10)",
    borderColor: "rgba(0,120,212,0.25)",
    securityPreview: true,
  },

  google_cloud: {
    id: "google_cloud",
    label: "Google Cloud",
    shortLabel: "Google Cloud",
    category: "cloud",
    description:
      "Track Google Cloud IAM, storage, networking, service accounts, and security posture settings for review-safe drift and security evidence.",
    monitoredSurfaces: [
      "IAM policy summary (role + member-type categories — no principal emails)",
      "Cloud Storage bucket exposure (public access prevention, IAM)",
      "Service account key posture (count, age categories — no key material)",
      "Firewall and networking (VPC firewall rule names, target categories)",
      "Cloud Run / GKE / Cloud SQL posture",
      "Secret Manager presence (counts only — no secret values)",
    ],
    trustNote:
      "ConfigTrace reads Google Cloud configuration metadata only. Service account JSON key material, OAuth tokens, principal emails, caller IPs, raw protoPayload, full IAM bindings, container args, kubeconfig, secret payloads, customer/workload data, and PII are never accessed or stored.",
    color: "#4285f4",
    bgColor: "rgba(66,133,244,0.10)",
    borderColor: "rgba(66,133,244,0.25)",
    securityPreview: true,
  },

  twilio: {
    id: "twilio",
    label: "Twilio",
    shortLabel: "Twilio",
    category: "communications",
    description:
      "Track Twilio messaging, voice, phone number, webhook, key, and account posture settings for review-safe configuration evidence.",
    monitoredSurfaces: [
      "Messaging services (SID-prefix, observability posture)",
      "Webhook configuration presence (URL never stored)",
      "Phone numbers (last 4 digits only — never full numbers)",
      "API keys (SID only — never the secret)",
      "Account posture (Verify service settings, status)",
    ],
    trustNote:
      "ConfigTrace reads Twilio configuration metadata only. Auth tokens, API key secret values, full account SIDs, full phone-number strings, message bodies, call recordings, raw webhook URLs, customer phone data, and PII are never accessed or stored.",
    color: "#f22f46",
    bgColor: "rgba(242,47,70,0.10)",
    borderColor: "rgba(242,47,70,0.25)",
    securityPreview: true,
  },

  sendgrid: {
    id: "sendgrid",
    label: "SendGrid",
    shortLabel: "SendGrid",
    category: "communications",
    description:
      "Track SendGrid sender authentication, API keys, suppression settings, inbound parse, webhook, and mail security posture.",
    monitoredSurfaces: [
      "Sender authentication (sender identity verification, domain auth)",
      "API keys (opaque ID and scope counts only — never key values)",
      "Inbound parse posture (enabled, spam-check posture)",
      "Event webhooks (presence and enabled-events posture — never URLs)",
      "Suppression settings (group counts — never recipient emails)",
    ],
    trustNote:
      "ConfigTrace reads SendGrid configuration metadata only. API key values, bearer tokens, email content, subject lines, recipient/sender emails, template content, raw webhook URLs, mail event payloads, message IDs, customer data, and PII are never accessed or stored.",
    color: "#1a82e2",
    bgColor: "rgba(26,130,226,0.10)",
    borderColor: "rgba(26,130,226,0.25)",
    securityPreview: true,
  },

  auth0: {
    id: "auth0",
    label: "Auth0",
    shortLabel: "Auth0",
    category: "identity",
    description:
      "Track Auth0 tenant, application, connection, API, rule, action, MFA, and custom-domain posture for review-safe identity configuration evidence.",
    monitoredSurfaces: [
      "Tenant settings (session lifetime categories, dynamic-client flags)",
      "Applications / clients (OAuth posture, URL counts — never raw URLs)",
      "Connections (strategy, password policy categories)",
      "Resource servers / APIs (RBAC, offline access, scope counts)",
      "Rules and actions (presence, code-length categories — never code)",
      "MFA / Guardian factors (factor name, enabled status)",
      "Custom domains (status, TLS policy — never domain strings)",
    ],
    trustNote:
      "ConfigTrace reads Auth0 configuration metadata only. Client secrets, management tokens, access/refresh/ID tokens, JWTs, user emails, user IDs, login history, IP addresses, sessions, raw callback URLs, raw Auth0 logs, rule/action code, MFA recovery codes, and customer PII are never accessed or stored.",
    color: "#eb5424",
    bgColor: "rgba(235,84,36,0.10)",
    borderColor: "rgba(235,84,36,0.25)",
    securityPreview: true,
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
  "shopify",
  // ── M82-pre: security-preview providers (no connect form yet) ───────────
  "azure",
  "google_cloud",
  "twilio",
  "sendgrid",
  "auth0",
];

/**
 * M82-pre: subset of providers that have a connect form on /integrations.
 * Security-preview providers (azure, google_cloud, twilio, sendgrid, auth0)
 * have a complete security arc but no credential UI yet — their cards route
 * to /security/cases instead of opening a credential form.
 */
export const CONNECTABLE_PROVIDER_IDS: ProviderId[] = [
  "cloudflare",
  "github",
  "vercel",
  "stripe",
  "aws",
  "firebase",
  "supabase",
  "shopify",
];

/**
 * M82-pre: provider IDs whose card is rendered as a "Security preview"
 * card linking to /security/cases. These providers have drift rules,
 * activity ingestion, signals, correlations, and a demo case — but no
 * credential connect form yet.
 */
export const SECURITY_PREVIEW_PROVIDER_IDS: ProviderId[] = [
  "azure",
  "google_cloud",
  "twilio",
  "sendgrid",
  "auth0",
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
