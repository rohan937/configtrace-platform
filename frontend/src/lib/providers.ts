/**
 * Central provider metadata registry for all supported providers.
 *
 * Import `PROVIDERS` for the full map, or `getProviderMeta` for a safe
 * single-provider lookup that never returns undefined.
 *
 * M82-pre.1: Azure, Google Cloud, Twilio, SendGrid, and Auth0 are now
 * fully connectable. They each have a backend POST /integrations
 * allowlist entry, a credential form, encrypted credential storage, and
 * the existing connector dispatch in sync_service / sync_task. The
 * security-preview routing (M82-pre) is retired — the cards now render
 * the same "Connect" CTA as the canonical 8 providers.
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
  // ── M82-pre.1 — fully connectable security providers ─────────────────────
  | "azure"
  | "google_cloud"
  | "twilio"
  | "sendgrid"
  | "auth0"
  // ── M82A — Datadog drift provider foundation ──────────────────────────────
  | "datadog"
  // ── M83A — Clerk drift provider foundation ────────────────────────────────
  | "clerk"
  // ── M84A — PagerDuty drift provider foundation ────────────────────────────
  | "pagerduty";

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
  | "identity"
  // ── M82A: observability category for Datadog ──────────────────────────────
  | "observability"
  // ── M84A: incident_management category for PagerDuty ─────────────────────
  | "incident_management";

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
   * Legacy M82-pre flag. M82-pre.1 retired the security-preview path so
   * every provider in this registry is now fully connectable. Kept as an
   * optional field so historical entries that set it explicitly still
   * type-check; new entries should omit it.
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

  // ── M82-pre.1 — fully connectable security providers ─────────────────────
  // These providers have a complete security arc (drift rules, activity
  // ingestion, signals, risk × activity correlations, demo + case evidence)
  // AND a credential connect form, backend POST /integrations allowlist
  // entry, encrypted credential storage, and sync_task dispatch. ConfigTrace
  // never stores secrets, tokens, JWTs, raw payloads, customer data, or PII
  // for any of these providers — credential values are encrypted at rest
  // and never returned in API responses.

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
  },

  // ── M82A — Datadog drift provider foundation ──────────────────────────────
  datadog: {
    id: "datadog",
    label: "Datadog",
    shortLabel: "Datadog",
    category: "observability",
    description:
      "Track Datadog monitors, SLOs, dashboards, integrations, keys, roles, teams, and cloud integration posture for review-safe configuration evidence.",
    monitoredSurfaces: [
      "Monitors (type, status, priority — never raw query or message)",
      "SLOs (type, target categories, counts — never raw description)",
      "Dashboards (layout, widget/variable counts — never raw JSON or queries)",
      "Webhooks (presence booleans — never URL, headers, payload, or secrets)",
      "API/application keys (name, created/modified presence — never key values)",
      "Roles and teams (name, counts — never user identities or handles)",
      "Cloud integrations (AWS/GCP/Azure collection flags — never account IDs)",
    ],
    trustNote:
      "ConfigTrace stores Datadog credentials encrypted and uses them only to read selected configuration metadata. It does not store API key values, application key values, OAuth tokens, webhook secrets, raw monitor queries, raw dashboard JSON, logs, traces, metric values, incident text, emails, destination handles, customer data, or PII in findings.",
    color: "#632ca6",
    bgColor: "rgba(99,44,166,0.10)",
    borderColor: "rgba(99,44,166,0.25)",
  },

  // ── M83A — Clerk drift provider foundation ────────────────────────────────
  clerk: {
    id: "clerk",
    label: "Clerk",
    shortLabel: "Clerk",
    category: "identity",
    description:
      "Track Clerk authentication, domain, redirect, JWT template, webhook, organization, and session policy configuration for review-safe drift evidence.",
    monitoredSurfaces: [
      "Instance settings (environment type, sign-up/sign-in flags, MFA posture, restriction posture — never raw domain names or support emails)",
      "Domains (verified/primary/SSL posture — never raw domain name strings)",
      "Redirect URLs (scheme category and posture booleans — never raw URL strings)",
      "JWT templates (name, claims count, lifetime category — never template body or claims)",
      "Webhooks (scheme category and posture booleans — never URL, secret, or event names)",
      "Auth strategy (enabled methods, MFA posture — never provider secrets or certificates)",
      "Organization settings (enabled flags, membership category — never member identities)",
      "Session policy (lifetime and inactivity categories — never session tokens or IDs)",
    ],
    trustNote:
      "ConfigTrace stores Clerk credentials encrypted and uses them only to read selected configuration metadata. It does not store secret key values, session tokens, JWTs, OAuth tokens, webhook secrets, raw redirect URLs, raw callback URLs, user emails, user IDs, phone numbers, names, organization member identities, session history, login history, IP addresses, user agents, customer data, or PII in findings.",
    color: "#4f4fa3",
    bgColor: "rgba(79,79,163,0.10)",
    borderColor: "rgba(79,79,163,0.25)",
  },

  // ── M84A — PagerDuty drift provider foundation ────────────────────────────
  pagerduty: {
    id: "pagerduty",
    label: "PagerDuty",
    shortLabel: "PagerDuty",
    category: "incident_management",
    description:
      "Track PagerDuty service configuration, escalation policies, schedules, webhook subscriptions, and event orchestration posture for review-safe drift evidence.",
    monitoredSurfaces: [
      "Services (status, escalation policy ref, timeout categories — never integration keys or incident data)",
      "Escalation policies (rule/level structure, loop settings — never user targets or contact methods)",
      "Schedules (layer/user/team counts — never user identities or on-call data)",
      "Service integrations (type category, vendor name, key presence — never integration keys or routing keys)",
      "Webhook subscriptions (active, event count, URL scheme category — never delivery URL or secret)",
      "Event orchestrations (route count, team presence — never routing expressions)",
      "Business services (team/contact presence — never subscriber lists)",
      "Response plays (responder/subscriber counts, runnability — never responder identities)",
    ],
    trustNote:
      "ConfigTrace stores PagerDuty credentials encrypted and uses them only to read selected configuration metadata. It does not store API token values, routing keys, integration keys, webhook secrets, delivery URLs, user emails, user names, phone numbers, contact methods, on-call user identities, responder identities, subscriber identities, incident payloads, alert payloads, or customer PII in findings.",
    color: "#06ac38",
    bgColor: "rgba(6,172,56,0.10)",
    borderColor: "rgba(6,172,56,0.25)",
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
  // ── M82-pre.1 — fully connectable security providers ────────────────────
  "azure",
  "google_cloud",
  "twilio",
  "sendgrid",
  "auth0",
  // ── M82A — Datadog drift provider foundation ────────────────────────────
  "datadog",
  // ── M83A — Clerk drift provider foundation ────────────────────────────────
  "clerk",
  // ── M84A — PagerDuty drift provider foundation ────────────────────────────
  "pagerduty",
];

/**
 * M82-pre.1: every provider in the registry has a credential connect form
 * and a backend POST /integrations allowlist entry. SECURITY_PREVIEW_*
 * is retained as an empty array for backwards compatibility with the
 * integrations page's preview branch — no provider currently routes
 * through the security-preview fallback.
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
  // ── M82-pre.1 — fully connectable security providers ────────────────────
  "azure",
  "google_cloud",
  "twilio",
  "sendgrid",
  "auth0",
  // ── M82A — Datadog drift provider foundation ────────────────────────────
  "datadog",
  // ── M83A — Clerk drift provider foundation ────────────────────────────────
  "clerk",
  // ── M84A — PagerDuty drift provider foundation ────────────────────────────
  "pagerduty",
];

/**
 * M82-pre.1: empty. The five M82-pre providers (azure/google_cloud/twilio/
 * sendgrid/auth0) are now fully connectable so none route through the
 * security-preview fallback. The constant remains exported (rather than
 * deleted) so callers can keep referencing it without churn.
 */
export const SECURITY_PREVIEW_PROVIDER_IDS: ProviderId[] = [];

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
