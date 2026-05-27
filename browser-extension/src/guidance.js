/* ConfigTrace browser helper — provider detection + static guidance catalog.
 *
 * Loaded by:
 *   • content scripts (manifest.json -> content_scripts.js[])
 *   • the popup (<script src="guidance.js"> in popup.html)
 *
 * SAFETY:
 *   This file performs URL-pattern detection only.
 *   It does NOT read DOM content, form values, secrets, customer data,
 *   source code, payment data, order data, database rows, logs, or file
 *   contents from provider pages. It does NOT issue network requests.
 *
 *   Detection is based solely on `window.location` hostname, pathname,
 *   and hash — all of which are part of the URL the browser is already
 *   showing in the address bar.
 */

const CT_APP_DEFAULT_BASE = "https://app.configtrace.org";
const CT_DOCS_BASE = "https://configtrace.org";

const CT_LINKS = {
  app:         "/",
  timeline:    "/timeline",
  needsReview: "/needs-review",
  integrations:"/integrations",
  demo:        CT_DOCS_BASE + "/demo.html",
  docs:        CT_DOCS_BASE + "/docs.html",
  trust:       CT_DOCS_BASE + "/docs/data-access.html"
};

/* ---------------------------------------------------------------------------
 * Static guidance catalog.
 *
 * Language is intentionally hedged ("may", "could", "potential blast radius").
 * No "auto-fix", no "guaranteed", no "breach", no compliance claims.
 * ------------------------------------------------------------------------- */
const CT_GUIDANCE = {
  /* ───── AWS ───── */
  aws_security_groups: {
    provider: "AWS",
    title: "AWS Security Groups",
    monitors: [
      "Public SSH / RDP ingress rules",
      "Database and cache port exposure",
      "Default security group drift"
    ],
    guidance:
      "Security group changes may expose resources attached to the group. ConfigTrace can detect risky ingress drift and show potential blast radius.",
    docsPath: "/docs/aws.html"
  },
  aws_iam: {
    provider: "AWS",
    title: "AWS IAM",
    monitors: [
      "Inline and attached IAM policies",
      "Role trust policies",
      "Newly granted broad permissions"
    ],
    guidance:
      "IAM policy changes may widen who can act on your AWS resources. ConfigTrace tracks attached and inline policy documents for drift.",
    docsPath: "/docs/aws.html"
  },
  aws_route53: {
    provider: "AWS",
    title: "AWS Route 53",
    monitors: [
      "Hosted zone record sets",
      "Routing changes (CNAME, A, AAAA)",
      "Deleted records that may affect resolution"
    ],
    guidance:
      "DNS changes can reroute production traffic or remove resolution entirely. ConfigTrace risk-classifies each record change.",
    docsPath: "/docs/aws.html"
  },
  aws_s3: {
    provider: "AWS",
    title: "AWS S3",
    monitors: [
      "Bucket policies",
      "Public access block settings",
      "ACL and ownership configuration"
    ],
    guidance:
      "Bucket policy and public-access changes could affect whether bucket objects are reachable from outside your account.",
    docsPath: "/docs/aws.html"
  },
  aws_console: {
    provider: "AWS",
    title: "AWS Console",
    monitors: [
      "Security groups, IAM, Route 53, S3, and related configuration"
    ],
    guidance:
      "ConfigTrace monitors security-relevant AWS configuration metadata (no resource data, no logs).",
    docsPath: "/docs/aws.html"
  },

  /* ───── GitHub ───── */
  github_branch_protection: {
    provider: "GitHub",
    title: "GitHub Branch Protection",
    monitors: [
      "Required pull request reviews",
      "Required status checks",
      "Force-push and deletion protection"
    ],
    guidance:
      "Branch protection weakening could allow unreviewed pushes to production branches. ConfigTrace flags rule changes here.",
    docsPath: "/docs/github.html"
  },
  github_environments: {
    provider: "GitHub",
    title: "GitHub Environments",
    monitors: [
      "Required reviewers",
      "Deployment branch policies",
      "Environment secret names (presence only)"
    ],
    guidance:
      "Environment protection changes may remove guardrails on deploys. ConfigTrace tracks required reviewers and policies.",
    docsPath: "/docs/github.html"
  },
  github_webhooks: {
    provider: "GitHub",
    title: "GitHub Webhooks",
    monitors: [
      "Webhook target URLs",
      "Subscribed event types",
      "Active / inactive state"
    ],
    guidance:
      "Webhook target changes may quietly reroute repo events to a different endpoint. ConfigTrace records each change.",
    docsPath: "/docs/github.html"
  },
  github_secrets: {
    provider: "GitHub",
    title: "GitHub Actions Secrets",
    monitors: [
      "Secret names (presence only — never values)",
      "Secret scope changes",
      "Variables added or removed"
    ],
    guidance:
      "ConfigTrace records the presence and scope of Actions secrets and variables. Secret values are never read or stored.",
    docsPath: "/docs/github.html"
  },
  github_settings: {
    provider: "GitHub",
    title: "GitHub Repo Settings",
    monitors: [
      "Repo visibility",
      "Default branch",
      "Collaborator and team access metadata"
    ],
    guidance:
      "Repo-level settings changes may affect access or release behavior. ConfigTrace tracks them as metadata only.",
    docsPath: "/docs/github.html"
  },

  /* ───── Stripe ───── */
  stripe_webhooks: {
    provider: "Stripe",
    title: "Stripe Webhooks",
    monitors: [
      "Webhook endpoint URLs",
      "Subscribed event types",
      "Endpoint enabled / disabled state"
    ],
    guidance:
      "Webhook URL or event-list changes can break payment reconciliation. ConfigTrace risk-classifies endpoint drift.",
    docsPath: "/docs/stripe.html"
  },
  stripe_api_keys: {
    provider: "Stripe",
    title: "Stripe API Keys",
    monitors: [
      "API key metadata (presence, scope) — never the key value",
      "Restricted key permissions",
      "Key creation and revocation events"
    ],
    guidance:
      "ConfigTrace tracks the presence and scope of Stripe API keys. Key values are never read or stored.",
    docsPath: "/docs/stripe.html"
  },
  stripe_settings: {
    provider: "Stripe",
    title: "Stripe Settings",
    monitors: [
      "Webhook, product, and account configuration metadata"
    ],
    guidance:
      "Account-level Stripe settings changes may affect payments or notifications. ConfigTrace records them as metadata only.",
    docsPath: "/docs/stripe.html"
  },
  stripe_dashboard: {
    provider: "Stripe",
    title: "Stripe Dashboard",
    monitors: [
      "Webhook endpoints, product config, restricted key metadata"
    ],
    guidance:
      "ConfigTrace monitors Stripe configuration metadata. It never reads payment data, customer details, or transaction history.",
    docsPath: "/docs/stripe.html"
  },

  /* ───── Cloudflare ───── */
  cloudflare_dns: {
    provider: "Cloudflare",
    title: "Cloudflare DNS",
    monitors: [
      "All record types (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA)",
      "Per-record TTL and proxy status",
      "Record additions and deletions"
    ],
    guidance:
      "DNS changes can reroute production traffic or deactivate proxy protections. ConfigTrace tracks every record field.",
    docsPath: "/docs/cloudflare.html"
  },
  cloudflare_waf: {
    provider: "Cloudflare",
    title: "Cloudflare WAF",
    monitors: [
      "Firewall rules and managed rulesets",
      "Rate-limit and bot-fight configuration",
      "Rule enabled / disabled state"
    ],
    guidance:
      "WAF rule changes may widen attack surface or disable bot protections. ConfigTrace records each rule diff.",
    docsPath: "/docs/cloudflare.html"
  },
  cloudflare_ssl: {
    provider: "Cloudflare",
    title: "Cloudflare SSL/TLS",
    monitors: [
      "SSL/TLS mode and certificate settings",
      "HSTS configuration",
      "Edge certificate metadata"
    ],
    guidance:
      "SSL/TLS configuration changes can affect how browsers establish secure connections. ConfigTrace tracks the settings.",
    docsPath: "/docs/cloudflare.html"
  },
  cloudflare_dashboard: {
    provider: "Cloudflare",
    title: "Cloudflare Dashboard",
    monitors: [
      "DNS records, WAF rules, SSL/TLS settings"
    ],
    guidance:
      "ConfigTrace monitors Cloudflare configuration metadata. It never reads request logs or visitor data.",
    docsPath: "/docs/cloudflare.html"
  },

  /* ───── Vercel ───── */
  vercel_env: {
    provider: "Vercel",
    title: "Vercel Environment Variables",
    monitors: [
      "Variable names and target environments",
      "Variable additions and removals",
      "Encryption type (plain / secret) metadata"
    ],
    guidance:
      "ConfigTrace records the names and targets of Vercel environment variables. Values are never read or stored.",
    docsPath: "/docs/vercel.html"
  },
  vercel_domains: {
    provider: "Vercel",
    title: "Vercel Domains",
    monitors: [
      "Custom domain assignments",
      "Redirect and routing config",
      "TLS certificate metadata"
    ],
    guidance:
      "Domain changes can reroute production traffic between projects. ConfigTrace tracks domain assignments.",
    docsPath: "/docs/vercel.html"
  },
  vercel_deploy_hooks: {
    provider: "Vercel",
    title: "Vercel Deploy Hooks / Git",
    monitors: [
      "Deploy hook URLs (presence and target branch)",
      "Production branch setting",
      "Git integration metadata"
    ],
    guidance:
      "Deploy hook and production-branch changes may shift what gets deployed to production. ConfigTrace tracks the configuration.",
    docsPath: "/docs/vercel.html"
  },
  vercel_project_settings: {
    provider: "Vercel",
    title: "Vercel Project Settings",
    monitors: [
      "Build & framework configuration",
      "Deployment protection settings",
      "Team and access settings"
    ],
    guidance:
      "Project-level Vercel settings affect how deployments build and who can access them. ConfigTrace tracks them as metadata.",
    docsPath: "/docs/vercel.html"
  },
  vercel_dashboard: {
    provider: "Vercel",
    title: "Vercel Dashboard",
    monitors: [
      "Environment variables, domains, deploy hooks, project settings"
    ],
    guidance:
      "ConfigTrace monitors Vercel configuration metadata. It never reads build output, logs, or environment variable values.",
    docsPath: "/docs/vercel.html"
  },

  /* ───── Supabase ───── */
  supabase_rls: {
    provider: "Supabase",
    title: "Supabase RLS / Policies",
    monitors: [
      "Row-level security policy definitions",
      "Policy additions and removals",
      "Policy expression changes"
    ],
    guidance:
      "RLS policy removal or weakening could expose table rows beyond intended audiences. ConfigTrace risk-classifies these.",
    docsPath: "/docs/supabase.html"
  },
  supabase_auth: {
    provider: "Supabase",
    title: "Supabase Auth",
    monitors: [
      "Auth provider configuration",
      "JWT settings",
      "Email and password rules metadata"
    ],
    guidance:
      "Auth configuration changes may affect who can log in and how. ConfigTrace tracks the policy and provider settings.",
    docsPath: "/docs/supabase.html"
  },
  supabase_storage: {
    provider: "Supabase",
    title: "Supabase Storage",
    monitors: [
      "Bucket policies",
      "Bucket public / private status",
      "CORS configuration"
    ],
    guidance:
      "Storage bucket policy changes could affect whether stored files are reachable. ConfigTrace tracks the bucket settings.",
    docsPath: "/docs/supabase.html"
  },
  supabase_dashboard: {
    provider: "Supabase",
    title: "Supabase Dashboard",
    monitors: [
      "RLS policies, auth settings, storage policies, API/CORS config"
    ],
    guidance:
      "ConfigTrace monitors Supabase configuration metadata. It never reads database row data, user records, or stored file contents.",
    docsPath: "/docs/supabase.html"
  },

  /* ───── Firebase ───── */
  firebase_firestore_rules: {
    provider: "Firebase",
    title: "Firebase Firestore Rules",
    monitors: [
      "Firestore security rule definitions",
      "Rule changes per collection / path",
      "Public-read or public-write rule additions"
    ],
    guidance:
      "Firestore rule loosening may expose document collections to unintended readers or writers. ConfigTrace tracks every rule change.",
    docsPath: "/docs/firebase.html"
  },
  firebase_storage_rules: {
    provider: "Firebase",
    title: "Firebase Storage Rules",
    monitors: [
      "Storage security rule definitions",
      "Rule changes per bucket / path"
    ],
    guidance:
      "Storage rule changes can affect whether stored files are reachable. ConfigTrace tracks the rule expressions.",
    docsPath: "/docs/firebase.html"
  },
  firebase_auth: {
    provider: "Firebase",
    title: "Firebase Authentication",
    monitors: [
      "OAuth provider configuration",
      "Sign-in method settings",
      "Email template metadata"
    ],
    guidance:
      "Auth configuration changes may affect sign-in flow and provider availability. ConfigTrace tracks the settings.",
    docsPath: "/docs/firebase.html"
  },
  firebase_app_check: {
    provider: "Firebase",
    title: "Firebase App Check",
    monitors: [
      "App Check enforcement state per product",
      "Provider configuration"
    ],
    guidance:
      "App Check disablement may reduce protections against abuse. ConfigTrace tracks the enforcement state.",
    docsPath: "/docs/firebase.html"
  },
  firebase_remote_config: {
    provider: "Firebase",
    title: "Firebase Remote Config",
    monitors: [
      "Remote config parameter keys (metadata only)",
      "Condition and version metadata"
    ],
    guidance:
      "Remote config changes can change runtime behavior. ConfigTrace tracks parameter and condition metadata.",
    docsPath: "/docs/firebase.html"
  },
  firebase_console: {
    provider: "Firebase",
    title: "Firebase Console",
    monitors: [
      "Firestore rules, Storage rules, Auth, App Check, Remote Config metadata"
    ],
    guidance:
      "ConfigTrace monitors Firebase configuration metadata. It never reads Firestore documents, Realtime DB data, or stored file contents.",
    docsPath: "/docs/firebase.html"
  },

  /* ───── Shopify ───── */
  shopify_apps: {
    provider: "Shopify",
    title: "Shopify Apps & Scopes",
    monitors: [
      "Installed app metadata",
      "Granted permission scopes"
    ],
    guidance:
      "App scope changes may widen what installed apps can access. ConfigTrace tracks installed-app metadata.",
    docsPath: null
  },
  shopify_webhooks: {
    provider: "Shopify",
    title: "Shopify Webhooks & Notifications",
    monitors: [
      "Webhook endpoint URLs",
      "Subscribed topic types",
      "Notification settings metadata"
    ],
    guidance:
      "Webhook URL or topic changes can break order and payment pipelines. ConfigTrace tracks the configuration.",
    docsPath: null
  },
  shopify_settings: {
    provider: "Shopify",
    title: "Shopify Store Settings",
    monitors: [
      "Checkout and policy settings metadata",
      "Payment gateway configuration metadata"
    ],
    guidance:
      "Store settings changes may affect checkout and order flows. ConfigTrace tracks the configuration metadata.",
    docsPath: null
  },
  shopify_admin: {
    provider: "Shopify",
    title: "Shopify Admin",
    monitors: [
      "App scopes, webhook subscriptions, store settings"
    ],
    guidance:
      "ConfigTrace monitors Shopify configuration metadata. It never reads order contents, checkout payloads, or customer records.",
    docsPath: null
  }
};

/* ---------------------------------------------------------------------------
 * Provider detection — URL-only, ordered most-specific to least-specific.
 *
 * Each rule: { id, hostTest(host), urlTest(pathname, hash) }.
 * First rule whose hostTest AND urlTest both return true wins.
 * ------------------------------------------------------------------------- */
const CT_PROVIDERS = [
  /* AWS */
  { id: "aws_security_groups",
    hostTest: h => h === "console.aws.amazon.com" || h.endsWith(".console.aws.amazon.com"),
    urlTest:  (p, hash) => /SecurityGroup|security-groups/i.test(p + " " + hash) },
  { id: "aws_iam",
    hostTest: h => h === "console.aws.amazon.com" || h.endsWith(".console.aws.amazon.com"),
    urlTest:  (p, hash) => /\/iam(\/|$|\?)/i.test(p) || /\/iamv2(\/|$|\?)/i.test(p) },
  { id: "aws_route53",
    hostTest: h => h === "console.aws.amazon.com" || h.endsWith(".console.aws.amazon.com"),
    urlTest:  (p, hash) => /\/route53(\/|$)/i.test(p) },
  { id: "aws_s3",
    hostTest: h => h === "console.aws.amazon.com" || h.endsWith(".console.aws.amazon.com"),
    urlTest:  (p, hash) => /\/s3(\/|$)/i.test(p) },
  { id: "aws_console",
    hostTest: h => h === "console.aws.amazon.com" || h.endsWith(".console.aws.amazon.com"),
    urlTest:  ()       => true },

  /* GitHub — only on settings pages, never on code/issues/PRs */
  { id: "github_branch_protection",
    hostTest: h => h === "github.com",
    urlTest:  p => /^\/[^\/]+\/[^\/]+\/settings\/branches/.test(p) ||
                   /^\/[^\/]+\/[^\/]+\/settings\/branch_protection_rules/.test(p) },
  { id: "github_environments",
    hostTest: h => h === "github.com",
    urlTest:  p => /^\/[^\/]+\/[^\/]+\/settings\/environments/.test(p) },
  { id: "github_webhooks",
    hostTest: h => h === "github.com",
    urlTest:  p => /^\/[^\/]+\/[^\/]+\/settings\/hooks/.test(p) },
  { id: "github_secrets",
    hostTest: h => h === "github.com",
    urlTest:  p => /^\/[^\/]+\/[^\/]+\/settings\/(secrets|variables)\/actions/.test(p) },
  { id: "github_settings",
    hostTest: h => h === "github.com",
    urlTest:  p => /^\/[^\/]+\/[^\/]+\/settings(\/|$)/.test(p) ||
                   /^\/organizations\/[^\/]+\/settings/.test(p) },

  /* Stripe */
  { id: "stripe_webhooks",
    hostTest: h => h === "dashboard.stripe.com",
    urlTest:  p => /\/webhooks/i.test(p) },
  { id: "stripe_api_keys",
    hostTest: h => h === "dashboard.stripe.com",
    urlTest:  p => /\/apikeys/i.test(p) || /\/developers\/api-keys/i.test(p) },
  { id: "stripe_settings",
    hostTest: h => h === "dashboard.stripe.com",
    urlTest:  p => /\/settings/i.test(p) },
  { id: "stripe_dashboard",
    hostTest: h => h === "dashboard.stripe.com",
    urlTest:  ()=> true },

  /* Cloudflare */
  { id: "cloudflare_dns",
    hostTest: h => h === "dash.cloudflare.com",
    urlTest:  p => /\/dns(\/|$)/i.test(p) },
  { id: "cloudflare_waf",
    hostTest: h => h === "dash.cloudflare.com",
    urlTest:  p => /\/security\/waf|\/firewall|\/rulesets/i.test(p) },
  { id: "cloudflare_ssl",
    hostTest: h => h === "dash.cloudflare.com",
    urlTest:  p => /\/ssl-tls|\/ssl/i.test(p) },
  { id: "cloudflare_dashboard",
    hostTest: h => h === "dash.cloudflare.com",
    urlTest:  ()=> true },

  /* Vercel — only on dashboard-shaped paths (avoid marketing pages) */
  { id: "vercel_env",
    hostTest: h => h === "vercel.com",
    urlTest:  p => /\/settings\/environment-variables/i.test(p) },
  { id: "vercel_domains",
    hostTest: h => h === "vercel.com",
    urlTest:  p => /\/settings\/domains/i.test(p) },
  { id: "vercel_deploy_hooks",
    hostTest: h => h === "vercel.com",
    urlTest:  p => /\/settings\/(git|deploy-hooks)/i.test(p) },
  { id: "vercel_project_settings",
    hostTest: h => h === "vercel.com",
    urlTest:  p => /\/settings(\/|$)/.test(p) },
  { id: "vercel_dashboard",
    hostTest: h => h === "vercel.com",
    urlTest:  p => /^\/dashboard|^\/[^\/]+\/[^\/]+/.test(p) },

  /* Supabase */
  { id: "supabase_rls",
    hostTest: h => h === "supabase.com",
    urlTest:  p => /^\/dashboard.*\/(database\/(policies|tables)|table-editor|sql)/i.test(p) },
  { id: "supabase_auth",
    hostTest: h => h === "supabase.com",
    urlTest:  p => /^\/dashboard.*\/auth(\/|$)/i.test(p) },
  { id: "supabase_storage",
    hostTest: h => h === "supabase.com",
    urlTest:  p => /^\/dashboard.*\/storage(\/|$)/i.test(p) },
  { id: "supabase_dashboard",
    hostTest: h => h === "supabase.com",
    urlTest:  p => /^\/dashboard/.test(p) },

  /* Firebase */
  { id: "firebase_firestore_rules",
    hostTest: h => h === "console.firebase.google.com",
    urlTest:  p => /\/firestore.*rules/i.test(p) },
  { id: "firebase_storage_rules",
    hostTest: h => h === "console.firebase.google.com",
    urlTest:  p => /\/storage.*rules/i.test(p) },
  { id: "firebase_auth",
    hostTest: h => h === "console.firebase.google.com",
    urlTest:  p => /\/authentication(\/|$)/i.test(p) },
  { id: "firebase_app_check",
    hostTest: h => h === "console.firebase.google.com",
    urlTest:  p => /\/appcheck(\/|$)/i.test(p) },
  { id: "firebase_remote_config",
    hostTest: h => h === "console.firebase.google.com",
    urlTest:  p => /\/config(\/|$)/i.test(p) },
  { id: "firebase_console",
    hostTest: h => h === "console.firebase.google.com",
    urlTest:  ()=> true },

  /* Shopify */
  { id: "shopify_apps",
    hostTest: h => h === "admin.shopify.com",
    urlTest:  p => /\/apps(\/|$)/i.test(p) },
  { id: "shopify_webhooks",
    hostTest: h => h === "admin.shopify.com",
    urlTest:  p => /\/notifications|\/webhooks/i.test(p) },
  { id: "shopify_settings",
    hostTest: h => h === "admin.shopify.com",
    urlTest:  p => /\/settings(\/|$)/i.test(p) },
  { id: "shopify_admin",
    hostTest: h => h === "admin.shopify.com",
    urlTest:  ()=> true }
];

/**
 * Detect the provider context for a given URL.
 *
 * @param {string} urlString  - full URL to inspect (e.g. window.location.href)
 * @returns {{contextKey: string, provider: string, title: string,
 *            monitors: string[], guidance: string, docsPath: string|null} | null}
 *          - guidance object plus contextKey, or null if no provider matched.
 */
function ctDetectProviderContext(urlString) {
  let u;
  try { u = new URL(urlString); } catch { return null; }

  const host = u.hostname || "";
  const path = u.pathname || "";
  const hash = u.hash || "";

  for (const rule of CT_PROVIDERS) {
    try {
      if (rule.hostTest(host) && rule.urlTest(path, hash)) {
        const g = CT_GUIDANCE[rule.id];
        if (!g) continue;
        return Object.assign({ contextKey: rule.id }, g);
      }
    } catch (e) {
      // never throw out of detection
    }
  }
  return null;
}

/* Expose to other extension scripts (popup.js, contentScript.js). */
try {
  // eslint-disable-next-line no-undef
  globalThis.CT_GUIDANCE = CT_GUIDANCE;
  // eslint-disable-next-line no-undef
  globalThis.CT_PROVIDERS = CT_PROVIDERS;
  // eslint-disable-next-line no-undef
  globalThis.CT_LINKS = CT_LINKS;
  // eslint-disable-next-line no-undef
  globalThis.CT_APP_DEFAULT_BASE = CT_APP_DEFAULT_BASE;
  // eslint-disable-next-line no-undef
  globalThis.CT_DOCS_BASE = CT_DOCS_BASE;
  // eslint-disable-next-line no-undef
  globalThis.ctDetectProviderContext = ctDetectProviderContext;
} catch (_e) { /* sandbox without globalThis — ignore */ }
