/**
 * Provider Trust Center catalog — M58.12.
 *
 * Static, read-only profiles for all 8 supported providers.
 * Each profile describes exactly what ConfigTrace reads, what it never reads,
 * how credentials are stored, what permissions are required, and how to revoke
 * access.
 *
 * Design rules:
 *   - No raw credential values, secret values, webhook URLs, or API key values.
 *   - No compliance claims (SOC2 etc.) unless actually certified.
 *   - Language: describe what we do, not what we prevent.
 */

import type { ProviderId } from "@/lib/providers";

// ── Type definitions ──────────────────────────────────────────────────────────

export interface ProviderTrustProfile {
  id: ProviderId;
  /** Configuration surfaces and metadata ConfigTrace reads. */
  reads: string[];
  /** Data ConfigTrace explicitly never accesses. */
  never_reads: string[];
  /** Human-readable note on how credentials are stored (no raw values). */
  credential_note: string;
  /** OAuth scopes, IAM policies, or API token permissions requested. */
  permissions: string[];
  /** Step-by-step instructions for revoking ConfigTrace's access. */
  revoke_steps: string[];
  /** Whether ConfigTrace can surface remediation recommendations for this provider. */
  remediation_supported: boolean;
}

// ── Per-provider profiles ─────────────────────────────────────────────────────

export const TRUST_PROFILES: Record<ProviderId, ProviderTrustProfile> = {
  aws: {
    id: "aws",
    reads: [
      "IAM users, roles, policies, and access key metadata",
      "S3 bucket policies, ACLs, and public-access block settings",
      "Security group rules and VPC configuration",
      "Lambda function metadata (name, runtime, timeout — not source code)",
      "API Gateway, ECS, and EKS configuration",
      "CloudTrail trail status and S3 delivery config",
      "GuardDuty detector status",
      "Security Hub enabled standards and control statuses",
      "RDS instance metadata and parameter groups",
      "KMS key metadata and rotation status",
      "Secrets Manager secret metadata (names and rotation config — not values)",
      "CloudFront distribution settings",
      "WAF web ACLs and rule groups",
      "Route 53 hosted zones and DNS records",
    ],
    never_reads: [
      "S3 object contents or bucket data",
      "Database row data (RDS, DynamoDB, or any database engine)",
      "Lambda function source code or deployment packages",
      "Secret values from Secrets Manager or Parameter Store",
      "CloudWatch log event contents or metric data",
      "Application data of any kind",
      "EC2 instance disk contents",
    ],
    credential_note:
      "An IAM access key pair (or cross-account read-only role) is stored encrypted at rest using your workspace's encryption key. Keys are never returned in API responses, logs, or exports.",
    permissions: [
      "iam:Get*, iam:List* (no iam:CreateUser or write APIs)",
      "s3:GetBucketAcl, s3:GetBucketPolicy, s3:GetBucketPublicAccessBlock, s3:ListAllMyBuckets",
      "ec2:DescribeSecurityGroups, ec2:DescribeVpcs, ec2:DescribeSubnets",
      "cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus",
      "guardduty:GetDetector, guardduty:ListDetectors",
      "securityhub:GetEnabledStandards, securityhub:DescribeStandardsControls",
      "lambda:GetFunction (config only), lambda:ListFunctions",
      "rds:DescribeDBInstances, rds:DescribeDBParameterGroups",
      "kms:ListKeys, kms:DescribeKey, kms:GetKeyRotationStatus",
      "secretsmanager:ListSecrets (metadata only — no GetSecretValue)",
    ],
    revoke_steps: [
      "Sign in to the AWS Management Console",
      "Navigate to IAM → Users (or Roles for cross-account access)",
      "Find the ConfigTrace user or role",
      "Delete the access key or remove the trust relationship",
    ],
    remediation_supported: true,
  },

  github: {
    id: "github",
    reads: [
      "Repository settings: visibility, default branch, fork and squash merge settings",
      "Branch protection rules (required reviewers, status checks, force-push restrictions)",
      "Environment protection rules (required reviewers, branch deployment policies)",
      "Webhook endpoints (URL domain, events, active status, HTTPS enforcement)",
      "Actions secrets and variables (names and last-updated timestamps — never values)",
      "Deploy keys (fingerprint and read/write flag — never private key content)",
    ],
    never_reads: [
      "Source code, file contents, or repository data",
      "Commit messages or diff contents",
      "Pull request bodies, issue text, or discussion contents",
      "Actions secret values or variable values",
      "Deploy key private key material",
      "Private repository contents beyond settings metadata",
    ],
    credential_note:
      "A fine-grained Personal Access Token (PAT) scoped to repository configuration metadata is stored encrypted at rest. The token grants no code-read access.",
    permissions: [
      "Administration: read (repository settings, branch protection)",
      "Environments: read (environment protection rules)",
      "Secrets: read (names and metadata — not values)",
      "Webhooks: read",
      "Deployments: read (deploy keys)",
    ],
    revoke_steps: [
      "Sign in to GitHub",
      "Go to Settings → Developer settings → Personal access tokens → Fine-grained tokens",
      "Find the ConfigTrace token",
      "Click Delete",
    ],
    remediation_supported: true,
  },

  vercel: {
    id: "vercel",
    reads: [
      "Project settings: framework preset, build command, install command, Node.js version",
      "Environment variable keys (names and target environment — never values)",
      "Custom domain configuration and SSL status",
      "Git branch and repository linkage",
      "Deploy hook metadata: URL host/domain (URL path is never stored)",
    ],
    never_reads: [
      "Environment variable values",
      "Deployment logs or build output",
      "Function source code or build artifacts",
      "Preview deployment content",
      "Application data returned by deployments",
    ],
    credential_note:
      "A Vercel API token with read-only project scope is stored encrypted at rest. The token has no access to deployment logs or environment variable values.",
    permissions: [
      "Read project settings and configuration",
      "Read environment variable keys (not values)",
      "Read custom domain configuration",
      "Read deploy hook metadata (no trigger access)",
    ],
    revoke_steps: [
      "Sign in to Vercel",
      "Go to Account Settings → Tokens",
      "Find the ConfigTrace token",
      "Delete the token",
    ],
    remediation_supported: true,
  },

  stripe: {
    id: "stripe",
    reads: [
      "Account settings: charges/payouts enabled, payout schedule, statement descriptor",
      "Webhook endpoints: URL, enabled events, HTTPS enforcement, active status",
      "Payment method configurations and enabled payment types",
      "Payment method domain allowlist",
      "Customer portal (billing portal) configuration settings",
    ],
    never_reads: [
      "Card numbers, CVVs, or bank account details",
      "Customer PII (names, email addresses, phone numbers)",
      "Transaction history or payment records",
      "Subscription or invoice line items",
      "Stripe secret API keys or restricted key values",
    ],
    credential_note:
      "A restricted Stripe API key with read-only account and webhook scopes is stored encrypted at rest. The key has no access to customer data, payment methods, or charges.",
    permissions: [
      "Account settings: read",
      "Webhook endpoints: read",
      "Payment method configurations: read",
      "Billing portal configurations: read",
    ],
    revoke_steps: [
      "Sign in to the Stripe Dashboard",
      "Go to Developers → API keys",
      "Find the ConfigTrace restricted key",
      "Delete the key",
    ],
    remediation_supported: true,
  },

  firebase: {
    id: "firebase",
    reads: [
      "Project metadata: region, display name, status",
      "Authentication configuration: enabled sign-in providers, authorized domains, MFA settings",
      "Firestore security ruleset metadata (rule hash — not document data)",
      "Cloud Storage bucket names and security ruleset metadata",
      "Firebase Hosting site and custom domain configuration",
      "Cloud Functions metadata: function names and regions (no source code)",
    ],
    never_reads: [
      "Firestore document data or collection contents",
      "Firebase Auth user records, email addresses, or credentials",
      "Cloud Storage file contents",
      "Cloud Functions source code or deployment packages",
      "Firebase Remote Config parameter values",
      "Secret values from Secret Manager",
    ],
    credential_note:
      "A Firebase Admin SDK service account with the Firebase Viewer IAM role is stored encrypted at rest. The service account is granted read-only metadata access only.",
    permissions: [
      "roles/firebase.viewer (Firebase Viewer — metadata only)",
      "roles/cloudfunctions.viewer (function list and metadata)",
      "No roles/datastore.user or storage.objectViewer (data access blocked)",
    ],
    revoke_steps: [
      "Sign in to Google Cloud Console",
      "Navigate to IAM & Admin → Service Accounts",
      "Find the ConfigTrace service account",
      "Delete the service account or remove and rotate its keys",
    ],
    remediation_supported: true,
  },

  supabase: {
    id: "supabase",
    reads: [
      "Project metadata: region, status, plan tier",
      "Auth configuration: enabled sign-in methods, MFA settings, session timeout",
      "Database pooler configuration (mode and port settings)",
      "Storage configuration",
      "Edge Function metadata: function names (no source code)",
      "Row Level Security (RLS) enabled/enforced status per table",
      "Network restriction rules and custom domain settings",
      "OAuth provider configuration (provider name and enabled status)",
    ],
    never_reads: [
      "Database rows or table data",
      "Auth user records, email addresses, or PII",
      "Edge Function source code",
      "Secret values, service role keys, or anon keys",
      "Storage file contents",
      "Session tokens or JWT secrets",
    ],
    credential_note:
      "A Supabase Management API token with read-only project configuration access is stored encrypted at rest. The token has no access to database data or user records.",
    permissions: [
      "Management API: projects.read",
      "Management API: auth.config.read",
      "Management API: functions.list (names only)",
      "Management API: database.settings.read (no data access)",
    ],
    revoke_steps: [
      "Sign in to Supabase Dashboard",
      "Go to Account → Access tokens",
      "Find the ConfigTrace token",
      "Click Revoke",
    ],
    remediation_supported: true,
  },

  cloudflare: {
    id: "cloudflare",
    reads: [
      "DNS records: A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, and other record types",
      "Zone settings: SSL/TLS mode, HTTPS redirect, security level, caching behavior",
      "WAF rule groups and custom ruleset configuration",
      "SSL/TLS certificate configuration and edge certificates",
      "Page rules (URL patterns and associated settings)",
    ],
    never_reads: [
      "Traffic content, request bodies, or response data",
      "Web Analytics visitor metrics or raw request logs",
      "Cloudflare Workers source code",
      "Origin server application data",
      "Cloudflare Access user sessions or identity provider config",
    ],
    credential_note:
      "A Cloudflare API token scoped to Zone:Read, DNS:Read, and Firewall:Read permissions is stored encrypted at rest. The token has no write permissions of any kind.",
    permissions: [
      "Zone: Read",
      "DNS: Read",
      "Firewall Services: Read",
      "SSL and Certificates: Read",
      "Cache Purge: denied",
    ],
    revoke_steps: [
      "Sign in to Cloudflare Dashboard",
      "Go to My Profile → API Tokens",
      "Find the ConfigTrace token",
      "Delete the token",
    ],
    remediation_supported: true,
  },

  shopify: {
    id: "shopify",
    reads: [
      "Store metadata: plan name, timezone, currency, locale settings",
      "Storefront access settings: password protection status",
      "Webhook subscriptions: endpoint host/domain, topic, HTTPS status",
      "Store policies: presence and content hash (raw policy text is never stored)",
      "App permission scopes: scope names only (no store data)",
    ],
    never_reads: [
      "Customer orders, line items, or payment information",
      "Customer PII (names, email addresses, shipping addresses)",
      "Transaction history or financial records",
      "Inventory quantities or product variant data",
      "Theme files, storefront code, or template content",
      "Shopify admin API secret keys or access token values",
    ],
    credential_note:
      "A Shopify custom app with read-only configuration scopes is stored encrypted at rest. No customer data scopes are requested, and access is limited to store configuration metadata.",
    permissions: [
      "read_settings (store configuration only)",
      "read_content (policy metadata and presence — no theme data)",
      "read_webhooks",
      "No read_customers, read_orders, or read_products",
    ],
    revoke_steps: [
      "Sign in to Shopify Admin",
      "Go to Settings → Apps and sales channels → Develop apps",
      "Find the ConfigTrace app",
      "Click Delete app",
    ],
    remediation_supported: true,
  },
};

// ── Global trust summary constants ────────────────────────────────────────────

export const TRUST_SUMMARY = {
  provider_count: 8,
  access_type: "Read-only",
  secret_values_stored: 0,
  customer_data_accessed: false,
} as const;

// ── Permission boundary rows ───────────────────────────────────────────────────

export interface BoundaryRow {
  action: string;
  permitted: boolean;
  note: string;
}

export const PERMISSION_BOUNDARY: BoundaryRow[] = [
  {
    action:    "Read configuration metadata",
    permitted: true,
    note:      "Snapshots provider settings on a schedule",
  },
  {
    action:    "Read customer or user data",
    permitted: false,
    note:      "No customer records, PII, or application data",
  },
  {
    action:    "Read secret or credential values",
    permitted: false,
    note:      "Secret names and metadata only — never the values",
  },
  {
    action:    "Write to any provider",
    permitted: false,
    note:      "API tokens and keys are read-only scoped",
  },
  {
    action:    "Execute commands or trigger deployments",
    permitted: false,
    note:      "No webhooks triggered, no actions triggered",
  },
  {
    action:    "Store plaintext credentials",
    permitted: false,
    note:      "Credentials are encrypted at rest; never returned in API responses",
  },
];
