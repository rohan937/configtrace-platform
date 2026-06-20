/**
 * Provider Trust Center catalog — M58.12.
 *
 * Static, read-only profiles for connectable providers (the 8 canonical
 * dual-stack-complete set). Each profile describes exactly what ConfigTrace
 * reads, what it never reads, how credentials are stored, what permissions
 * are required, and how to revoke access.
 *
 * M82-pre note: security-preview providers (azure, google_cloud, twilio,
 * sendgrid, auth0) intentionally have no trust profile here because they
 * have no credential connect form yet. The consumer renders nothing for
 * providers without a profile (Partial<Record<...>> below).
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

export const TRUST_PROFILES: Partial<Record<ProviderId, ProviderTrustProfile>> = {
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

  // ── M82A — Datadog trust profile ───────────────────────────────────────────
  datadog: {
    id: "datadog",
    reads: [
      "Monitor metadata: type, status, priority category, query/message presence and length categories",
      "SLO metadata: type, target categories, timeframe/monitor/group counts",
      "Dashboard metadata: layout type, widget count, template variable count",
      "Webhook integration metadata: presence booleans only (URL, headers, and payload never read)",
      "Notification integration metadata: type and handle/channel counts",
      "API key metadata: name, created/modified presence, last4_present boolean",
      "Application key metadata: name, scope count",
      "Role metadata: name, permission/user/team counts",
      "Team metadata: name, member count, handle_present boolean",
      "Cloud integration metadata: cloud provider type, collection enabled flags",
    ],
    never_reads: [
      "API key values or application key values",
      "Monitor query strings or raw monitor message text",
      "Dashboard JSON or widget query strings",
      "Webhook URLs, custom headers, payload templates, or signing secrets",
      "Notification handles (Slack channels, PagerDuty service IDs, OpsGenie keys)",
      "Team handles or member identities (names, emails, or IDs)",
      "AWS account IDs, GCP project IDs, or Azure tenant/subscription IDs",
      "Log data, trace payloads, or metric values",
      "Incident content or notebook content",
      "OAuth tokens, bearer tokens, or SAML assertions",
      "Customer data or PII of any kind",
    ],
    credential_note:
      "Datadog API key and Application key are stored encrypted at rest using AES-256-GCM. They are never returned in API responses, never logged, and never copied to resource metadata. Only the Datadog site (region) is stored in plain text as a safe non-secret identifier.",
    permissions: [
      "monitors_read (monitor list and metadata)",
      "dashboards_read (dashboard list and metadata)",
      "api_keys_read (API key metadata — never values)",
      "roles_read (role list and permission counts)",
      "teams_read (team list and member counts)",
      "No write permissions of any kind",
      "No logs_read, metrics_read, traces_read, or incident data access",
    ],
    revoke_steps: [
      "Sign in to your Datadog account",
      "Go to Organization Settings → API Keys",
      "Find and delete the ConfigTrace API key",
      "Go to Organization Settings → Application Keys",
      "Find and delete the ConfigTrace Application key",
    ],
    remediation_supported: false,
  },

  // ── M83A — Clerk trust profile ───────────────────────────────────────────────
  clerk: {
    id: "clerk",
    reads: [
      "Instance settings: environment type, sign-up/sign-in enabled flags, MFA posture, session lifetime category, restriction posture (allowlist/blocklist enabled, sign-in mode)",
      "Domain metadata: verified, primary, SSL enabled, DNS status category — never raw domain name strings",
      "Redirect URL metadata: scheme category (https/http/custom), wildcard presence, localhost presence — never raw URL strings",
      "JWT template metadata: name, claims count, audience presence, lifetime category, algorithm — never template body or claims content",
      "Webhook endpoint metadata: enabled, URL scheme category, event count, secret presence — never webhook URL, signing secret, or event names",
      "Authentication strategy: enabled sign-in methods, social provider count, MFA settings — never provider secrets or certificates",
      "Organization settings: organizations enabled, membership category, admin deletion, verified domains settings",
      "Session policy: session and inactivity lifetime categories, single-session mode",
    ],
    never_reads: [
      "Clerk secret key values or publishable key values",
      "Session tokens, JWTs, OAuth tokens, or bearer tokens of any kind",
      "Webhook secrets or signing keys",
      "Raw redirect URLs, callback URLs, or allowed origins",
      "JWT template body, custom claim values, audience URIs, or issuer strings",
      "User emails, user IDs, phone numbers, names, or profile data",
      "Organization member identities, invitation lists, or member emails",
      "Session history, login history, authentication events",
      "Password data, MFA secrets, backup codes, or verification codes",
      "IP addresses, device fingerprints, or user agents",
      "Raw Clerk API response payloads",
      "Customer data or PII of any kind",
    ],
    credential_note:
      "Clerk secret key is stored encrypted at rest using AES-256-GCM. It is never returned in API responses, never logged, and never copied to resource metadata. No secret key values, publishable key values, or session tokens are ever stored in plaintext.",
    permissions: [
      "Read instance configuration settings (/v1/instance)",
      "Read domain list and posture metadata (/v1/domains)",
      "Read redirect URL list and posture metadata (/v1/redirect_urls)",
      "Read JWT template list and posture metadata (/v1/jwt_templates)",
      "Read webhook endpoint list and posture metadata (/v1/webhooks/svix)",
      "No read_users, read_sessions, read_audit_logs, or write permissions",
      "No access to user data, session data, or authentication events",
    ],
    revoke_steps: [
      "Sign in to your Clerk Dashboard",
      "Go to Configure → API Keys",
      "Find the ConfigTrace secret key",
      "Click the delete/revoke button to invalidate it immediately",
    ],
    remediation_supported: false,
  },

  // ── M84A — PagerDuty trust profile ────────────────────────────────────────
  pagerduty: {
    id: "pagerduty",
    reads: [
      "Service metadata: name, status category, escalation policy reference, timeout categories, team/integration counts — never integration keys or incident data",
      "Escalation policy metadata: name, rule/level structure, loop settings — never user targets, emails, or phone numbers",
      "Schedule metadata: name, layer/user/team counts — never user identities, emails, or on-call assignments",
      "Service integration metadata: type category, vendor name, key presence boolean — never integration key or routing key values",
      "Webhook subscription metadata: active status, event count, URL scheme category — never delivery URL or webhook secret",
      "Event orchestration metadata: name, route count, team presence — never routing expressions or conditions",
      "Business service metadata: name, team/contact presence — never subscriber lists or contact details",
      "Response play metadata: name, responder/subscriber counts, runnability — never responder identities or conference numbers",
    ],
    never_reads: [
      "PagerDuty API token values",
      "Integration keys or routing keys of any kind",
      "Webhook delivery URLs or webhook secrets",
      "User emails, user names, phone numbers, or SMS numbers",
      "Contact methods, notification rules with personal details, or push tokens",
      "On-call user identities or schedule assignments",
      "Responder identities, subscriber identities, or conference phone numbers",
      "Incident payloads, alert payloads, or incident content",
      "Raw routing expressions, condition logic, or action details",
      "Authorization headers or raw API responses",
      "IP addresses, user agents, or audit logs",
      "Customer data or PII of any kind",
    ],
    credential_note:
      "PagerDuty API token is stored encrypted at rest using AES-256-GCM. It is never returned in API responses, never logged, and never copied to resource metadata. No token values, routing keys, or integration keys are ever stored in plaintext.",
    permissions: [
      "Read services list and configuration metadata (/services)",
      "Read escalation policies (/escalation_policies)",
      "Read schedules (/schedules)",
      "Read service integrations per service (/services/{id}/integrations)",
      "Read webhook subscriptions (/webhook_subscriptions)",
      "Read event orchestrations (/event_orchestrations)",
      "Read business services (/business_services)",
      "Read response plays (/response_plays)",
      "No write permissions of any kind",
      "No access to incidents, alerts, logs, or user data",
    ],
    revoke_steps: [
      "Sign in to your PagerDuty account",
      "Go to My Profile → User Settings → API Access Keys (or use the REST API endpoint)",
      "Find the ConfigTrace API token",
      "Delete or revoke the token to invalidate it immediately",
    ],
    remediation_supported: false,
  },

  // ── M85A — Linear trust profile ───────────────────────────────────────────
  linear: {
    id: "linear",
    reads: [
      "Workspace configuration: name, URL key presence — never member emails or PII",
      "Team metadata: name, visibility, member count category, project count, cycle settings — never member identities or user details",
      "Project metadata: name, status, health, lead presence, issue count category — never issue content or assignees",
      "Workflow state metadata: name, type, position category — never issue assignments or issue data",
      "Issue label metadata: name, type, group structure — never label assignments or issue content",
      "Webhook subscription metadata: enabled status, resource types, URL scheme category, secret presence boolean — never delivery URL or secret value",
      "Custom view metadata: name, shared status, filter count category — never filter content or view results",
      "Active cycle metadata: name, duration, issue count category — never issue content or member assignments",
      "Integration metadata: type, enabled status — never credentials, API keys, or integration secrets",
    ],
    never_reads: [
      "Linear API key values or OAuth tokens",
      "Webhook delivery URLs or webhook secrets",
      "Issue titles, descriptions, or body content",
      "Comments, attachments, or issue activity",
      "User emails, user names, or phone numbers",
      "Member identities, invitation lists, or member emails",
      "Issue assignments, due dates, or priority content",
      "Filter content or custom view query logic",
      "Raw routing expressions or condition logic",
      "Authorization headers or raw API response payloads",
      "Audit logs, activity feeds, or notification history",
      "Customer data or PII of any kind",
    ],
    credential_note:
      "Linear API key is stored encrypted at rest using AES-256-GCM. It is never returned in API responses, never logged, and never copied to resource metadata.",
    permissions: [
      "Linear GraphQL API: organization (workspace metadata)",
      "Linear GraphQL API: teams (configuration metadata)",
      "Linear GraphQL API: projects (status and metadata only)",
      "Linear GraphQL API: workflowStates (type and position metadata)",
      "Linear GraphQL API: issueLabels (label structure metadata)",
      "Linear GraphQL API: webhooks (configuration metadata — not payloads)",
      "Linear GraphQL API: customViews (shared status and filter count)",
      "Linear GraphQL API: cycles (active cycles metadata)",
      "Linear GraphQL API: integrations (type and enabled status)",
    ],
    revoke_steps: [
      "Sign in to Linear",
      "Go to Settings → API (or click your profile picture → API keys)",
      "Find the API key created for ConfigTrace",
      "Delete or revoke it",
    ],
    remediation_supported: false,
  },

  // ── M86A — Jira trust profile ─────────────────────────────────────────────
  jira: {
    id: "jira",
    reads: [
      "Project metadata: key presence, type, lead presence, category — never issue keys, issue content, or assignees",
      "Board metadata: type, project association — never issue content or sprint data",
      "Workflow metadata: status structure, transition count category — never issue assignments",
      "Workflow scheme metadata: project mapping structure — never issue content",
      "Permission scheme metadata: grant count category, holder type structure — never account IDs or user identities",
      "Notification scheme metadata: event count category, recipient type structure — never emails or identities",
      "Webhook subscription metadata: enabled status, event types, URL scheme category — never delivery URL or secret value",
      "Automation rule metadata: enabled status, trigger type, action count category — never rule content or conditions",
      "Integration / app metadata: type, enabled status — never credentials, API tokens, or secrets",
    ],
    never_reads: [
      "Jira API token values or OAuth tokens",
      "Webhook delivery URLs or webhook secrets",
      "Issue keys, issue titles, descriptions, or body content",
      "Comments, attachments, or issue activity",
      "User emails, user names, account IDs, or phone numbers",
      "Member identities, assignees, reporters, or watcher lists",
      "Automation rule logic, conditions, or action details",
      "Authorization headers or raw API response payloads",
      "Audit logs, activity feeds, or notification history",
      "Customer data or PII of any kind",
    ],
    credential_note:
      "Jira configuration monitoring at foundation stage (M86A). Snapshot-only — no issue titles, descriptions, comments, account IDs, or customer data stored. The Jira API token is stored encrypted at rest using AES-256-GCM. It is never returned in API responses, never logged, and never copied to resource metadata.",
    permissions: [
      "Jira REST API: projects (configuration metadata only)",
      "Jira REST API: boards (type and project association)",
      "Jira REST API: workflows (status and transition structure)",
      "Jira REST API: workflow schemes (mapping structure)",
      "Jira REST API: permission schemes (grant structure metadata)",
      "Jira REST API: notification schemes (recipient structure metadata)",
      "Jira REST API: webhooks (configuration metadata — not payloads)",
      "Jira REST API: automation rules (enabled status and structure)",
      "Jira REST API: installed apps (type and enabled status)",
      "No write permissions of any kind",
    ],
    revoke_steps: [
      "Sign in to your Atlassian account",
      "Go to id.atlassian.com → Security → API tokens",
      "Find the API token created for ConfigTrace",
      "Delete or revoke it to invalidate it immediately",
    ],
    remediation_supported: false,
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
