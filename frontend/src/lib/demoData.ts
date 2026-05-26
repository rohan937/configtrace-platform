/**
 * Synthetic demo data — M58.13 Public Demo Risk Timeline.
 *
 * All data is entirely fictional. No real workspace, customer, provider,
 * integration, or credential IDs are used.  Fake resource names use the
 * "Acme" placeholder company only.
 *
 * Safety rules:
 *   - No real customer/company names (only "Acme" placeholder).
 *   - No real provider IDs, API keys, secrets, or webhook URLs.
 *   - prev_value/new_value are never included — guidance is metadata-based only.
 *   - Language: "may", "potentially", "appears" — never "confirmed", "breach",
 *     "publicly reachable", "customers impacted", or "auto-fixed".
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export interface DemoChange {
  id: string;
  provider: string;
  risk_level: "critical" | "high" | "medium" | "low";
  change_type: "added" | "removed" | "modified";
  title: string;
  /** One-sentence description for the timeline row. */
  description: string;
  /** Human-readable fake relative timestamp. */
  timestamp_label: string;
  resource_name: string;
  category: string;

  // ── Detail panel ────────────────────────────────────────────────────────────

  /** What changed (metadata-only; no raw values). */
  what_changed: string;
  /** Why this matters for production posture. */
  why_it_matters: string;
  /** Bullet list of things to verify. */
  what_to_check: string[];
  /** One-sentence remediation guidance. */
  remediation_summary: string;
  /** Step-by-step remediation. */
  remediation_steps: string[];
  /** Fix plan summary. */
  fix_plan_summary: string;
  /** Dry-run preview summary. */
  dry_run_summary: string;
  /** Blast radius summary. */
  blast_radius_summary: string;
  /** Example Ask ConfigTrace Q&A. */
  ask_configtrace: {
    question: string;
    answer: string;
    bullets: string[];
  };

  /** Optional: reference to a demo cluster ID. */
  cluster_id?: string;
}

export interface DemoCluster {
  id: string;
  title: string;
  description: string;
  change_ids: string[];
  providers: string[];
  /** Human-readable timespan, e.g. "12 minutes". */
  timespan_label: string;
}

// ── Demo changes ──────────────────────────────────────────────────────────────

export const DEMO_CHANGES: DemoChange[] = [
  // ── 1. AWS security group ──────────────────────────────────────────────────
  {
    id: "demo-aws-sg-001",
    provider: "aws",
    risk_level: "critical",
    change_type: "modified",
    title: "AWS security group may expose SSH to the internet",
    description:
      "An inbound rule was modified on a production security group. tcp/22 is now listed with a broad IP range.",
    timestamp_label: "47 min ago",
    resource_name: "sg-demo-prod-web",
    category: "Network",

    what_changed:
      "An inbound security group rule was modified. A rule allowing tcp/22 traffic from a broad CIDR was added or changed on sg-demo-prod-web.",
    why_it_matters:
      "Direct SSH access from a wide CIDR significantly expands the attack surface on any instances associated with this security group. If the change was unintended, external hosts may be able to attempt connections.",
    what_to_check: [
      "Verify whether tcp/22 access is intentional for this security group",
      "Check whether SSM Session Manager can replace direct SSH access",
      "Review AWS CloudTrail for the IAM principal that made this change",
      "Confirm no other overly broad inbound rules were added at the same time",
      "List all EC2 instances that reference sg-demo-prod-web",
    ],
    remediation_summary:
      "Replace the broad CIDR on the tcp/22 rule with your VPN IP range, or remove the rule and use SSM Session Manager for instance access.",
    remediation_steps: [
      "Open AWS Console → EC2 → Security Groups",
      "Find sg-demo-prod-web and open Inbound rules",
      "Remove or restrict the tcp/22 rule to the VPN CIDR (e.g. 10.0.0.0/8)",
      "Enable SSM Session Manager on affected instances to eliminate direct SSH dependency",
      "Verify no other instances share this security group unexpectedly",
    ],
    fix_plan_summary:
      "Remove or scope the tcp/22 inbound rule. Verify SSM is configured as the preferred access method before removing SSH access.",
    dry_run_summary:
      "Removing the rule would leave port 22 inaccessible from the broad CIDR. Verify SSM agent is running and IAM permissions allow SSM access before applying.",
    blast_radius_summary:
      "May affect all instances associated with sg-demo-prod-web. Direct SSH connectivity would be impacted by remediation — confirm SSM availability first.",
    ask_configtrace: {
      question: "What should I check first?",
      answer:
        "Start by reviewing AWS CloudTrail for the IAM principal that modified the security group. Check whether this aligns with a scheduled maintenance window or deployment runbook. If no justification is found, treat as unintended until confirmed.",
      bullets: [
        "Review CloudTrail: filter by resource sg-demo-prod-web in the past 2 hours",
        "Identify the IAM user or role that made the change",
        "Check whether a ticket or runbook covers this change",
        "If no justification exists, restrict the rule while investigating",
      ],
    },
  },

  // ── 2. Firebase Firestore rules ────────────────────────────────────────────
  {
    id: "demo-firebase-rules-001",
    provider: "firebase",
    risk_level: "critical",
    change_type: "modified",
    title: "Firebase Firestore rules may allow public writes",
    description:
      "Firestore security ruleset metadata changed. Rule conditions appear to have been broadened to allow write access without authentication checks.",
    timestamp_label: "2h ago",
    resource_name: "acme-prod-firebase",
    category: "Auth",

    what_changed:
      "The Firestore security ruleset hash changed on the acme-prod-firebase project. Ruleset metadata indicates write conditions were broadened beyond authenticated access.",
    why_it_matters:
      "If Firestore rules allow writes without authentication or authorization checks, any external request may be able to modify documents in the affected collections. Production data integrity and consistency may be at risk.",
    what_to_check: [
      "Open Firebase Console → Firestore → Rules and review all allow write: conditions",
      "Use the Rules Playground to simulate an unauthenticated write attempt",
      "Confirm all write rules require at minimum request.auth != null",
      "Review who published the ruleset and whether it matches a planned release",
      "Check Firestore usage logs for unexpected write traffic since the change",
    ],
    remediation_summary:
      "Update Firestore rules to require authentication and authorization checks for all write operations.",
    remediation_steps: [
      "Open Firebase Console → Firestore → Rules",
      "Review all allow write: conditions for missing auth checks",
      "Add: allow write: if request.auth != null; as a minimum guard",
      "For user-scoped data: allow write: if request.auth.uid == resource.data.userId;",
      "Publish the updated ruleset and verify in the Firebase Rules Playground",
    ],
    fix_plan_summary:
      "Add authentication and authorization checks to all Firestore write rules. Test in the Firebase Rules Playground before deploying.",
    dry_run_summary:
      "Adding auth checks would block unauthenticated write requests. Verify that all client-side write calls include an authenticated Firebase user before applying.",
    blast_radius_summary:
      "May affect all Firestore collections if the ruleset change is at the root level. All write-capable client paths may be affected until the rule is corrected.",
    ask_configtrace: {
      question: "Could this be expected?",
      answer:
        "This could be expected only if a deployment explicitly loosened rules as part of a migration or testing step. However, broad write rules in production are rarely intentional and should always be reviewed.",
      bullets: [
        "Could be expected if: a developer is migrating data and temporarily loosened rules",
        "Needs review if: no migration is in progress, or the change was not in a deployment runbook",
        "Check whether the ruleset version aligns with a recent CI/CD deployment",
        "If in doubt: apply restrictive rules immediately and investigate in parallel",
      ],
    },
  },

  // ── 3. Supabase RLS ────────────────────────────────────────────────────────
  {
    id: "demo-supabase-rls-001",
    provider: "supabase",
    risk_level: "critical",
    change_type: "modified",
    title: "Supabase RLS disabled on a table in customer-facing project",
    description:
      "Row Level Security was disabled for a table in the production Supabase project. Without RLS, all authenticated requests can access all rows.",
    timestamp_label: "3h ago",
    resource_name: "acme-prod-supabase",
    category: "Auth",

    what_changed:
      "RLS enabled flag changed from true to false on a table in the acme-prod-supabase project. The table appears to be in an application-facing schema.",
    why_it_matters:
      "With RLS disabled, any user with a valid Supabase anon key or authenticated token can read and write all rows in the table, regardless of which user owns the data. This bypasses per-user data isolation.",
    what_to_check: [
      "Identify which table had RLS disabled in Supabase Dashboard → Table Editor",
      "Determine whether the table contains user-scoped or multi-tenant data",
      "Check Supabase logs for unexpected cross-user data access since the change",
      "Confirm whether RLS was disabled intentionally (e.g. for a migration step)",
      "Verify that appropriate RLS policies exist before re-enabling",
    ],
    remediation_summary:
      "Re-enable RLS on the affected table. Confirm that appropriate policies exist before re-enabling to avoid locking out legitimate queries.",
    remediation_steps: [
      "Open Supabase Dashboard → Table Editor",
      "Navigate to Authentication → Policies to review existing RLS policies",
      "If policies exist: ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;",
      "If no policies exist: create appropriate policies first, then enable RLS",
      "Test with a non-admin Supabase key to confirm rows are properly scoped",
    ],
    fix_plan_summary:
      "Re-enable RLS. Confirm policies exist that scope data to authenticated users before applying the change.",
    dry_run_summary:
      "Re-enabling RLS without policies in place would cause queries to return zero rows for non-admin users. Confirm all necessary policies are present before applying.",
    blast_radius_summary:
      "May affect all requests to the affected table. Client-side queries may return different results after RLS is re-enabled if policies are missing or incomplete.",
    ask_configtrace: {
      question: "What is the blast radius?",
      answer:
        "The blast radius depends on how many application features read from or write to this table. If the table is shared across user accounts, all records may be visible to any authenticated user until RLS is restored.",
      bullets: [
        "All API requests that query this table are potentially affected",
        "If the table contains multi-tenant data, any tenant may access any other tenant's rows",
        "Remediation (re-enabling RLS) may break queries that rely on unrestricted access",
        "Blast radius is inferred from configuration metadata — review the table schema and usage before acting",
      ],
    },
  },

  // ── 4. Stripe webhook (cluster) ───────────────────────────────────────────
  {
    id: "demo-stripe-webhook-001",
    provider: "stripe",
    risk_level: "high",
    change_type: "modified",
    title: "Stripe webhook endpoint changed on payments-webhook",
    description:
      "A webhook endpoint was modified. The destination domain changed for payment and subscription event notifications.",
    timestamp_label: "12h ago",
    resource_name: "payments-webhook",
    category: "Webhooks",
    cluster_id: "demo-cluster-checkout",

    what_changed:
      "The Stripe webhook endpoint URL was modified on the payments-webhook endpoint. The destination domain was changed. Enabled events include payment and subscription topics.",
    why_it_matters:
      "If the change was unintended, payment event notifications may be delivered to an unexpected destination. This could cause missed subscription updates, failed payment confirmations, or notification routing to an untrusted host.",
    what_to_check: [
      "Open Stripe Dashboard → Developers → Webhooks and confirm the current endpoint domain",
      "Verify the current URL is owned and operated by your team",
      "Check Webhook attempts for delivery failures since the change",
      "Confirm whether this corresponds to a planned migration or new deployment",
      "Review Stripe Dashboard → Events for any undelivered payment or subscription events",
    ],
    remediation_summary:
      "Confirm the current endpoint is correct and receiving events. If the change was unintended, restore the previous endpoint or disable the modified one.",
    remediation_steps: [
      "Open Stripe Dashboard → Developers → Webhooks",
      "Find the payments-webhook endpoint and verify its current URL",
      "Check the Webhook attempts tab for delivery failures",
      "If unintended: add the correct endpoint and disable the unexpected one",
      "Rotate the webhook signing secret if the endpoint may have been forwarded externally",
    ],
    fix_plan_summary:
      "Verify endpoint ownership and event delivery. Restore previous endpoint and rotate signing secret if the change was not planned.",
    dry_run_summary:
      "Disabling the current endpoint would halt payment event delivery to that URL. Confirm a valid receiving endpoint is in place before disabling.",
    blast_radius_summary:
      "May affect payment processing and subscription event handling for the duration of the unexpected endpoint being active. Payment confirmation flows are potentially affected.",
    ask_configtrace: {
      question: "What should I check first?",
      answer:
        "Start by confirming whether the new endpoint domain is one your team owns. Check Stripe's webhook delivery logs for failures, which would indicate events are not being processed. If events are failing, treat this as urgent.",
      bullets: [
        "Verify the endpoint domain belongs to your infrastructure",
        "Check Stripe webhook delivery attempts for failures or 4xx/5xx responses",
        "Cross-reference with any recent Vercel or DNS changes in the same time window",
        "This change is part of a cluster of 4 related changes — review together",
      ],
    },
  },

  // ── 5. GitHub environment protection (cluster) ────────────────────────────
  {
    id: "demo-github-env-001",
    provider: "github",
    risk_level: "high",
    change_type: "modified",
    title: "GitHub production environment protection weakened",
    description:
      "Required reviewers were removed and prevent-self-review was disabled on the production deployment environment.",
    timestamp_label: "12h ago",
    resource_name: "github.com/acme/checkout-api",
    category: "Branch protection",
    cluster_id: "demo-cluster-checkout",

    what_changed:
      "The production environment's required reviewer count was decreased to zero. The prevent-self-review setting was changed to disabled on the checkout-api repository.",
    why_it_matters:
      "With required reviewers removed, deployments to the production environment can now be approved by the deploying developer themselves. The peer review gate is no longer enforced by GitHub.",
    what_to_check: [
      "Review GitHub → checkout-api → Settings → Environments → production",
      "Check whether any production deployments were approved without peer review since the change",
      "Confirm whether this change was intentional and approved through your change control process",
      "Review Actions workflow logs for recent production deployments",
      "Confirm the production branch policy is still appropriate",
    ],
    remediation_summary:
      "Restore the required reviewer count and re-enable prevent-self-review on the production environment.",
    remediation_steps: [
      "Open GitHub → checkout-api → Settings → Environments",
      "Select the production environment",
      "Under 'Required reviewers', add at least one reviewer",
      "Enable 'Prevent self-review'",
      "Save changes and notify the team",
    ],
    fix_plan_summary:
      "Restore required reviewers and prevent-self-review. Verify that recent production deployments were appropriately authorized.",
    dry_run_summary:
      "Restoring protection settings would require peer review for all future production deployments. Existing deployments are not retroactively affected.",
    blast_radius_summary:
      "May affect the review gate for all future production deployments to checkout-api. Changes can be deployed without peer review until protection is restored.",
    ask_configtrace: {
      question: "What should I check first?",
      answer:
        "Check the GitHub audit log for who made the environment protection change and whether any deployments were approved without peer review since then. If unauthorized deployments have occurred, review them before restoring protection.",
      bullets: [
        "GitHub → Settings → Audit log: filter by environment_protection_rule events",
        "Review recent Actions workflow runs for production deployments",
        "Confirm whether the change was part of a planned environment migration",
        "This change is part of a cluster of 4 related changes — review together",
      ],
    },
  },

  // ── 6. Cloudflare WAF (cluster) ───────────────────────────────────────────
  {
    id: "demo-cf-waf-001",
    provider: "cloudflare",
    risk_level: "high",
    change_type: "modified",
    title: "Cloudflare WAF ruleset protection reduced",
    description:
      "WAF rule coverage was reduced on app.example.com. Block and challenge actions changed; skip rules were added to the managed ruleset.",
    timestamp_label: "12h ago",
    resource_name: "app.example.com",
    category: "WAF",
    cluster_id: "demo-cluster-checkout",

    what_changed:
      "WAF ruleset was modified on the app.example.com zone. Block and challenge actions were changed for a subset of managed rules. Skip rules were added that bypass sections of the managed ruleset.",
    why_it_matters:
      "Reduced WAF rule coverage may allow malicious traffic patterns — such as SQL injection or cross-site scripting probes — to reach the origin without being blocked or challenged. If the skip rules were not intentionally added, protection has been lowered.",
    what_to_check: [
      "Review Cloudflare Dashboard → Security → WAF → Custom Rules and Managed Rules",
      "Identify which rules were changed from block/challenge to skip",
      "Confirm whether the skip rules correspond to a false-positive remediation",
      "Review Security Events for any unusual traffic patterns in the past 12 hours",
      "Check whether the WAF changes align with a planned deployment",
    ],
    remediation_summary:
      "Review skip rules and restore block/challenge coverage for unintended exceptions. Scope rule exceptions to specific URIs if needed.",
    remediation_steps: [
      "Open Cloudflare Dashboard → Security → WAF",
      "Review Custom Rules for recently added skip actions",
      "Remove skip rules that were not intentionally added",
      "If a specific URI needed an exception: scope the override to that URI pattern only",
      "Monitor Security Events after restoring coverage to confirm normal traffic patterns",
    ],
    fix_plan_summary:
      "Remove or narrow skip rules. Restore intended block/challenge coverage at the managed ruleset level. Scope any necessary exceptions to specific URIs.",
    dry_run_summary:
      "Restoring WAF rules may block or challenge requests currently passing. Review Security Events first to confirm no legitimate traffic would be affected by the restored rules.",
    blast_radius_summary:
      "May affect traffic filtering for the entire app.example.com zone. WAF changes apply to all inbound requests to this zone.",
    ask_configtrace: {
      question: "What is the blast radius?",
      answer:
        "WAF ruleset changes apply zone-wide, so all traffic to app.example.com is potentially affected. The impact depends on which traffic patterns are now unblocked and whether any corresponds to attack traffic.",
      bullets: [
        "All inbound requests to the app.example.com zone are affected",
        "Traffic patterns previously caught by the disabled rules may now reach the origin",
        "Review Cloudflare Security Events to identify any unusual traffic since the change",
        "This change is part of a cluster of 4 related changes — review together",
      ],
    },
  },

  // ── 7. Vercel deploy hook (cluster) ───────────────────────────────────────
  {
    id: "demo-vercel-hook-001",
    provider: "vercel",
    risk_level: "high",
    change_type: "modified",
    title: "Vercel deploy hook target branch changed",
    description:
      "A deploy hook's target ref was changed on the prod-web Vercel project. Deployments triggered by this hook will target a different branch.",
    timestamp_label: "12h ago",
    resource_name: "prod-web",
    category: "Deployment",
    cluster_id: "demo-cluster-checkout",

    what_changed:
      "A deploy hook on the prod-web project was modified. The hook's target branch ref was changed from the production branch to a different ref.",
    why_it_matters:
      "If unintended, future deployments triggered by this hook could deploy non-production code to the production Vercel environment. Any CI/CD pipeline or external automation that uses this hook would be affected.",
    what_to_check: [
      "Open Vercel Dashboard → prod-web → Settings → Git → Deploy Hooks",
      "Confirm the current hook target branch is the intended production branch",
      "Check whether any hook-triggered deployments have run since the change",
      "Identify which integration or automation owns this deploy hook",
      "Review recent Vercel deployment logs for unexpected branch deployments",
    ],
    remediation_summary:
      "Restore the correct target branch on the deploy hook. Rotate or remove the hook if its origin is unknown.",
    remediation_steps: [
      "Open Vercel Dashboard → prod-web → Settings → Git",
      "Find the deploy hook that was modified",
      "Update the target branch to main (or the intended production branch)",
      "If the hook origin is unknown: delete the hook and create a new one with a fresh secret",
      "Review recent deployments to confirm no unintended code was shipped",
    ],
    fix_plan_summary:
      "Restore target branch to main. Rotate the hook secret if the hook's origin is unknown or the secret may have been exposed.",
    dry_run_summary:
      "Changing the target branch would affect future hook-triggered deployments only. In-flight deployments are not affected. Verify the correct branch deploys cleanly before removing the modified hook.",
    blast_radius_summary:
      "May affect all deployments triggered by this hook. If the hook is used by an upstream CI pipeline, triggering logic in that pipeline may also need updating.",
    ask_configtrace: {
      question: "What are my next steps?",
      answer:
        "Verify the current hook target branch immediately. If any deployments ran after the change, review the Vercel deployment log to confirm what code was deployed. If the hook source is unknown, rotate it and update any automation that depends on it.",
      bullets: [
        "Check the current deploy hook configuration in Vercel Dashboard",
        "Review Vercel deployment log for branch deployments since the change",
        "Identify the automation or CI job that calls this hook",
        "This change is part of a cluster of 4 related changes — review together",
      ],
    },
  },

  // ── 8. Shopify app scopes ─────────────────────────────────────────────────
  {
    id: "demo-shopify-scope-001",
    provider: "shopify",
    risk_level: "high",
    change_type: "modified",
    title: "Shopify app scope list now includes sensitive write permissions",
    description:
      "An installed app's permission scope summary changed. Scope metadata indicates write-level permissions were added.",
    timestamp_label: "1d ago",
    resource_name: "storefront-prod",
    category: "Commerce",

    what_changed:
      "The app permission scope list changed for an app installed on the storefront-prod Shopify store. Scope metadata now includes write-level permissions that were not previously present.",
    why_it_matters:
      "Write-level app scopes can allow an app to modify orders, products, inventory, or customer data. Unexpected write permissions may indicate an unauthorized scope expansion via an app update or reinstallation.",
    what_to_check: [
      "Open Shopify Admin → Settings → Apps and sales channels → Manage apps",
      "Find the affected app and review its current permission list",
      "Contact the app vendor to understand the justification for the new write scopes",
      "Check whether this corresponds to a planned app upgrade or new feature enablement",
      "Review Shopify Admin activity log for recent order or product changes by the app",
    ],
    remediation_summary:
      "Confirm the business justification for each new scope. Remove unnecessary write scopes by uninstalling and reinstalling the app with the minimal required permissions.",
    remediation_steps: [
      "Open Shopify Admin → Settings → Apps and sales channels",
      "Find the affected app and review its permissions",
      "Contact the app vendor for written justification of write scopes",
      "If scopes are unnecessary: uninstall and reinstall the app requesting only required scopes",
      "If this is a custom app: update the scope request in the Shopify Partners Dashboard",
    ],
    fix_plan_summary:
      "Confirm scope justification with the app vendor. Remove unnecessary write scopes by reinstalling with minimal required permissions.",
    dry_run_summary:
      "Reinstalling with reduced scopes would revoke write access immediately. Some app features may stop working if they depend on the write permissions. Coordinate with the app vendor before removing scopes.",
    blast_radius_summary:
      "May affect all store data the app has write access to. Depending on the specific scopes added, orders, products, inventory, or customer records may be writable by the app.",
    ask_configtrace: {
      question: "Could this be expected?",
      answer:
        "This could be expected if the app vendor released an update requiring additional permissions and your team approved the updated scope request. However, write-level scope additions should always be reviewed explicitly, not accepted automatically.",
      bullets: [
        "Could be expected if: the app recently released a feature update requiring write access",
        "Needs review if: no scope upgrade notice was received from the app vendor",
        "Check Shopify App Store or vendor changelog for recent permission changes",
        "If in doubt: contact the vendor before accepting additional write scopes",
      ],
    },
  },
];

// ── Demo cluster ──────────────────────────────────────────────────────────────

export const DEMO_CLUSTERS: DemoCluster[] = [
  {
    id: "demo-cluster-checkout",
    title: "Possible checkout routing change",
    description:
      "4 related changes across Cloudflare, Vercel, Stripe, and GitHub were detected within a 12-minute window. The changes may indicate a coordinated routing or deployment activity. Review together before acting on any individually.",
    change_ids: [
      "demo-cf-waf-001",
      "demo-vercel-hook-001",
      "demo-stripe-webhook-001",
      "demo-github-env-001",
    ],
    providers: ["cloudflare", "vercel", "stripe", "github"],
    timespan_label: "12 minutes",
  },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

export function getDemoClusterForChange(changeId: string): DemoCluster | null {
  const change = DEMO_CHANGES.find((c) => c.id === changeId);
  if (!change?.cluster_id) return null;
  return DEMO_CLUSTERS.find((cl) => cl.id === change.cluster_id) ?? null;
}

export function getDemoChangesForCluster(clusterId: string): DemoChange[] {
  const cluster = DEMO_CLUSTERS.find((cl) => cl.id === clusterId);
  if (!cluster) return [];
  return DEMO_CHANGES.filter((c) => cluster.change_ids.includes(c.id));
}

// ── Risk summary counts ───────────────────────────────────────────────────────

export interface DemoRiskCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  needsReview: number;
  providerCount: number;
}

export function getDemoRiskCounts(): DemoRiskCounts {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const c of DEMO_CHANGES) {
    counts[c.risk_level] = (counts[c.risk_level] ?? 0) + 1;
  }
  const providerSet = new Set(DEMO_CHANGES.map((c) => c.provider));
  return {
    ...counts,
    needsReview: DEMO_CHANGES.length,
    providerCount: providerSet.size,
  };
}
