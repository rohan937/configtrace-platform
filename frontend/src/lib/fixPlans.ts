/**
 * Fix plan generation — M58.2.
 *
 * Generates structured, non-executed fix plans for risky configuration changes.
 * Plans are preview/guidance only: ConfigTrace never executes them.
 *
 * Architecture: frontend-only pure mapping (mirrors remediation.ts).
 *
 * Data safety:
 *   - No secrets, tokens, or credentials are ever included in commands.
 *   - Placeholder tokens (<NAME>) are used wherever values are unknown.
 *   - prev_value/new_value contents are never forwarded into command text.
 *   - record_identifier is used only if it matches a safe structural pattern
 *     (e.g. sg-[0-9a-f]+) — never forwarded raw.
 *
 * Coverage: 7 flagship examples for M58.2. Provider-specific expansion
 * continues in M58.2a (AWS + GitHub + Cloudflare) and M58.2b (Firebase +
 * Supabase + Stripe + Vercel + Shopify).
 */

import type {
  ChangeInput,
  FixPlan,
  FixPlanCommand,
  FixPlanResult,
} from "@/lib/remediation";

// ── Constants ─────────────────────────────────────────────────────────────────

const NA: FixPlanResult = { available: false };

/** Standard postconditions appended to every fix plan. */
const STANDARD_POSTCONDITIONS: string[] = [
  "Run a ConfigTrace sync again.",
  "Confirm the change no longer appears as a high-risk or critical finding.",
  "Verify the expected security configuration is in place.",
];

// ── Builder helper ────────────────────────────────────────────────────────────

type FixPlanCore = Omit<FixPlan, "available" | "execution_enabled" | "execution_mode">;

function _fp(core: FixPlanCore): FixPlan {
  return {
    ...core,
    available: true,
    execution_enabled: false,
    execution_mode: "manual_only",
  };
}

// ── Value extraction helpers ──────────────────────────────────────────────────

/**
 * Returns the security group ID from record_identifier if it matches the
 * AWS sg-xxx pattern; returns null otherwise.
 * Safe: only returns values that match a structural pattern, never raw strings.
 */
function _extractSgId(recordId: string): string | null {
  const match = /^(sg-[0-9a-f]{8,17})$/i.exec(recordId.trim());
  return match ? match[1] : null;
}

/**
 * Extract AWS region from provider_metadata if present.
 * Returns null when unavailable so callers can use a placeholder instead.
 */
function _extractAwsRegion(pm: Record<string, unknown> | null): string | null {
  if (!pm) return null;
  const r = pm["region"] ?? pm["aws_region"] ?? pm["aws_default_region"];
  if (typeof r === "string" && /^[a-z]{2}-[a-z]+-\d$/.test(r)) return r;
  return null;
}

/**
 * Extract Cloudflare Zone ID from provider_metadata.
 * Returns null if unavailable.
 */
function _extractZoneId(pm: Record<string, unknown> | null): string | null {
  if (!pm) return null;
  const z = pm["zone_id"] ?? pm["cloudflare_zone_id"];
  if (typeof z === "string" && /^[0-9a-f]{32}$/.test(z)) return z;
  return null;
}

/**
 * Extract table identifier from record_identifier for Supabase RLS changes.
 * Accepts "schema.table" or bare "table" patterns; returns null otherwise.
 */
function _extractTableId(recordId: string): string | null {
  const t = recordId.trim();
  if (/^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?$/i.test(t) && t.length < 128) return t;
  return null;
}

// ── Flagship 1: AWS Security Group — public SSH (port 22) ────────────────────

function _awsSgSshFixPlan(
  change: ChangeInput, rt: string, fp: string,
  ct: string, rl: string, rr: string,
): FixPlan | null {
  if (rt !== "aws_security_group") return null;
  if (!(
    fp === "has_public_ssh" ||
    rr.includes("ssh")     ||
    rr.includes("port 22") ||
    rr.includes("tcp/22")
  )) return null;
  if (rl !== "critical" && rl !== "high") return null;

  const sgId    = _extractSgId(change.record_identifier);
  const region  = _extractAwsRegion(change.provider_metadata);
  const sgToken = sgId ?? "<SECURITY_GROUP_ID>";

  const regionLine = region
    ? `  # If your default region differs: add --region ${region}`
    : "  # Add --region <AWS_REGION> if your default region is not correct";

  const command = [
    "aws ec2 revoke-security-group-ingress \\",
    `  --group-id ${sgToken} \\`,
    "  --protocol tcp \\",
    "  --port 22 \\",
    "  --cidr 0.0.0.0/0",
    regionLine,
  ].join("\n");

  const requiresValues: string[] = [
    ...(!sgId   ? ["SECURITY_GROUP_ID"] : []),
    ...(!region ? ["AWS_REGION"]        : []),
  ];

  const cmds: FixPlanCommand[] = [
    {
      label: "AWS CLI — IPv4",
      language: "bash",
      command,
      requires_values: requiresValues,
    },
    {
      label: "AWS CLI — IPv6 (if ::/0 rule also exists)",
      language: "bash",
      command: [
        "aws ec2 revoke-security-group-ingress \\",
        `  --group-id ${sgToken} \\`,
        "  --ip-permissions '[{\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"Ipv6Ranges\":[{\"CidrIpv6\":\"::/0\"}]}]'",
        regionLine,
      ].join("\n"),
      requires_values: requiresValues,
    },
  ];

  return _fp({
    kind: "command",
    title: "Remove public SSH ingress rule",
    summary:
      "These commands remove the publicly accessible tcp/22 (SSH) ingress rule from the affected security group. Apply the IPv4 command first; apply the IPv6 command only if an ::/0 IPv6 rule also exists.",
    safety_level: "requires_human_review",
    commands: cmds,
    required_permissions: ["ec2:RevokeSecurityGroupIngress"],
    preconditions: [
      "Confirm an alternate SSH access path exists: VPN, bastion host, or AWS SSM Session Manager.",
      "Identify all EC2 instances attached to this security group and confirm the change is intended for all of them.",
      `Verify the security group ID (${sgToken}) matches the expected resource in the AWS console.`,
    ],
    postconditions: [
      ...STANDARD_POSTCONDITIONS,
      "Verify SSH access via the secure alternate path (VPN/bastion/SSM) still works after the rule is removed.",
    ],
    warnings: [
      "This will block all direct SSH access from public IPs — confirm a secure alternative access path exists before applying.",
      "The IPv4 command removes 0.0.0.0/0 only. Run the IPv6 command separately if a ::/0 IPv6 ingress rule also exists.",
      "ConfigTrace does not execute this command. Review it in the context of your environment before applying.",
    ],
    copy_enabled: true,
  });
}

// ── Flagship 2: AWS Security Group — public RDP (port 3389) ──────────────────

function _awsSgRdpFixPlan(
  change: ChangeInput, rt: string, fp: string,
  ct: string, rl: string, rr: string,
): FixPlan | null {
  if (rt !== "aws_security_group") return null;
  if (!(
    fp === "has_public_rdp"   ||
    rr.includes("rdp")        ||
    rr.includes("port 3389")  ||
    rr.includes("tcp/3389")
  )) return null;
  if (rl !== "critical" && rl !== "high") return null;

  const sgId    = _extractSgId(change.record_identifier);
  const region  = _extractAwsRegion(change.provider_metadata);
  const sgToken = sgId ?? "<SECURITY_GROUP_ID>";

  const regionLine = region
    ? `  # If your default region differs: add --region ${region}`
    : "  # Add --region <AWS_REGION> if your default region is not correct";

  const command = [
    "aws ec2 revoke-security-group-ingress \\",
    `  --group-id ${sgToken} \\`,
    "  --protocol tcp \\",
    "  --port 3389 \\",
    "  --cidr 0.0.0.0/0",
    regionLine,
  ].join("\n");

  const requiresValues: string[] = [
    ...(!sgId   ? ["SECURITY_GROUP_ID"] : []),
    ...(!region ? ["AWS_REGION"]        : []),
  ];

  return _fp({
    kind: "command",
    title: "Remove public RDP ingress rule",
    summary:
      "This command removes the publicly accessible tcp/3389 (RDP) ingress rule from the affected security group. Apply the IPv6 variant separately if a ::/0 rule also exists.",
    safety_level: "requires_human_review",
    commands: [
      {
        label: "AWS CLI — IPv4",
        language: "bash",
        command,
        requires_values: requiresValues,
      },
      {
        label: "AWS CLI — IPv6 (if ::/0 rule also exists)",
        language: "bash",
        command: [
          "aws ec2 revoke-security-group-ingress \\",
          `  --group-id ${sgToken} \\`,
          "  --ip-permissions '[{\"IpProtocol\":\"tcp\",\"FromPort\":3389,\"ToPort\":3389,\"Ipv6Ranges\":[{\"CidrIpv6\":\"::/0\"}]}]'",
          regionLine,
        ].join("\n"),
        requires_values: requiresValues,
      },
    ],
    required_permissions: ["ec2:RevokeSecurityGroupIngress"],
    preconditions: [
      "Confirm an alternate Windows remote access path exists: VPN, bastion/jump host, or AWS SSM Fleet Manager.",
      "Identify all EC2 instances attached to this security group and confirm the change is intended for all of them.",
      `Verify the security group ID (${sgToken}) matches the expected resource in the AWS console.`,
    ],
    postconditions: [
      ...STANDARD_POSTCONDITIONS,
      "Verify Windows remote access via the secure alternate path (VPN/bastion/SSM) still works after the rule is removed.",
    ],
    warnings: [
      "This will block all direct RDP access from public IPs — confirm a secure alternative access path exists before applying.",
      "The IPv4 command removes 0.0.0.0/0 only. Run the IPv6 command separately if a ::/0 IPv6 ingress rule also exists.",
      "ConfigTrace does not execute this command. Review it carefully before applying.",
    ],
    copy_enabled: true,
  });
}

// ── Flagship 3: GitHub branch protection — guided fix ────────────────────────

function _ghBranchProtectionFixPlan(
  change: ChangeInput, rt: string, fp: string,
  ct: string, rl: string, rr: string,
): FixPlan | null {
  if (rt !== "github_branch_protection") return null;
  if (rl !== "critical" && rl !== "high") return null;

  // Extract owner/repo/branch from record_identifier if structured.
  // Common patterns: "owner/repo" or "owner/repo:branch" or just "branch-name".
  let owner = "<OWNER>";
  let repo  = "<REPO>";
  let branch = "<BRANCH>";
  const rid = change.record_identifier.trim();
  const ownerRepoMatch = /^([^/:\s]+)\/([^/:\s]+)(?::(.+))?$/.exec(rid);
  if (ownerRepoMatch) {
    owner  = ownerRepoMatch[1];
    repo   = ownerRepoMatch[2];
    branch = ownerRepoMatch[3] ?? "<BRANCH>";
  } else if (rid && !/[/:]/.test(rid)) {
    // Looks like just a branch name
    branch = rid;
  }

  const hasPlaceholders = owner === "<OWNER>" || repo === "<REPO>" || branch === "<BRANCH>";
  const requiresValues: string[] = [
    ...(owner  === "<OWNER>"  ? ["OWNER"]  : []),
    ...(repo   === "<REPO>"   ? ["REPO"]   : []),
    ...(branch === "<BRANCH>" ? ["BRANCH"] : []),
  ];

  return _fp({
    kind: "guided_manual",
    title: "Restore GitHub branch protection rules",
    summary:
      "Review and restore the weakened or removed branch protection settings via GitHub repository settings. The GitHub CLI outline below is for reference — apply via the GitHub UI or with a complete, reviewed API payload.",
    safety_level: "requires_human_review",
    commands: [
      {
        label: "GitHub CLI — read current protection (review before restoring)",
        language: "bash",
        command: [
          `# Step 1: View the current branch protection state`,
          `gh api repos/${owner}/${repo}/branches/${branch}/protection`,
          ``,
          `# Step 2: Restore via GitHub UI (recommended), or prepare a complete`,
          `# protection payload and apply via API:`,
          `# gh api repos/${owner}/${repo}/branches/${branch}/protection \\`,
          `#   --method PUT --input branch-protection.json`,
        ].join("\n"),
        requires_values: requiresValues,
      },
    ],
    manual_steps: [
      `Open GitHub → [repo] → Settings → Branches.`,
      `Find the protection rule for the affected branch (${branch === "<BRANCH>" ? "check the change detail for the branch name" : branch}).`,
      `Review the current settings and restore: required reviewers, required status checks, enforce admins, dismiss stale reviews, prevent force pushes, prevent deletions.`,
      `Save the rule.`,
      `Audit recent commits and pull requests on this branch for any that bypassed protection while the rule was weakened.`,
    ],
    required_permissions: [
      "GitHub: repository admin role (to modify branch protection in Settings)",
      "GitHub API: repo administration scope (if applying via API or gh CLI)",
    ],
    preconditions: [
      "Identify which specific protection settings were weakened or removed.",
      "Confirm the correct required reviewer count and status check names for this branch.",
      "If using the GitHub API (PUT), prepare a complete protection payload — a partial PUT can silently disable settings not included in the body.",
    ],
    postconditions: [
      ...STANDARD_POSTCONDITIONS,
      "Test that pull requests require the expected reviews and status checks before merging.",
    ],
    warnings: [
      "Do not apply a GitHub branch protection API PUT without a complete, reviewed payload — omitting fields in a PUT request disables those settings.",
      "Restoring required status checks will block open pull requests whose checks are not currently passing.",
      "If this branch was unprotected during a window, audit the git log for any commits merged without review.",
    ],
    copy_enabled: true,
  });
}

// ── Flagship 4: Cloudflare DNS record — guided fix ───────────────────────────

const _CF_DNS_TYPES = new Set([
  "a", "aaaa", "cname", "mx", "txt", "ns", "srv",
  "ptr", "spf", "caa", "ds", "tlsa",
]);

function _cfDnsFixPlan(
  change: ChangeInput, rt: string, fp: string,
  ct: string, rl: string, rr: string,
): FixPlan | null {
  if (!_CF_DNS_TYPES.has(rt) && rt !== "cloudflare_dns_record") return null;
  if (rl !== "critical" && rl !== "high") return null;

  const zoneId    = _extractZoneId(change.provider_metadata);
  const zoneToken = zoneId ?? "<ZONE_ID>";
  const isRemoved = ct === "removed";

  return _fp({
    kind: "guided_manual",
    title: isRemoved ? "Restore removed Cloudflare DNS record" : "Restore Cloudflare DNS record value",
    summary:
      "Restore the DNS record via the Cloudflare dashboard or API. Confirm the correct record type, name, content, and proxy status before applying.",
    safety_level: "requires_human_review",
    commands: [
      {
        label: isRemoved ? "Cloudflare API — create record (outline)" : "Cloudflare API — update record (outline)",
        language: "bash",
        command: isRemoved
          ? [
              `# Replace placeholders with the correct record values before running.`,
              `# Do not include your API token in shell history — use a .env file or secret manager.`,
              `curl -X POST "https://api.cloudflare.com/client/v4/zones/${zoneToken}/dns_records" \\`,
              `  -H "Authorization: Bearer <CLOUDFLARE_API_TOKEN>" \\`,
              `  -H "Content-Type: application/json" \\`,
              `  --data '{`,
              `    "type": "<RECORD_TYPE>",`,
              `    "name": "<RECORD_NAME>",`,
              `    "content": "<EXPECTED_VALUE>",`,
              `    "ttl": 1,`,
              `    "proxied": true`,
              `  }'`,
            ].join("\n")
          : [
              `# Replace placeholders with the correct record values before running.`,
              `# Retrieve the RECORD_ID first: GET zones/${zoneToken}/dns_records?name=<RECORD_NAME>`,
              `curl -X PATCH "https://api.cloudflare.com/client/v4/zones/${zoneToken}/dns_records/<RECORD_ID>" \\`,
              `  -H "Authorization: Bearer <CLOUDFLARE_API_TOKEN>" \\`,
              `  -H "Content-Type: application/json" \\`,
              `  --data '{`,
              `    "type": "<RECORD_TYPE>",`,
              `    "name": "<RECORD_NAME>",`,
              `    "content": "<EXPECTED_VALUE>",`,
              `    "proxied": true`,
              `  }'`,
            ].join("\n"),
        requires_values: [
          "CLOUDFLARE_API_TOKEN",
          ...(zoneId ? [] : ["ZONE_ID"]),
          "RECORD_TYPE",
          "RECORD_NAME",
          "EXPECTED_VALUE",
          ...(!isRemoved ? ["RECORD_ID"] : []),
        ],
      },
    ],
    manual_steps: [
      "Open the Cloudflare Dashboard → your domain → DNS → Records.",
      isRemoved
        ? "Click 'Add record' and restore the missing record with the correct type, name, content, and proxy status."
        : "Find the affected record and click 'Edit'. Restore the correct content/value and proxy status.",
      "Save the record.",
      "Use a DNS propagation checker (e.g. dnschecker.org) to verify the record is live.",
    ],
    required_permissions: [
      "Cloudflare: Zone DNS Edit permission (for the affected zone)",
    ],
    preconditions: [
      "Confirm the expected record type, name, and content value from your DNS records history or infrastructure documentation.",
      "If the record is proxied (orange cloud), confirm the proxy setting should be restored.",
    ],
    postconditions: [
      ...STANDARD_POSTCONDITIONS,
      "Verify DNS resolution for the affected record using: dig <RECORD_NAME> @1.1.1.1",
      "Confirm dependent services (web app, mail, etc.) are functioning after the record is restored.",
    ],
    warnings: [
      "Do not include your Cloudflare API token in command history — use environment variables or a secrets manager.",
      "DNS changes propagate over time — monitor resolution for 15–30 minutes after applying.",
      "Verify the correct record content before applying — restoring an incorrect value may break services.",
    ],
    copy_enabled: true,
  });
}

// ── Flagship 5: Firebase Security Rules — guided fix ─────────────────────────

const _FB_RULES_RECORD_TYPES = new Set([
  "firebase_security_rules",
  "firebase_rules",
  "firebase_firestore_rules",
  "firebase_storage_rules",
  "firebase_realtime_database",
]);

function _firebaseRulesFixPlan(
  change: ChangeInput, rt: string, fp: string,
  ct: string, rl: string, rr: string,
): FixPlan | null {
  if (!_FB_RULES_RECORD_TYPES.has(rt)) return null;
  if (rl !== "critical" && rl !== "high") return null;

  const isRealtime  = rt === "firebase_realtime_database";
  const ruleProduct = isRealtime ? "Realtime Database" : "Firestore / Storage";

  return _fp({
    kind: "guided_manual",
    title: `Tighten Firebase ${ruleProduct} security rules`,
    summary:
      "Review the affected Firebase security rules and add authentication and authorization checks to restrict public read/write access. Firebase rules require application-specific context — use the Rules Simulator to test before publishing.",
    safety_level: "requires_human_review",
    manual_steps: [
      `Open the Firebase Console → your project → ${isRealtime ? "Realtime Database → Rules" : "Firestore / Storage → Rules"}.`,
      "Review the current rules and identify paths that allow public reads or writes (e.g. allow read, write: if true;).",
      "Add authentication checks: replace `if true` with `if request.auth != null` at minimum.",
      "For sensitive data paths, add role-based checks: `if request.auth.uid == userId` or custom claims.",
      "Use the Rules Simulator (available in the Firebase Console) to test your updated rules with authenticated and unauthenticated requests.",
      "Publish the updated rules.",
    ],
    required_permissions: [
      "Firebase: Project Editor or Owner role (to modify and publish security rules)",
    ],
    preconditions: [
      "Identify which specific Firestore collection, Storage bucket, or Realtime Database path has overly permissive rules.",
      "Understand what authentication is used by your application (email/password, Google, anonymous, custom tokens).",
      "Review existing client code to confirm which reads/writes require authentication vs public access.",
    ],
    postconditions: [
      ...STANDARD_POSTCONDITIONS,
      "Test client flows that read and write the affected paths to confirm they still work for authenticated users.",
      "Confirm unauthenticated access to the affected paths is now denied.",
    ],
    warnings: [
      "Firebase security rules are case-sensitive and path-specific — an incorrect rule can break client access or leave paths unprotected.",
      "Test rules thoroughly in the Simulator before publishing to production.",
      "Rules changes take effect immediately after publishing — ensure client apps are not broken before deploying.",
    ],
    copy_enabled: false,
  });
}

// ── Flagship 6: Supabase RLS — guided fix with SQL outline ───────────────────

function _supabaseRlsFixPlan(
  change: ChangeInput, rt: string, fp: string,
  ct: string, rl: string, rr: string,
): FixPlan | null {
  if (rt !== "supabase_rls_status") return null;
  if (rl !== "critical" && rl !== "high") return null;

  const tableId = _extractTableId(change.record_identifier);
  const tableToken = tableId ?? "<schema.table>";

  return _fp({
    kind: "command",
    title: "Enable Row Level Security on Supabase table",
    summary:
      "Enable RLS on the affected table to prevent unauthenticated or unauthorized access. Ensure RLS policies exist before enabling, or all non-superuser client access will be denied.",
    safety_level: "requires_human_review",
    commands: [
      {
        label: "SQL — enable RLS",
        language: "sql",
        command: [
          `-- Step 1: Verify existing policies BEFORE enabling RLS`,
          `SELECT schemaname, tablename, policyname, cmd, qual`,
          `FROM pg_policies`,
          `WHERE tablename = '${tableId ? tableId.split(".").pop() : "<TABLE_NAME>"}';`,
          ``,
          `-- Step 2: Enable RLS (only after confirming policies exist)`,
          `ALTER TABLE ${tableToken} ENABLE ROW LEVEL SECURITY;`,
          ``,
          `-- Step 3: Verify RLS is enabled`,
          `SELECT tablename, rowsecurity`,
          `FROM pg_tables`,
          `WHERE tablename = '${tableId ? tableId.split(".").pop() : "<TABLE_NAME>"}';`,
        ].join("\n"),
        requires_values: tableId ? [] : ["TABLE_NAME"],
      },
    ],
    required_permissions: [
      "Supabase: database owner or postgres superuser role",
      "Apply via: Supabase Dashboard → SQL Editor, or via a database migration",
    ],
    preconditions: [
      "Run the Step 1 query to confirm that RLS policies exist for this table BEFORE enabling RLS.",
      "Enabling RLS without any policies will deny all access for non-superuser roles — including your application service role.",
      `Confirm the table identifier (${tableToken}) is correct before running.`,
    ],
    postconditions: [
      ...STANDARD_POSTCONDITIONS,
      "Test that application queries to this table succeed for authenticated users.",
      "Verify that unauthenticated or unauthorized queries are correctly denied.",
    ],
    warnings: [
      "Enabling RLS without policies will block ALL data access for non-superuser roles. Verify policies exist first using Step 1.",
      "Apply this change via a reviewed database migration in non-production environments before production.",
      "The Supabase service role key bypasses RLS — ensure your application uses the anon key for client-side queries.",
    ],
    copy_enabled: true,
  });
}

// ── Flagship 7: Vercel deploy hook — guided fix ───────────────────────────────

function _vercelDeployHookFixPlan(
  change: ChangeInput, rt: string, fp: string,
  ct: string, rl: string, rr: string,
): FixPlan | null {
  if (rt !== "vercel_deploy_hook_metadata") return null;
  // Backend classifies deploy hook changes as medium or higher
  if (rl === "low" || rl === "unknown") return null;

  const isAdded   = ct === "added";
  const isRemoved = ct === "removed";

  return _fp({
    kind: "guided_manual",
    title: isAdded
      ? "Review and audit the new Vercel deploy hook"
      : isRemoved
        ? "Restore or confirm removed Vercel deploy hook"
        : "Review and secure the changed Vercel deploy hook",
    summary:
      "Review the deploy hook configuration in Vercel project settings. If unexpected, delete the hook and recreate it with a new URL to revoke the old trigger endpoint.",
    safety_level: "requires_human_review",
    manual_steps: isAdded
      ? [
          "Open the Vercel Dashboard → [project] → Settings → Git → Deploy Hooks.",
          "Find the newly added hook and confirm its name, target branch/ref, and that it was created by a team member.",
          "Verify the hook URL has not been exposed in public repositories, CI logs, or client-side code.",
          "If the hook is unexpected or unauthorized: click the delete icon to remove it.",
          "If the hook was created for a legitimate purpose: document the integration it serves.",
        ]
      : isRemoved
        ? [
            "Open the Vercel Dashboard → [project] → Settings → Git → Deploy Hooks.",
            "Confirm whether the removed hook was serving a known integration (cron job, CMS trigger, CI pipeline).",
            "If removal was unintentional: click 'Create Hook', enter the correct name and branch/ref.",
            "Update the new hook URL in the integration that used it (treat the old URL as revoked).",
            "Test the integration to confirm deployments still trigger as expected.",
          ]
        : [
            "Open the Vercel Dashboard → [project] → Settings → Git → Deploy Hooks.",
            "Review the affected hook's name, target branch/ref, and URL.",
            "If the ref was changed unexpectedly: delete and recreate the hook with the correct branch.",
            "If the hook URL may have been exposed: delete and recreate to generate a new secret URL.",
            "Update any integrations that used the old hook URL.",
          ],
    required_permissions: [
      "Vercel: project owner or team member with project settings access",
    ],
    preconditions: [
      "Identify the integration or automation that uses (or used) this deploy hook.",
      "Confirm the intended target branch for this project's deployments.",
    ],
    postconditions: [
      ...STANDARD_POSTCONDITIONS,
      "Confirm the deploy hook list shows only expected, authorized hooks.",
      "Test that legitimate deployment triggers continue to work.",
    ],
    warnings: [
      "Deploy hook URLs are secrets — they allow triggering deployments without GitHub access. Treat them like API keys.",
      "Deleting a hook immediately breaks any integration that holds the old URL.",
      "Vercel deploy hook URLs cannot be retrieved after creation — if exposed, delete and recreate.",
    ],
    copy_enabled: false,
  });
}

// ── Main dispatcher ───────────────────────────────────────────────────────────

/**
 * Return a structured fix plan for a risky configuration change, or
 * `{ available: false }` when no fix plan is implemented for this change type.
 *
 * Fix plans are preview/guidance only. ConfigTrace never executes them.
 * The user must copy and run any commands manually in their own environment.
 *
 * Coverage in M58.2: 7 flagship examples.
 * Full provider expansion comes in M58.2a and M58.2b.
 */
export function getFixPlanForChange(change: ChangeInput): FixPlanResult {
  const pm = change.provider_metadata ?? {};
  const rt = ((pm["record_type"] as string) ?? "").toLowerCase();
  const fp = (change.field_path ?? "").toLowerCase();
  const ct = change.change_type.toLowerCase();
  const rl = change.risk_level.toLowerCase();
  const rr = (change.risk_reason ?? "").toLowerCase();

  if (rl === "low" || rl === "unknown") return NA;

  return (
    _awsSgSshFixPlan(change, rt, fp, ct, rl, rr)             ??
    _awsSgRdpFixPlan(change, rt, fp, ct, rl, rr)             ??
    _ghBranchProtectionFixPlan(change, rt, fp, ct, rl, rr)   ??
    _cfDnsFixPlan(change, rt, fp, ct, rl, rr)                ??
    _firebaseRulesFixPlan(change, rt, fp, ct, rl, rr)        ??
    _supabaseRlsFixPlan(change, rt, fp, ct, rl, rr)          ??
    _vercelDeployHookFixPlan(change, rt, fp, ct, rl, rr)     ??
    NA
  );
}
