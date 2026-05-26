/**
 * Remediation guidance framework — M58.1.
 *
 * Maps risky configuration changes to structured, read-only remediation
 * guidance. This module is intentionally guidance-only:
 *   - No provider writes.
 *   - No command generation (deferred to M58.2).
 *   - No one-click execution (deferred to M58.3).
 *   - No write permissions required or requested.
 *
 * Architecture: frontend-only pure mapping.
 * The Change object already carries all required fields:
 *   provider_metadata.record_type, field_path, change_type, risk_level,
 *   risk_reason, prev_value, new_value, record_identifier.
 *
 * Pattern mirrors getWhyItMatters / getSuggestedChecks in the change detail
 * page — pure functions, no API calls, no side effects.
 *
 * Data safety:
 *   - Guidance text is fully static — no raw prev_value/new_value content is
 *     interpolated into the output.
 *   - prev_value/new_value are only read as booleans or numbers for trigger
 *     logic; their string contents are never forwarded.
 *   - No secrets, tokens, credentials, customer data, or raw rule bodies
 *     appear in guidance output.
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export interface DocsLink {
  label: string;
  url:   string;
}

export interface RemediationGuidance {
  readonly available:                  true;
  readonly confidence:                 "high" | "medium" | "low";
  readonly title:                      string;
  readonly summary:                    string;
  readonly why_this_helps:             string;
  readonly verify_first:               string[];
  readonly manual_steps:               string[];
  readonly validation_steps:           string[];
  readonly caveats:                    string[];
  readonly docs_links:                 DocsLink[];
  /** Always false in M58.1 — command generation starts in M58.2. */
  readonly fix_command_available:      false;
  /** Always false in M58.1 — one-click remediation starts in M58.3. */
  readonly one_click_available:        false;
  readonly one_click_status:           "not_supported_yet";
  /** Always false — M58.1 is read-only guidance. */
  readonly requires_write_permissions: false;
  readonly provider_console_hint:      string;
}

export interface RemediationNotAvailable {
  readonly available: false;
}

export type RemediationResult = RemediationGuidance | RemediationNotAvailable;

// ── Input type ────────────────────────────────────────────────────────────────
// Subset of ChangeListItem / ChangeDetail — works for both contexts.

export interface ChangeInput {
  change_type:       string;
  record_identifier: string;
  field_path:        string | null;
  prev_value:        unknown;
  new_value:         unknown;
  risk_level:        string;
  risk_reason:       string | null;
  provider_metadata: Record<string, unknown> | null;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const NA: RemediationNotAvailable = { available: false };

/** Steps shown at the end of every remediation: re-sync + verify. */
const STANDARD_VALIDATION: string[] = [
  "Run a ConfigTrace sync again.",
  "Confirm the change no longer appears as a high-risk or critical finding.",
  "Verify the expected security configuration is in place.",
];

// ── Builder helper ────────────────────────────────────────────────────────────
// Adds the fixed M58.1 readonly fields so playbook definitions stay clean.

type PlaybookCore = Omit<
  RemediationGuidance,
  | "available"
  | "fix_command_available"
  | "one_click_available"
  | "one_click_status"
  | "requires_write_permissions"
>;

function _guidance(core: PlaybookCore): RemediationGuidance {
  return {
    ...core,
    available:                  true,
    fix_command_available:      false,
    one_click_available:        false,
    one_click_status:           "not_supported_yet",
    requires_write_permissions: false,
  };
}

// ── Main entry point ──────────────────────────────────────────────────────────

/**
 * Return structured remediation guidance for a risky configuration change.
 *
 * Returns `{ available: false }` when:
 *   - The change is low or unknown risk (noise/informational changes).
 *   - No matching playbook exists for this record type / field path.
 *
 * The caller is responsible for rendering the guidance as read-only
 * text — ConfigTrace never applies these steps automatically.
 */
export function getRemediationGuidance(change: ChangeInput): RemediationResult {
  const pm = change.provider_metadata ?? {};
  const rt = ((pm["record_type"] as string) ?? "").toLowerCase();
  const fp = (change.field_path ?? "").toLowerCase();
  const ct = change.change_type.toLowerCase();
  const rl = change.risk_level.toLowerCase();
  const rr = (change.risk_reason ?? "").toLowerCase();
  // new_value used only for boolean/numeric trigger logic — never forwarded as text.
  const nv = change.new_value;

  // Guidance is only meaningful for medium-and-above risk.
  if (rl === "low" || rl === "unknown") return NA;

  return (
    _awsPlaybooks(rt, fp, ct, rl, rr, nv)         ??
    _cloudflarePlaybooks(rt, fp, ct, rl, rr, nv)  ??
    _firebasePlaybooks(rt, fp, ct, rl, rr, nv)    ??
    _supabasePlaybooks(rt, fp, ct, rl, rr, nv)    ??
    _githubPlaybooks(rt, fp, ct, rl, rr, nv)      ??
    _stripePlaybooks(rt, fp, ct, rl, rr, nv)      ??
    _vercelPlaybooks(rt, fp, ct, rl, rr, nv)      ??
    _shopifyPlaybooks(rt, fp, ct, rl, rr, nv)     ??
    NA
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Playbook 1 — AWS
// ─────────────────────────────────────────────────────────────────────────────

function _awsPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {

  // 1a. Security group: public administrative port access
  if (rt === "aws_security_group_rule" || rt === "aws_security_group") {
    if (rl === "critical" || rl === "high") {
      const isPublicAdmin =
        rr.includes("public") && (
          rr.includes("ssh")     || rr.includes("rdp")     ||
          rr.includes("admin")   || rr.includes("port 22") ||
          rr.includes("0.0.0.0") || rr.includes("::/0")    ||
          rr.includes("ingress")
        );
      if (isPublicAdmin || ct === "added") {
        return _guidance({
          confidence: rl === "critical" ? "high" : "medium",
          title:   "Restrict public administrative port access",
          summary: "Remove or narrow the inbound rule permitting public internet access (0.0.0.0/0 or ::/0) to administrative ports such as SSH (22), RDP (3389), or database ports.",
          why_this_helps:
            "Security groups are the primary network firewall for EC2 instances and related resources. Leaving administrative ports open to 0.0.0.0/0 or ::/0 exposes the service to the entire internet. Automated scanners continuously probe these ports for brute-force login and known-vulnerability exploits. Restricting access to a trusted CIDR (corporate VPN, bastion host, or office IP range) eliminates the internet-facing attack surface for admin protocols.",
          verify_first: [
            "Identify all resources currently attached to this security group (EC2 instances, RDS, ECS tasks, load balancers).",
            "Confirm an alternative admin access path exists before removing the rule — AWS Systems Manager Session Manager, a VPN, or a dedicated bastion host.",
            "Check whether this rule was added intentionally (e.g. emergency incident response, temporary maintenance window).",
            "Confirm the security group is not shared across resources that legitimately need different access levels.",
            "Review AWS CloudTrail for the IAM principal that added this rule and when.",
          ],
          manual_steps: [
            "Open the AWS EC2 console → Security Groups.",
            "Locate the affected security group by name or group ID (shown in the change record).",
            "Select Inbound rules → Edit inbound rules.",
            "Remove the rule allowing 0.0.0.0/0 or ::/0 on the admin port, or change the CIDR to your trusted VPN, bastion, or office IP range.",
            "Save the inbound rule changes.",
            "Verify admin access still works through the permitted path (e.g. SSM Session Manager, VPN, bastion) before ending the session.",
          ],
          validation_steps: STANDARD_VALIDATION,
          caveats: [
            "Removing the only SSH/RDP rule without a verified alternative path will lock you out of the instance immediately.",
            "If this instance serves as a bastion host for other systems, ensure a replacement access path is in place first.",
            "Changes take effect immediately — test connectivity through the intended access method before closing the current admin session.",
            "If the rule is on a shared security group, the change affects all attached resources.",
          ],
          docs_links: [
            { label: "AWS Security Groups",                    url: "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html" },
            { label: "AWS Systems Manager Session Manager",    url: "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html" },
          ],
          provider_console_hint:
            "AWS Console → EC2 → Security Groups → [group name/ID] → Inbound rules → Edit inbound rules.",
        });
      }
    }
  }

  // 1b. CloudFront: HTTPS policy or WAF weakened
  if (rt === "aws_cloudfront_distribution" && (rl === "critical" || rl === "high")) {
    return _guidance({
      confidence: "medium",
      title:   "Restore CloudFront HTTPS enforcement and WAF coverage",
      summary: "Re-enable HTTPS-only viewer protocol policy, restore the WAF Web ACL association, and re-enable access logging if they were disabled or weakened.",
      why_this_helps:
        "CloudFront is the edge entry point for your application. Weakening the viewer protocol policy (e.g. allowing HTTP) exposes users to downgrade attacks and plain-text credential interception. Detaching a WAF Web ACL removes rate-limiting, bot protection, and managed rule groups. Disabling access logs removes forensic visibility for security incidents.",
      verify_first: [
        "Confirm the protocol or WAF change was not part of a planned migration or A/B test.",
        "Identify all origins and behaviours the distribution serves — weaker protocol on a non-sensitive path may be acceptable.",
        "Check whether any downstream service depends on plain HTTP delivery (rare but possible).",
        "Review CloudTrail for who made the change and whether it aligns with a deployment event.",
      ],
      manual_steps: [
        "Open the AWS CloudFront console → Distributions → [affected distribution].",
        "Under Behaviours, select the affected path pattern → Edit.",
        "Set Viewer Protocol Policy to 'Redirect HTTP to HTTPS' or 'HTTPS Only'.",
        "Under Security, confirm a WAF Web ACL is associated. If missing, attach the appropriate Web ACL.",
        "Under General → Settings, confirm Standard logging is enabled.",
        "Save and deploy the distribution changes.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Enforcing HTTPS-only will break any clients or integrations that use plain HTTP.",
        "Reattaching a WAF Web ACL may introduce rate-limiting that affects legitimate high-traffic paths.",
        "CloudFront distribution changes take a few minutes to propagate globally.",
      ],
      docs_links: [
        { label: "CloudFront viewer protocol policies", url: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesViewerProtocolPolicy" },
        { label: "CloudFront WAF integration",          url: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html" },
      ],
      provider_console_hint:
        "AWS Console → CloudFront → Distributions → [ID] → Behaviours + General tab.",
    });
  }

  // 1c. WAFv2 Web ACL removed or weakened
  if (
    (rt === "aws_wafv2_web_acl" || rt === "aws_wafv2_web_acl_association") &&
    (rl === "critical" || rl === "high" || ct === "removed")
  ) {
    return _guidance({
      confidence: ct === "removed" ? "high" : "medium",
      title:   "Restore WAFv2 Web ACL rules and associations",
      summary: "Re-enable or restore the WAFv2 Web ACL, its managed rule groups, and any associations with CloudFront distributions, API Gateways, or Application Load Balancers.",
      why_this_helps:
        "WAFv2 Web ACLs protect web applications from common exploits such as SQL injection, cross-site scripting, and automated bot attacks. Removing or weakening a Web ACL—especially by disabling managed rule groups—eliminates protection across all associated resources simultaneously. A missing ACL-to-resource association means the resource receives unfiltered traffic.",
      verify_first: [
        "Confirm the rule group removal or ACL disassociation was intentional and approved.",
        "Identify all resources (CloudFront, API Gateway, ALB) the ACL was protecting.",
        "Check whether a replacement or updated ACL is being deployed in parallel.",
        "Review CloudTrail and AWS Config for the timeline of changes.",
      ],
      manual_steps: [
        "Open the AWS WAF & Shield console → Web ACLs.",
        "Select the affected Web ACL.",
        "Review Rules — add back any removed managed rule groups (e.g. AWSManagedRulesCommonRuleSet).",
        "Go to Associated AWS resources — add back removed CloudFront, API Gateway, or ALB associations.",
        "Save changes and verify rule counts match the expected baseline.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Re-adding overly broad managed rule groups may block legitimate traffic. Test in count mode first.",
        "Associating an ACL with a CloudFront distribution takes a few minutes to propagate.",
      ],
      docs_links: [
        { label: "AWS WAFv2 managed rule groups", url: "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html" },
      ],
      provider_console_hint:
        "AWS Console → WAF & Shield → Web ACLs → [ACL name] → Rules + Associated AWS resources.",
    });
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Playbook 2 — Cloudflare
// ─────────────────────────────────────────────────────────────────────────────

function _cloudflarePlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {

  if (rt === "cloudflare_ruleset") {
    if (rl === "critical" || rl === "high" || ct === "removed") {
      const weakened =
        fp === "enabled_rule_count" || fp === "block_count" ||
        fp === "skip_count"         || fp === "active"       ||
        ct === "removed";

      if (weakened || rl === "critical" || rl === "high") {
        return _guidance({
          confidence: ct === "removed" ? "high" : "medium",
          title:   "Re-enable WAF ruleset and restore rule coverage",
          summary: "Restore disabled WAF rules, re-enable the ruleset, or remove unintended skip/bypass rules that reduced protection coverage.",
          why_this_helps:
            "Cloudflare WAF rulesets are the primary application-layer defence for your zone. Disabling managed rules, removing block actions, or increasing skip/bypass counts means malicious requests (SQL injection, XSS, credential stuffing, bot attacks) may pass through unfiltered. Even a temporary ruleset disable during a deployment can leave the zone unprotected if not restored.",
          verify_first: [
            "Confirm the ruleset change was part of a planned deployment, security-policy update, or emergency bypass.",
            "Check whether skip/bypass rules are scoped narrowly (specific URI paths or IP ranges) rather than globally.",
            "Confirm no legitimate traffic is being blocked by the rules you intend to restore.",
            "Review Cloudflare audit logs for who made the change.",
          ],
          manual_steps: [
            "Log into the Cloudflare dashboard → select your account → choose the affected zone.",
            "Navigate to Security → WAF → Custom rules (or Managed rules).",
            "Re-enable any disabled managed rule groups or custom rules.",
            "Review and remove or narrow any skip rules that bypass protection broadly.",
            "If the ruleset was deleted, re-create it from the Cloudflare managed ruleset library.",
            "Save changes and monitor Security → Overview for traffic patterns.",
          ],
          validation_steps: STANDARD_VALIDATION,
          caveats: [
            "Re-enabling aggressive managed rules may block legitimate API traffic — monitor carefully in the first hour.",
            "Removing skip rules may reintroduce false positives that were previously bypassed for a reason.",
          ],
          docs_links: [
            { label: "Cloudflare WAF managed rules",  url: "https://developers.cloudflare.com/waf/managed-rules/" },
            { label: "Cloudflare ruleset engine",     url: "https://developers.cloudflare.com/ruleset-engine/" },
          ],
          provider_console_hint:
            "Cloudflare Dashboard → [zone] → Security → WAF → Managed rules / Custom rules.",
        });
      }
    }
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Playbook 3 — Firebase
// ─────────────────────────────────────────────────────────────────────────────

function _firebasePlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {

  // 3a. Firestore or Storage ruleset: public write enabled
  if (
    (rt === "firebase_firestore_ruleset" || rt === "firebase_storage_ruleset") &&
    fp === "public_write_detected" && nv === true
  ) {
    const surface = rt.includes("storage") ? "Storage" : "Firestore";
    return _guidance({
      confidence: "high",
      title:   `Remove public write access from Firebase ${surface} rules`,
      summary: `Restrict Firestore or Cloud Storage security rules so that unauthenticated (public) write access is not permitted on any path.`,
      why_this_helps:
        `Firebase security rules are the sole data-access control layer for Firestore and Cloud Storage when accessed from client SDKs. A rule that permits \`allow write: if true;\` or \`allow write: if request.auth == null;\` on any path exposes your database or storage bucket to unauthenticated writes from the internet. This can result in data injection, spam, storage exhaustion, or overwriting production documents.`,
      verify_first: [
        `Identify which Firestore collection paths or Storage bucket paths have the public write rule.`,
        `Confirm whether any app feature legitimately requires unauthenticated writes (e.g. a public feedback form) — if so, scope the rule to a specific path and rate-limit via App Check.`,
        `Confirm you are reviewing the correct Firebase project (production vs staging).`,
        `Test the rollback in a staging environment before applying to production if possible.`,
      ],
      manual_steps: [
        `Open the Firebase Console → select the affected project.`,
        `Navigate to ${surface} (Firestore Database or Storage) → Rules tab.`,
        `Find the rule that permits public writes (e.g. \`allow write: if true;\` or an unauthenticated condition).`,
        `Replace with an authenticated condition: \`allow write: if request.auth != null;\` or a more specific claim check.`,
        `Use the Rules Playground to test the updated rules against expected client requests.`,
        `Publish the updated rules.`,
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        `Tightening rules without reviewing all app code paths can break legitimate client writes.`,
        `Rules changes take effect immediately — have a rollback plan ready.`,
        `If App Check is not yet enforced, authenticated rules alone provide weaker protection than authenticated + App Check together.`,
      ],
      docs_links: [
        { label: `Firebase ${surface} security rules`,  url: `https://firebase.google.com/docs/rules` },
        { label: "Firebase Rules Playground",           url: "https://firebase.google.com/docs/rules/simulator" },
      ],
      provider_console_hint:
        `Firebase Console → [project] → ${surface} → Rules.`,
    });
  }

  // 3b. App Check: enforcement weakened
  if (rt === "firebase_app_check_config" && (rl === "critical" || rl === "high")) {
    const isWeakened =
      fp === "unenforced_count"      ||
      fp === "enabled_count"         ||
      fp === "enforcement_mode"      ||
      fp.includes("enforc");
    if (isWeakened || rl === "high" || rl === "critical") {
      return _guidance({
        confidence: "medium",
        title:   "Re-enable Firebase App Check enforcement",
        summary: "Restore App Check enforcement for Firebase services to prevent unauthorized or abusive client access.",
        why_this_helps:
          "Firebase App Check verifies that requests to Firebase services originate from your legitimate app — not scripts, emulators, or other clients. When enforcement is unenforced or disabled for a service (Firestore, Storage, Functions, etc.), any client can access it without attestation, bypassing the App Check layer entirely. This is especially important when security rules cannot otherwise distinguish legitimate app clients from automated abuse.",
        verify_first: [
          "Confirm which Firebase services (Firestore, Storage, Functions, etc.) had enforcement changed.",
          "Check the App Check rollout status — enforcement mode is typically ramped up gradually after registering providers.",
          "Ensure all app versions currently in production have App Check providers (Play Integrity, App Attest, reCAPTCHA) registered.",
          "Confirm this is the production project, not a development or emulator environment.",
        ],
        manual_steps: [
          "Open the Firebase Console → [project] → App Check.",
          "Review the enforcement status for each listed service.",
          "For services showing 'Unenforced', click Enforce to re-enable.",
          "Monitor App Check metrics for any legitimate app traffic that fails attestation before enforcing broadly.",
        ],
        validation_steps: STANDARD_VALIDATION,
        caveats: [
          "Enabling enforcement will block app versions without a registered App Check provider — ensure all production app versions are updated first.",
          "Debug tokens must be registered for development environments to continue working after enforcement is enabled.",
        ],
        docs_links: [
          { label: "Firebase App Check",              url: "https://firebase.google.com/docs/app-check" },
          { label: "App Check enforcement guidance",  url: "https://firebase.google.com/docs/app-check/manage-enforcement" },
        ],
        provider_console_hint:
          "Firebase Console → [project] → App Check → [service] → Enforce.",
      });
    }
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Playbook 4 — Supabase
// ─────────────────────────────────────────────────────────────────────────────

function _supabasePlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {

  // 4a. RLS disabled on a table
  if (
    rt === "supabase_database_table" &&
    fp === "rls_enabled" && nv === false
  ) {
    return _guidance({
      confidence: "high",
      title:   "Re-enable Row Level Security on this table",
      summary: "Turn Row Level Security back on for the affected table and verify that appropriate policies exist for the anon and authenticated roles.",
      why_this_helps:
        "Row Level Security (RLS) is Supabase's primary data isolation mechanism. When RLS is disabled on a table accessible via the public PostgREST API, any authenticated — or even anonymous — client can read and write all rows regardless of their identity. This effectively makes the table fully public to anyone with the project's anon key, which is embedded in every client application.",
      verify_first: [
        "Identify who disabled RLS and why — check the Supabase audit log.",
        "Confirm that at least one policy exists for the table that covers the access patterns your app uses (anon SELECT, authenticated INSERT/UPDATE, etc.). Enabling RLS without policies blocks all access.",
        "Confirm whether the table is accessed directly from client code via the Supabase JS/Python client (and therefore subject to anon key exposure) or only from trusted server-side code.",
        "Confirm this is the production project, not a development or staging environment.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Table Editor or Authentication → Policies.",
        "Select the affected table.",
        "Enable Row Level Security via the RLS toggle.",
        "Review and update policies to cover SELECT, INSERT, UPDATE, and DELETE as appropriate for the anon and authenticated roles.",
        "Test that legitimate app queries still succeed.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Re-enabling RLS without any policies will block all client access to the table — ensure policies are in place first.",
        "Service role keys bypass RLS by design — ensure server-side code uses the service role key only where intentional.",
      ],
      docs_links: [
        { label: "Supabase Row Level Security",         url: "https://supabase.com/docs/guides/database/postgres/row-level-security" },
        { label: "Supabase Auth and policies",          url: "https://supabase.com/docs/guides/auth" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Authentication → Policies → [table] → Enable RLS.",
    });
  }

  // 4b. Database policy removed
  if (rt === "supabase_database_policy" && ct === "removed" && (rl === "critical" || rl === "high")) {
    return _guidance({
      confidence: "medium",
      title:   "Restore the removed database access policy",
      summary: "Re-create the RLS policy that was removed to restore the intended access control for the affected table.",
      why_this_helps:
        "Supabase Row Level Security policies are the fine-grained access control layer for individual tables. Removing a policy expands access for the affected role — for example, removing a SELECT policy for the anon role can silently allow all anonymous reads on the table if RLS is still enabled but no restrictive policy remains.",
      verify_first: [
        "Identify which table and role the removed policy covered.",
        "Confirm whether other policies on the same table still cover the same access pattern.",
        "Review the Supabase audit log to confirm who removed the policy and when.",
        "Confirm the removal was not part of a schema migration that added a replacement policy.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Authentication → Policies.",
        "Select the affected table.",
        "Click 'New Policy' to re-create the removed policy.",
        "Define the appropriate USING expression for the role (anon, authenticated, or service_role).",
        "Save and test that the policy produces the expected access behaviour.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "If the policy was removed as part of a migration, check for a replacement before re-creating the original.",
        "An incorrect USING expression may inadvertently block legitimate access.",
      ],
      docs_links: [
        { label: "Supabase RLS policy guide",   url: "https://supabase.com/docs/guides/database/postgres/row-level-security" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Authentication → Policies → [table] → New Policy.",
    });
  }

  // 4c. Auth security settings weakened
  if (rt === "supabase_auth_config" && (rl === "critical" || rl === "high")) {
    const authWeakeningFields = new Set([
      "leaked_password_protection_enabled",
      "captcha_enabled",
      "refresh_token_rotation_enabled",
      "jwt_expiry",
      "redirect_uris_count",
    ]);
    if (authWeakeningFields.has(fp) || rl === "critical") {
      return _guidance({
        confidence: "medium",
        title:   "Restore auth security configuration",
        summary: "Re-enable weakened auth security settings such as leaked password protection, CAPTCHA, token rotation, or restrictive redirect URI policies.",
        why_this_helps:
          "Supabase auth security settings are layered defences against credential attacks and account takeover. Disabling leaked password protection allows users to set passwords that appear in known breach databases. Disabling CAPTCHA removes bot protection from sign-in and sign-up flows. Disabling token rotation allows refresh tokens to be reused indefinitely by an attacker who obtains one. Increasing redirect URIs broadens the attack surface for OAuth redirect hijacking.",
        verify_first: [
          "Confirm which auth setting was changed and whether the change was intentional.",
          "If JWT expiry was increased, confirm it was not to compensate for a session management bug.",
          "If redirect URIs were added, verify each added URI is an expected application domain.",
          "Confirm the change does not correspond to a planned auth migration or onboarding flow change.",
        ],
        manual_steps: [
          "Open the Supabase dashboard → [project] → Authentication → Providers / Settings.",
          "Review the auth configuration and restore the intended security settings.",
          "For leaked password protection: re-enable under Security settings.",
          "For token rotation: enable Refresh Token Rotation under Session settings.",
          "For redirect URIs: review the list and remove unexpected or overly broad entries.",
        ],
        validation_steps: STANDARD_VALIDATION,
        caveats: [
          "Re-enabling CAPTCHA requires the app to handle CAPTCHA tokens on sign-in/sign-up forms.",
          "Enabling refresh token rotation invalidates existing long-lived refresh tokens — users may need to re-authenticate.",
          "Removing redirect URIs may break OAuth flows for legitimate apps that depend on those URLs.",
        ],
        docs_links: [
          { label: "Supabase Auth configuration",    url: "https://supabase.com/docs/guides/auth" },
          { label: "Supabase security checklist",    url: "https://supabase.com/docs/guides/platform/going-into-prod" },
        ],
        provider_console_hint:
          "Supabase Dashboard → [project] → Authentication → Providers / Settings.",
      });
    }
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Playbook 5 — GitHub
// ─────────────────────────────────────────────────────────────────────────────

function _githubPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {

  if (
    (rt === "github_branch_protection" || rt === "github_environment_protection") &&
    (rl === "critical" || rl === "high")
  ) {
    const isBranch = rt === "github_branch_protection";
    const subject  = isBranch ? "branch protection" : "environment protection";

    return _guidance({
      confidence: rl === "critical" ? "high" : "medium",
      title:   `Restore ${subject} policy`,
      summary: `Re-enable required reviewers, required status checks, and prevent-self-review rules that were removed or weakened on this ${isBranch ? "branch" : "environment"}.`,
      why_this_helps: isBranch
        ? "Branch protection rules are the primary code review and quality gate for production branches. Reducing required reviewers, removing required status checks, or disabling prevent-self-review means code can be merged without peer review — including code introduced by a compromised developer account or a malicious pull request. For branches that deploy to production, this is a direct path to unauthorized deployments."
        : "Environment protection rules gate deployments to sensitive environments (production, staging) by requiring specific reviewers to approve before a deployment proceeds. Reducing reviewer counts or wait timers means deployments can run without the intended oversight, increasing the risk of unauthorized or accidental changes reaching production.",
      verify_first: [
        `Confirm the ${subject} change was intentional and approved by the team.`,
        `Review recent GitHub audit log entries for who changed the ${isBranch ? "branch" : "environment"} settings.`,
        `Identify any open pull requests or pending deployments that were unblocked by this change.`,
        `Confirm whether this ${isBranch ? "branch" : "environment"} is used for production deployments.`,
      ],
      manual_steps: [
        `Open the GitHub repository settings.`,
        isBranch
          ? "Navigate to Code and automation → Branches → Branch protection rules."
          : "Navigate to Environments → [affected environment] → Environment protection rules.",
        `Review the current protection settings and restore: required reviewers, required status checks, prevent-self-review, and dismiss stale reviews if applicable.`,
        `Save the updated protection rules.`,
        `Audit any pull requests or deployments that may have bypassed protection during the window it was weakened.`,
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Restoring required status checks may block pending pull requests that no longer pass those checks.",
        "If the change was intentional (e.g. a hotfix bypass during an incident), document it and restore the rules promptly.",
        "Required reviewers must be current team members — update the reviewer list if team membership has changed.",
      ],
      docs_links: isBranch
        ? [
            { label: "GitHub branch protection rules",        url: "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches" },
          ]
        : [
            { label: "GitHub environment protection rules",   url: "https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment" },
          ],
      provider_console_hint: isBranch
        ? "GitHub → [repo] → Settings → Branches → Branch protection rules."
        : "GitHub → [repo] → Settings → Environments → [environment] → Protection rules.",
    });
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Playbook 6 — Stripe
// ─────────────────────────────────────────────────────────────────────────────

function _stripePlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {

  // 6a. Webhook endpoint removed, disabled, or URL changed
  if (rt === "stripe_webhook_endpoint" && (rl === "high" || rl === "critical")) {
    return _guidance({
      confidence: ct === "removed" ? "high" : "medium",
      title:   "Restore Stripe webhook endpoint",
      summary: "Re-create or re-enable the webhook endpoint and verify it is receiving the expected events for payment, subscription, and fulfilment flows.",
      why_this_helps:
        "Stripe webhooks are the event-delivery mechanism for critical payment and subscription lifecycle events (payment_intent.succeeded, invoice.payment_failed, customer.subscription.updated, etc.). If the endpoint is removed, disabled, or its URL is changed to an unexpected destination, your application will silently miss payment events, potentially resulting in unprocessed orders, missed subscription renewals, or failed payment recovery flows. In a worst case, webhook events may be redirected to an attacker-controlled URL.",
      verify_first: [
        "Confirm whether the endpoint was removed as part of a planned migration or decommission.",
        "If the URL was changed, confirm the new URL is an expected application domain under your control.",
        "Check Stripe Dashboard → Developers → Webhooks → Event deliveries for recent failed deliveries that may need replaying.",
        "Confirm the endpoint is correctly handling live vs test mode events.",
      ],
      manual_steps: [
        "Open the Stripe Dashboard → Developers → Webhooks.",
        "If the endpoint was deleted: click 'Add endpoint' and recreate it with the correct URL and event subscriptions.",
        "If the endpoint was disabled: select the endpoint and click 'Enable'.",
        "If the URL was changed unexpectedly: update it back to the expected value.",
        "Send a test webhook event from the Stripe dashboard to confirm the endpoint is healthy.",
        "Review recent event delivery failures and replay any events that were missed during the outage window.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Replaying missed events must be done carefully to avoid processing the same payment or subscription event twice — implement idempotency keys in your handler.",
        "If the endpoint URL was changed by an attacker, rotate the webhook signing secret after restoring the endpoint.",
      ],
      docs_links: [
        { label: "Stripe webhooks guide",             url: "https://stripe.com/docs/webhooks" },
        { label: "Stripe webhook event delivery",     url: "https://stripe.com/docs/webhooks/best-practices" },
      ],
      provider_console_hint:
        "Stripe Dashboard → Developers → Webhooks → [endpoint] → Enable / Edit.",
    });
  }

  // 6b. Billing portal configuration weakened
  if (rt === "stripe_billing_portal_config" && (rl === "high" || rl === "critical")) {
    return _guidance({
      confidence: "medium",
      title:   "Review Stripe billing portal configuration changes",
      summary: "Confirm the billing portal feature changes were intentional and restore any disabled payment method update or subscription management capabilities if needed.",
      why_this_helps:
        "The Stripe billing portal is the customer self-service interface for managing subscriptions, updating payment methods, and downloading invoices. Disabling or restricting portal features without a business reason can prevent customers from updating expired cards, cancelling subscriptions through proper channels, or managing their own account — leading to involuntary churn and support escalations.",
      verify_first: [
        "Confirm whether the billing portal change was part of a planned pricing or subscription model update.",
        "Review the Stripe billing portal configuration to understand which features were enabled vs disabled.",
        "Confirm the change does not affect active subscription flows for current customers.",
      ],
      manual_steps: [
        "Open the Stripe Dashboard → Settings → Billing → Customer portal.",
        "Review the enabled features list.",
        "Re-enable Payment method update, Subscription cancellation, or other features that were disabled unexpectedly.",
        "Save the updated portal configuration.",
        "Test the customer portal using Stripe's 'Preview' feature with a test customer.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Billing portal changes affect all customers using the portal link — test in Stripe test mode before applying to live.",
        "Some features (like subscription pausing) require specific Stripe plan features — confirm eligibility.",
      ],
      docs_links: [
        { label: "Stripe customer portal",    url: "https://stripe.com/docs/billing/subscriptions/customer-portal" },
      ],
      provider_console_hint:
        "Stripe Dashboard → Settings → Billing → Customer portal.",
    });
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Playbook 7 — Vercel
// ─────────────────────────────────────────────────────────────────────────────

function _vercelPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {

  // 7a. Deploy hook added, removed, or ref changed
  if (rt === "vercel_deploy_hook_metadata" && (rl === "high" || rl === "critical")) {
    return _guidance({
      confidence: ct === "added" ? "medium" : rl === "critical" ? "high" : "medium",
      title:   "Review and secure Vercel deploy hook",
      summary: ct === "added"
        ? "Verify the newly added deploy hook is expected, owned by your team, and scoped to the correct branch/ref."
        : "Restore or review the removed deploy hook and confirm no unexpected deploy triggers were added.",
      why_this_helps:
        "Vercel deploy hooks are HTTPS endpoints that trigger a new deployment when called. An unexpected deploy hook can allow an external actor to trigger production deployments on demand — without GitHub push access — by simply calling the hook URL. A removed hook may break a CI/CD pipeline or cron-based deployment flow. A hook with a changed ref may deploy from an unexpected branch, potentially shipping unreviewed code to production.",
      verify_first: [
        "Identify who created, modified, or removed the deploy hook — check Vercel audit logs.",
        "Confirm the hook's target branch/ref is the expected production or deployment branch.",
        "Verify the hook URL has not been shared or exposed in public repositories, CI logs, or client-side code.",
        "Confirm the hook is owned by a team member and created for a known, approved integration (e.g. a cron job, CMS trigger, or CI pipeline).",
      ],
      manual_steps: [
        "Open the Vercel dashboard → [project] → Settings → Git → Deploy Hooks.",
        "Review the list of hooks and confirm each is expected.",
        "For unexpected hooks: click the delete icon to remove them.",
        "For hooks with changed refs: update the ref to the correct branch.",
        "If a legitimate hook was removed: click 'Create Hook' and recreate it with the correct name, branch, and ref.",
        "If a hook URL may have been exposed: delete and recreate the hook to generate a new secret URL.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Deleting a deploy hook immediately breaks any integration that depends on the hook URL.",
        "Deploy hook URLs are secrets — treat them like API keys and store them in environment variables or a secrets manager.",
      ],
      docs_links: [
        { label: "Vercel deploy hooks",    url: "https://vercel.com/docs/deployments/deploy-hooks" },
      ],
      provider_console_hint:
        "Vercel Dashboard → [project] → Settings → Git → Deploy Hooks.",
    });
  }

  // 7b. Project: deployment protection or production branch changed
  if (rt === "vercel_project" && (rl === "high" || rl === "critical")) {
    const isProtection = fp.includes("protection") || fp.includes("deployment");
    const isBranch     = fp === "production_branch";

    if (isProtection || isBranch || rl === "critical") {
      return _guidance({
        confidence: "medium",
        title:   "Restore Vercel deployment protection settings",
        summary: "Re-enable deployment protection or restore the production branch to its expected value to prevent unauthorized preview or production deployments.",
        why_this_helps:
          "Vercel deployment protection gates who can trigger and access deployments. Disabling protection allows anyone with the deployment URL to access previews or trigger production deployments without authentication. Changing the production branch without a corresponding code change may deploy a different branch's code to the production domain, overwriting the intended release.",
        verify_first: [
          "Confirm the protection or branch change was part of an approved deployment process update.",
          "Identify the current production branch and confirm it matches the team's release convention.",
          "Check Vercel audit logs for who made the change and when.",
        ],
        manual_steps: [
          "Open the Vercel dashboard → [project] → Settings → General.",
          "Review the Production Branch setting and restore if changed unexpectedly.",
          "Navigate to Settings → Deployment Protection to re-enable password protection or Vercel Authentication.",
          "Save changes and verify the next deployment uses the correct branch.",
        ],
        validation_steps: STANDARD_VALIDATION,
        caveats: [
          "Re-enabling deployment protection may block automated CI/CD jobs that access deployment URLs — add bypass tokens if needed.",
          "Changing the production branch triggers a redeployment from the new branch head.",
        ],
        docs_links: [
          { label: "Vercel deployment protection",   url: "https://vercel.com/docs/security/deployment-protection" },
        ],
        provider_console_hint:
          "Vercel Dashboard → [project] → Settings → General / Deployment Protection.",
      });
    }
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Playbook 8 — Shopify
// ─────────────────────────────────────────────────────────────────────────────

function _shopifyPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {

  // 8a. App scope summary: sensitive or write scopes increased
  if (rt === "shopify_app_scope_summary" && (rl === "critical" || rl === "high")) {
    return _guidance({
      confidence: "high",
      title:   "Review and revoke unexpected Shopify app permission scopes",
      summary: "Investigate which installed app gained new sensitive or write-access scopes (customer, order, payment data) and revoke permissions for any app that should not have them.",
      why_this_helps:
        "Shopify app permission scopes define what store data each installed app can read and write. An increase in write scopes or the appearance of customer, order, or payment data scopes means an app has gained elevated access to sensitive store and customer information. If this was not intentional — caused by an app update, a new app installation, or compromised OAuth flow — it represents a direct data exposure risk for your customers.",
      verify_first: [
        "Identify which app's scope changed by checking Shopify Admin → Apps → [app name] → Permissions.",
        "Confirm whether the scope change corresponds to a known app update or a new app installation.",
        "Verify the app is a trusted, legitimate integration from a known developer.",
        "Confirm whether your business actually requires the app to have the new scopes.",
      ],
      manual_steps: [
        "Open Shopify Admin → Apps.",
        "Find the app with the expanded scopes.",
        "Review the listed permissions under the app's detail page.",
        "If the scopes are not required: uninstall the app and reinstall with only the necessary permissions, or contact the app developer to request a reduced scope.",
        "If the app is unknown or unexpected: uninstall it immediately.",
        "After resolving, review the Shopify Partner Dashboard or app listings for recent scope change notifications.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Uninstalling an app may break integrations that depend on it — confirm with your team before uninstalling.",
        "Some apps require broad scopes by design — confirm the scope is genuinely unexpected before acting.",
      ],
      docs_links: [
        { label: "Shopify app permissions",      url: "https://shopify.dev/docs/apps/auth/admin-app-access-tokens/scopes" },
        { label: "Shopify API access scopes",    url: "https://shopify.dev/docs/api/usage/access-scopes" },
      ],
      provider_console_hint:
        "Shopify Admin → Apps → [app name] → View permissions / Uninstall.",
    });
  }

  // 8b. Webhook subscription removed or endpoint changed
  if (rt === "shopify_webhook_subscription" && (rl === "high" || rl === "critical")) {
    return _guidance({
      confidence: ct === "removed" ? "high" : "medium",
      title:   "Restore or review Shopify webhook subscription",
      summary: ct === "removed"
        ? "Re-create the removed webhook subscription to restore event delivery for order, fulfilment, or payment events."
        : "Verify the webhook endpoint change was intentional and that the new endpoint is HTTPS and under your control.",
      why_this_helps:
        "Shopify webhooks deliver real-time event notifications for orders, fulfilment, payments, inventory, and customer data. A removed or re-routed webhook can cause silent failures in order processing, inventory sync, or payment confirmation. If a webhook endpoint URL was changed to a domain not under your control, event payloads containing order and customer data may be delivered to an unintended recipient.",
      verify_first: [
        "Confirm whether the webhook change was part of a planned endpoint migration.",
        "Verify the current (or new) webhook endpoint domain is owned by your team.",
        "Check whether order or fulfilment processing is functioning normally following the change.",
        "Confirm the endpoint uses HTTPS — Shopify requires HTTPS for all webhook endpoints.",
      ],
      manual_steps: [
        "Open Shopify Admin → Settings → Notifications → Webhooks (or via Shopify Admin API).",
        "Review the list of active webhooks.",
        "If a webhook was removed: re-create it with the correct topic and endpoint URL.",
        "If the endpoint URL changed unexpectedly: update it back to the correct URL.",
        "Use Shopify's 'Send test notification' feature to verify the endpoint is receiving events.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Webhook payloads contain order and customer data — ensure the endpoint has appropriate authentication (HMAC verification using the shared secret).",
        "Re-creating a webhook assigns a new webhook ID and a new shared secret — update your verification code accordingly.",
      ],
      docs_links: [
        { label: "Shopify webhooks overview",      url: "https://shopify.dev/docs/apps/build/webhooks" },
        { label: "Shopify webhook verification",   url: "https://shopify.dev/docs/apps/build/webhooks/delivery/https#verify-the-webhook" },
      ],
      provider_console_hint:
        "Shopify Admin → Settings → Notifications → Webhooks.",
    });
  }

  // 8c. Store policy removed
  if (rt === "shopify_store_policy" && ct === "removed" && (rl === "high" || rl === "medium")) {
    return _guidance({
      confidence: "medium",
      title:   "Restore removed Shopify store policy",
      summary: "Re-publish the removed store policy (privacy, refund, or terms of service) to maintain legal compliance and customer trust.",
      why_this_helps:
        "Shopify store policies (Privacy Policy, Refund Policy, Terms of Service, and Shipping Policy) are legally required disclosures in most jurisdictions and are displayed in your store's footer and checkout. Removing a policy means customers can no longer access these disclosures during or after checkout — potentially violating consumer protection laws and payment processor requirements.",
      verify_first: [
        "Confirm whether the policy removal was intentional (e.g. a policy rewrite in progress).",
        "Check whether a replacement policy was published at the same time.",
        "Confirm the store is operating in a jurisdiction where this policy is legally required.",
      ],
      manual_steps: [
        "Open Shopify Admin → Settings → Policies.",
        "Find the removed policy type (Privacy, Refund, Terms, or Shipping).",
        "Restore from the previous version or use Shopify's policy generator templates.",
        "Publish the policy and confirm it appears in the store footer and at checkout.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Policies should be reviewed by legal counsel for your jurisdiction before publishing.",
        "Shopify generated templates are starting points only — customise them for your specific business model.",
      ],
      docs_links: [
        { label: "Shopify store policies",    url: "https://help.shopify.com/en/manual/checkout-settings/refund-privacy-tos" },
      ],
      provider_console_hint:
        "Shopify Admin → Settings → Policies.",
    });
  }

  return null;
}
