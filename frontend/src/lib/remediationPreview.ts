/**
 * Remediation Preview / Dry Run framework — M58.3.
 *
 * Generates non-executing, preview-only remediation plans with before/after
 * state, required permissions, confirmation phrases, and validation steps.
 *
 * CRITICAL constraints (must remain in effect permanently):
 *   - execution_enabled is ALWAYS false. ConfigTrace never applies changes.
 *   - mode is ALWAYS "dry_run_only".
 *   - This module never calls provider APIs or mutates any resources.
 *   - No provider write actions, no one-click fixes, no backend jobs.
 *
 * Data safety:
 *   - before/after values are derived from field_path, risk_reason, and
 *     record_type — never from raw prev_value/new_value strings.
 *   - record_identifier is used only for structural pattern matching
 *     (e.g. safe table name regex); never forwarded as raw text.
 *   - provider_console_url only uses safe generic console URLs — no
 *     resource-specific identifiers or sensitive IDs.
 */

import type {
  ChangeInput,
  RemediationResult,
  FixPlanResult,
} from "@/lib/remediation";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface BeforeAfterItem {
  label: string;
  value: string;
}

export interface RemediationPreview {
  readonly available: true;
  readonly mode: "dry_run_only";
  readonly title: string;
  readonly summary: string;
  readonly before: BeforeAfterItem[];
  readonly after: BeforeAfterItem[];
  readonly preview_kind: "exact" | "conceptual";
  readonly confirmation_phrase: string;
  readonly execution_enabled: false;
  readonly would_create_audit_event: true;
  readonly required_permissions: string[];
  readonly warnings: string[];
  readonly preconditions: string[];
  readonly validation_steps: string[];
  readonly provider_console_url: string | null;
}

export interface RemediationPreviewNotAvailable {
  readonly available: false;
}

export type RemediationPreviewResult = RemediationPreview | RemediationPreviewNotAvailable;

// ── Constants ─────────────────────────────────────────────────────────────────

const NA: RemediationPreviewResult = { available: false };

const STANDARD_VALIDATION: string[] = [
  "Run a ConfigTrace sync again.",
  "Confirm the change no longer appears as a high-risk or critical finding.",
  "Verify the expected security configuration is in place.",
];

// ── Builder helper ────────────────────────────────────────────────────────────

type PreviewCore = Omit<
  RemediationPreview,
  "available" | "execution_enabled" | "would_create_audit_event" | "mode"
>;

function _preview(core: PreviewCore): RemediationPreview {
  return {
    ...core,
    available: true,
    execution_enabled: false,
    would_create_audit_event: true,
    mode: "dry_run_only",
  };
}

// ── Value extraction helpers ──────────────────────────────────────────────────

/**
 * Extract table identifier from record_identifier for Supabase RLS changes.
 * Accepts "schema.table" or bare "table" patterns; returns null otherwise.
 * Safe: only returns values that match a structural pattern.
 */
function _extractTableId(recordId: string): string | null {
  const t = recordId.trim();
  if (/^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?$/i.test(t) && t.length < 128) return t;
  return null;
}

// ── Generator 1: AWS Security Group — public SSH (port 22) ───────────────────

function _awsSgSshPreview(
  _change: ChangeInput, rt: string, fp: string,
  _ct: string, rl: string, rr: string,
): RemediationPreview | null {
  if (rt !== "aws_security_group") return null;
  if (!(
    fp === "has_public_ssh" ||
    rr.includes("ssh")      ||
    rr.includes("port 22")  ||
    rr.includes("tcp/22")
  )) return null;
  if (rl !== "critical" && rl !== "high") return null;

  return _preview({
    title: "Remove public SSH ingress rule",
    summary:
      "This preview shows the expected before and after state for removing the publicly accessible TCP/22 (SSH) ingress rule from the affected security group. ConfigTrace does not apply this change.",
    before: [
      { label: "Ingress rule (IPv4)", value: "TCP/22 from 0.0.0.0/0 — unrestricted public access" },
      { label: "Ingress rule (IPv6)", value: "TCP/22 from ::/0 — unrestricted public access (if present)" },
    ],
    after: [
      { label: "Ingress rule (IPv4)", value: "TCP/22 rule removed or restricted to a trusted CIDR block" },
      { label: "Ingress rule (IPv6)", value: "TCP/22 ::/0 rule removed (if it existed)" },
    ],
    preview_kind: "exact",
    confirmation_phrase: "REMOVE SSH",
    required_permissions: [
      "ec2:RevokeSecurityGroupIngress",
      "ec2:DescribeSecurityGroups",
    ],
    warnings: [
      "Removing this rule will block all direct SSH access from public IPs.",
      "Confirm a secure alternative access path (VPN, bastion host, or AWS SSM Session Manager) exists before applying.",
    ],
    preconditions: [
      "Verify an alternate SSH access path exists (VPN, bastion, or SSM).",
      "Identify all EC2 instances using this security group.",
      "Confirm the change is intended for all attached instances.",
    ],
    validation_steps: [
      "Open the security group in the AWS EC2 console and confirm TCP/22 from 0.0.0.0/0 no longer appears in inbound rules.",
      "Test SSH from a trusted IP to confirm access still works via the alternate path.",
      ...STANDARD_VALIDATION,
    ],
    provider_console_url: "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups",
  });
}

// ── Generator 2: AWS Security Group — public RDP (port 3389) ─────────────────

function _awsSgRdpPreview(
  _change: ChangeInput, rt: string, fp: string,
  _ct: string, rl: string, rr: string,
): RemediationPreview | null {
  if (rt !== "aws_security_group") return null;
  if (!(
    fp === "has_public_rdp"   ||
    rr.includes("rdp")         ||
    rr.includes("port 3389")   ||
    rr.includes("tcp/3389")
  )) return null;
  if (rl !== "critical" && rl !== "high") return null;

  return _preview({
    title: "Remove public RDP ingress rule",
    summary:
      "This preview shows the expected before and after state for removing the publicly accessible TCP/3389 (RDP) ingress rule from the affected security group. ConfigTrace does not apply this change.",
    before: [
      { label: "Ingress rule (IPv4)", value: "TCP/3389 from 0.0.0.0/0 — unrestricted public access" },
      { label: "Ingress rule (IPv6)", value: "TCP/3389 from ::/0 — unrestricted public access (if present)" },
    ],
    after: [
      { label: "Ingress rule (IPv4)", value: "TCP/3389 rule removed or restricted to a trusted CIDR block" },
      { label: "Ingress rule (IPv6)", value: "TCP/3389 ::/0 rule removed (if it existed)" },
    ],
    preview_kind: "exact",
    confirmation_phrase: "REMOVE RDP",
    required_permissions: [
      "ec2:RevokeSecurityGroupIngress",
      "ec2:DescribeSecurityGroups",
    ],
    warnings: [
      "Removing this rule will block all direct RDP access from public IPs.",
      "Confirm a secure alternative access path (VPN, bastion, or AWS SSM Fleet Manager) exists before applying.",
    ],
    preconditions: [
      "Verify an alternate Windows remote access path exists (VPN, bastion, or SSM Fleet Manager).",
      "Identify all EC2 instances using this security group.",
      "Confirm the change is intended for all attached instances.",
    ],
    validation_steps: [
      "Open the security group in the AWS EC2 console and confirm TCP/3389 from 0.0.0.0/0 no longer appears in inbound rules.",
      "Test Windows remote access from a trusted IP to confirm access still works via the alternate path.",
      ...STANDARD_VALIDATION,
    ],
    provider_console_url: "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups",
  });
}

// ── Generator 3: GitHub branch protection weakened/removed ───────────────────

function _ghBranchProtectionPreview(
  _change: ChangeInput, rt: string, fp: string,
  ct: string, rl: string, _rr: string,
): RemediationPreview | null {
  if (rt !== "github_branch_protection") return null;
  if (rl !== "critical" && rl !== "high") return null;

  // Derive field-specific before/after from field_path
  const fpMap: Record<string, { before: string; after: string }> = {
    "required_pull_request_reviews.required_approving_review_count": {
      before: "Required approving reviews: 0 (or reduced below minimum)",
      after:  "Required approving reviews: 1 or more",
    },
    "required_pull_request_reviews.dismiss_stale_reviews": {
      before: "Dismiss stale reviews: disabled",
      after:  "Dismiss stale reviews: enabled",
    },
    "required_pull_request_reviews.require_code_owner_reviews": {
      before: "Code owner reviews required: disabled",
      after:  "Code owner reviews required: enabled",
    },
    "enforce_admins": {
      before: "Enforce admins: disabled — admins can bypass all protection rules",
      after:  "Enforce admins: enabled",
    },
    "allow_force_pushes": {
      before: "Force pushes: allowed — branch history can be rewritten",
      after:  "Force pushes: blocked",
    },
    "allow_deletions": {
      before: "Branch deletions: allowed",
      after:  "Branch deletions: blocked",
    },
    "required_status_checks": {
      before: "Required status checks: removed or weakened",
      after:  "Required status checks: restored",
    },
  };

  const mapped = fp ? fpMap[fp] : null;
  const isRemoved = ct === "removed" || ct === "field_removed";

  const beforeItems: BeforeAfterItem[] = mapped
    ? [{ label: "Setting", value: mapped.before }]
    : isRemoved
      ? [{ label: "Branch protection", value: "Rule removed — branch is now unprotected" }]
      : [{ label: "Branch protection", value: "Setting weakened (see change detail for specifics)" }];

  const afterItems: BeforeAfterItem[] = mapped
    ? [{ label: "Setting", value: mapped.after }]
    : [{ label: "Branch protection", value: "Rule restored to a secure baseline" }];

  return _preview({
    title: "Restore GitHub branch protection",
    summary:
      "This preview shows the expected security state after restoring the weakened or removed branch protection settings. Apply via GitHub repository Settings → Branches. ConfigTrace does not apply this change.",
    before: beforeItems,
    after: afterItems,
    preview_kind: "conceptual",
    confirmation_phrase: "RESTORE PROTECTION",
    required_permissions: [
      "GitHub: repository admin role",
      "GitHub API: repo administration scope (if applying via API or gh CLI)",
    ],
    warnings: [
      "Restoring required status checks will block open pull requests whose checks are not currently passing.",
      "If the branch was unprotected during a window, audit the git log for commits merged without review.",
      "A GitHub API PUT for branch protection requires a complete payload — partial payloads silently disable omitted settings.",
    ],
    preconditions: [
      "Identify which specific protection settings were weakened or removed.",
      "Confirm the correct required reviewer count and status check names for this branch.",
      "Review any commits merged to this branch while protection was weakened.",
    ],
    validation_steps: [
      "Open GitHub → repository → Settings → Branches and verify the protection rule is active with the expected settings.",
      "Create a test pull request and confirm it requires the expected reviews and status checks before merging.",
      ...STANDARD_VALIDATION,
    ],
    provider_console_url: "https://github.com",
  });
}

// ── Generator 4: Cloudflare DNS record removed ────────────────────────────────

function _cfDnsPreview(
  _change: ChangeInput, rt: string, fp: string,
  ct: string, rl: string, rr: string,
): RemediationPreview | null {
  if (rt !== "cloudflare_dns_record") return null;
  if (ct !== "removed" && !rr.includes("removed") && !rr.includes("missing")) return null;
  if (rl !== "critical" && rl !== "high") return null;

  const isEmailSecurity =
    fp === "spf"    || fp === "dmarc"  || fp === "dkim"  ||
    rr.includes("spf")   || rr.includes("dmarc") || rr.includes("dkim") ||
    rr.includes("mx")    || rr.includes("email");

  const recordLabel = isEmailSecurity
    ? (fp?.toUpperCase() ?? "Email security DNS record")
    : "DNS record";

  return _preview({
    title: `Restore removed ${recordLabel}`,
    summary:
      "This preview shows the expected state after restoring the removed DNS record. The record must be re-added manually in the Cloudflare dashboard. ConfigTrace does not apply this change.",
    before: [
      { label: "DNS record", value: `${recordLabel} was present in the zone` },
    ],
    after: [
      { label: "DNS record", value: `${recordLabel} restored with the correct type, content, and TTL` },
    ],
    preview_kind: "conceptual",
    confirmation_phrase: "RESTORE DNS",
    required_permissions: [
      "Cloudflare: Zone DNS edit permission",
      "Cloudflare API: Zone:Edit scope (if applying via API)",
    ],
    warnings: [
      "DNS changes propagate globally and can take up to 48 hours to fully resolve.",
      isEmailSecurity
        ? "Missing email security records (SPF/DMARC/DKIM) leave your domain open to email spoofing until restored."
        : "Removing DNS records can cause service disruptions for any hostname that was resolving to it.",
    ],
    preconditions: [
      "Retrieve the exact previous record configuration: type, name, content, TTL, and proxy status.",
      "Confirm the record was not intentionally deleted as part of a planned change.",
    ],
    validation_steps: [
      "Verify the record appears in the Cloudflare DNS dashboard for this zone.",
      "Use a DNS lookup tool (e.g., `dig` or MXToolbox) to confirm the record resolves correctly.",
      ...STANDARD_VALIDATION,
    ],
    provider_console_url: "https://dash.cloudflare.com",
  });
}

// ── Generator 5: Firebase security rules — permissive ────────────────────────

function _firebaseRulesPreview(
  _change: ChangeInput, rt: string, _fp: string,
  _ct: string, rl: string, _rr: string,
): RemediationPreview | null {
  if (rt !== "firebase_security_rules") return null;
  if (rl !== "critical" && rl !== "high") return null;

  return _preview({
    title: "Tighten Firebase security rules",
    summary:
      "This preview describes the expected outcome of restricting overly permissive Firebase security rules. Rules must be updated in the Firebase console or via the Firebase CLI. ConfigTrace does not apply this change.",
    before: [
      { label: "Security rules", value: "Permissive — data readable or writable without authentication" },
    ],
    after: [
      { label: "Security rules", value: "Restricted — reads and writes require valid authentication and authorization checks" },
    ],
    preview_kind: "conceptual",
    confirmation_phrase: "TIGHTEN RULES",
    required_permissions: [
      "Firebase: project owner or editor role",
      "Firebase CLI: firebase deploy --only firestore:rules (or realtime database rules)",
    ],
    warnings: [
      "Tightening rules will immediately block clients that relied on open access — test against staging first if possible.",
      "allow:read rules that are too broad can expose all user data to unauthenticated callers.",
      "Firebase rule changes take effect immediately after deployment with no gradual rollout.",
    ],
    preconditions: [
      "Review all current rules and identify which specific allow blocks are overly permissive.",
      "Test rule changes in the Firebase Rules Simulator before deploying to production.",
      "Confirm client applications send valid authentication tokens before restricting access.",
    ],
    validation_steps: [
      "Use the Firebase Rules Simulator to confirm the updated rules behave as expected.",
      "Verify that authenticated clients can still perform the expected read/write operations.",
      ...STANDARD_VALIDATION,
    ],
    provider_console_url: "https://console.firebase.google.com",
  });
}

// ── Generator 6: Supabase Row Level Security disabled ────────────────────────

function _supabaseRlsPreview(
  change: ChangeInput, rt: string, fp: string,
  _ct: string, rl: string, rr: string,
): RemediationPreview | null {
  if (rt !== "supabase_table_rls") return null;
  if (!(
    fp === "rls_enabled"     ||
    fp === "row_security"    ||
    rr.includes("rls")       ||
    rr.includes("row level") ||
    rr.includes("row-level")
  )) return null;
  if (rl !== "critical" && rl !== "high") return null;

  const tableId    = _extractTableId(change.record_identifier);
  const tableLabel = tableId ?? "affected table";

  return _preview({
    title: "Enable Row Level Security",
    summary:
      `This preview shows the expected state after enabling Row Level Security (RLS) on the ${tableLabel} table. Apply via the Supabase SQL editor or dashboard. ConfigTrace does not apply this change.`,
    before: [
      { label: "Row Level Security", value: "Disabled — all rows accessible to any role with table access" },
      { label: "Table",              value: tableLabel },
    ],
    after: [
      { label: "Row Level Security", value: "Enabled — access controlled by RLS policies on the table" },
      { label: "Table",              value: tableLabel },
    ],
    preview_kind: "exact",
    confirmation_phrase: "ENABLE RLS",
    required_permissions: [
      "Supabase: project owner or admin role",
      "PostgreSQL: ALTER TABLE privilege on the affected table",
    ],
    warnings: [
      "Enabling RLS without any policies will block ALL access to the table — including authenticated users.",
      "Ensure at least one permissive policy exists before enabling RLS on a table with active users.",
      "Test in a staging environment first to verify existing application queries are not broken.",
    ],
    preconditions: [
      "Verify that appropriate RLS policies exist (or are ready to be created) for the table.",
      "Review any application code that queries this table without user context.",
      "Confirm no background jobs rely on unrestricted table access.",
    ],
    validation_steps: [
      `Run: SELECT relrowsecurity FROM pg_class WHERE relname = '${tableId ?? "<table_name>"}' — expect true.`,
      "Test that application queries using row-level access return the expected rows.",
      ...STANDARD_VALIDATION,
    ],
    provider_console_url: "https://app.supabase.com",
  });
}

// ── Generator 7: Vercel deploy hook added or removed ─────────────────────────

function _vercelDeployHookPreview(
  _change: ChangeInput, rt: string, _fp: string,
  ct: string, rl: string, _rr: string,
): RemediationPreview | null {
  if (rt !== "vercel_deploy_hook") return null;
  if (rl !== "critical" && rl !== "high" && rl !== "medium") return null;

  const isAdded = ct === "added" || ct === "field_added";

  if (isAdded) {
    return _preview({
      title: "Audit newly added deploy hook",
      summary:
        "A new Vercel deploy hook was added. Deploy hooks can trigger deployments via an unauthenticated URL — review who added it and whether it is authorized. ConfigTrace does not apply this change.",
      before: [
        { label: "Deploy hook", value: "Hook did not exist" },
      ],
      after: [
        { label: "Deploy hook",       value: "Hook added — triggers a deployment when the URL is called" },
        { label: "Action required",   value: "Verify the hook is authorized and its URL is kept confidential" },
      ],
      preview_kind: "conceptual",
      confirmation_phrase: "AUDIT HOOK",
      required_permissions: [
        "Vercel: project owner or member role (to review and manage deploy hooks)",
      ],
      warnings: [
        "Deploy hook URLs trigger a deployment when called by anyone who has the URL — treat them as secrets.",
        "If this hook was not authorized, delete it immediately and audit recent deployments.",
      ],
      preconditions: [
        "Confirm who added this hook and for what purpose.",
        "Verify the hook URL has not been exposed in logs, commits, or public channels.",
      ],
      validation_steps: [
        "Open Vercel → project → Settings → Git → Deploy Hooks and review all active hooks.",
        "If the hook is unexpected, delete it and audit recent deployments triggered by it.",
        ...STANDARD_VALIDATION,
      ],
      provider_console_url: "https://vercel.com/dashboard",
    });
  }

  // Removed or modified
  return _preview({
    title: "Restore removed deploy hook",
    summary:
      "A Vercel deploy hook was removed. If this was unintentional, restore it in the Vercel project settings. ConfigTrace does not apply this change.",
    before: [
      { label: "Deploy hook", value: "Hook existed and could trigger deployments when called" },
    ],
    after: [
      { label: "Deploy hook", value: "Hook removed — deployments via this hook URL are no longer possible" },
    ],
    preview_kind: "conceptual",
    confirmation_phrase: "RESTORE HOOK",
    required_permissions: [
      "Vercel: project owner or member role (to manage deploy hooks)",
    ],
    warnings: [
      "Any integrations or CI pipelines that relied on this hook URL will fail until a new hook is created.",
    ],
    preconditions: [
      "Confirm whether this hook removal was intentional.",
      "Identify any systems that were calling this hook URL.",
    ],
    validation_steps: [
      "If restored, verify the new hook URL is distributed to all systems that need it.",
      "Confirm no unintended deployments were triggered before removal.",
      ...STANDARD_VALIDATION,
    ],
    provider_console_url: "https://vercel.com/dashboard",
  });
}

// ── Generic fallback ──────────────────────────────────────────────────────────

function _genericPreview(
  _change: ChangeInput,
  _rt: string,
  _fp: string,
  ct: string,
  _rl: string,
  rr: string,
  remediation: RemediationResult & { available: true },
): RemediationPreview {
  const isRemoved  = ct === "removed"  || ct === "field_removed";
  const isAdded    = ct === "added"    || ct === "field_added";

  const beforeValue = isRemoved
    ? "Setting or record was present"
    : isAdded
      ? "Setting or record did not exist"
      : "Setting was at the previously observed value";

  const afterValue = isRemoved
    ? "Setting or record restored to expected configuration"
    : isAdded
      ? "Setting reviewed and confirmed authorized, or reverted"
      : "Setting updated to the expected secure value";

  const summaryBase = rr
    ? `This preview summarises the expected remediation outcome. Risk reason: ${rr}.`
    : "This preview summarises the expected remediation outcome.";

  return _preview({
    title: remediation.title,
    summary: `${summaryBase} ConfigTrace does not apply this change.`,
    before: [
      { label: "State", value: beforeValue },
    ],
    after: [
      { label: "State", value: afterValue },
    ],
    preview_kind: "conceptual",
    confirmation_phrase: "CONFIRM CHANGE",
    required_permissions: [],
    warnings: [
      "Review this change in the context of your environment before applying any remediation.",
    ],
    preconditions: [
      "Read the full remediation guidance for this change before proceeding.",
    ],
    validation_steps: [
      ...STANDARD_VALIDATION,
    ],
    provider_console_url: null,
  });
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Returns a dry-run remediation preview for the given change.
 *
 * CRITICAL: execution_enabled is always false. This function never mutates
 * any provider resource and never triggers backend jobs.
 *
 * @param change      The change to preview.
 * @param remediation The remediation guidance result (from getRemediationGuidance).
 * @param _fixPlan    The fix plan result (from getFixPlanForChange) — accepted
 *                    for API consistency and future enrichment; not used in M58.3.
 * @returns RemediationPreviewResult. Always { available: false } when
 *          remediation.available is false.
 */
export function getRemediationPreviewForChange(
  change: ChangeInput,
  remediation: RemediationResult,
  _fixPlan: FixPlanResult,
): RemediationPreviewResult {
  // Only generate a preview when there is remediation guidance
  if (!remediation.available) return NA;

  const pm = change.provider_metadata ?? {};
  const rt = (typeof pm["record_type"] === "string" ? pm["record_type"] : "").toLowerCase();
  const fp = (change.field_path   ?? "").toLowerCase();
  const ct = (change.change_type  ?? "").toLowerCase();
  const rl = (change.risk_level   ?? "").toLowerCase();
  const rr = (change.risk_reason  ?? "").toLowerCase();

  // Try specific generators in priority order
  const specific =
    _awsSgSshPreview(change, rt, fp, ct, rl, rr)             ??
    _awsSgRdpPreview(change, rt, fp, ct, rl, rr)             ??
    _ghBranchProtectionPreview(change, rt, fp, ct, rl, rr)   ??
    _cfDnsPreview(change, rt, fp, ct, rl, rr)                ??
    _firebaseRulesPreview(change, rt, fp, ct, rl, rr)        ??
    _supabaseRlsPreview(change, rt, fp, ct, rl, rr)          ??
    _vercelDeployHookPreview(change, rt, fp, ct, rl, rr);

  if (specific) return specific;

  // Generic fallback — any remediation-covered change gets a conceptual preview
  return _genericPreview(change, rt, fp, ct, rl, rr, remediation);
}
