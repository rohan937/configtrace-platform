/**
 * securityRuleCatalog.ts — read-only catalog of the Configuration Risk rules
 * ConfigTrace evaluates (M60.9).
 *
 * This is a STATIC mirror of the backend rules implemented in
 * backend/app/services/security_rules/*.py (M60.4–M60.4.5). Every entry's
 * `key` matches a real backend rule_key. It is intentionally a hand-maintained
 * catalog (no backend endpoint exists for rule metadata yet); when a backend
 * rule is added/changed, update this file to match.
 *
 * Nothing here claims breach/threat detection. All rules evaluate provider
 * CONFIGURATION snapshots for risky current states, using metadata only.
 */

export type RuleSeverity = "critical" | "high" | "medium" | "low" | "info";
export type RuleConfidence = "high" | "medium";

export interface SecurityRuleMeta {
  key: string;
  provider: string; // matches getProviderMeta ids: github/aws/cloudflare/…
  severity: RuleSeverity; // headline (worst case the rule can emit)
  severityNote?: string;
  title: string;
  category: string;
  confidence: RuleConfidence;
  metadataOnly: true;
  description: string;
  whatItChecks: string;
  whyItMatters: string;
  evidence: string;
  remediation: string;
  falsePositiveGuard: string;
}

export interface DeferredRuleMeta {
  provider: string;
  title: string;
  reason: string;
}

export interface ProviderCoverage {
  provider: string;
  surfaces: string[];
}

// ── Implemented rules (exact keys from backend security_rules/*) ─────────────

export const SECURITY_RULES: SecurityRuleMeta[] = [
  // ── GitHub ────────────────────────────────────────────────────────────────
  {
    key: "github_webhook_http",
    provider: "github",
    severity: "critical",
    title: "GitHub webhook uses plain HTTP",
    category: "Webhooks",
    confidence: "high",
    metadataOnly: true,
    description: "An active GitHub webhook delivers events over plain HTTP.",
    whatItChecks: "Each active webhook's delivery URL scheme.",
    whyItMatters:
      "Event payloads and signature headers may be transmitted in cleartext, which could allow interception or tampering.",
    evidence: "Webhook delivery URL (scheme/host/path).",
    remediation: "Restore HTTPS on the endpoint and verify ownership.",
    falsePositiveGuard: "Only fires for active webhooks whose URL begins with http://.",
  },
  {
    key: "github_branch_protection_missing",
    provider: "github",
    severity: "high",
    title: "GitHub default branch has no protection",
    category: "Branch protection",
    confidence: "high",
    metadataOnly: true,
    description: "The default branch has no branch protection rule.",
    whatItChecks: "Whether protection is enabled on the repository's default branch.",
    whyItMatters:
      "Commits can be pushed directly without review, and history can be rewritten or the branch deleted.",
    evidence: "Branch name and protection-enabled flag.",
    remediation: "Enable branch protection: require reviews, status checks, and block force pushes/deletions.",
    falsePositiveGuard:
      "Only the default branch is evaluated; a 403/permission error aborts the fetch before this fires, so a 404→disabled reliably means 'no rule configured'.",
  },
  {
    key: "github_force_pushes_allowed",
    provider: "github",
    severity: "high",
    title: "GitHub default branch allows force pushes",
    category: "Branch protection",
    confidence: "high",
    metadataOnly: true,
    description: "Force pushes are permitted on the protected default branch.",
    whatItChecks: "The allow_force_pushes flag on an enabled protection rule.",
    whyItMatters: "History can be rewritten, erasing the audit trail.",
    evidence: "Branch name and force-pushes-allowed flag.",
    remediation: "Disable 'Allow force pushes' in branch protection.",
    falsePositiveGuard: "Only evaluated when protection is enabled (sub-rules are skipped when protection is missing).",
  },
  {
    key: "github_branch_deletion_allowed",
    provider: "github",
    severity: "high",
    title: "GitHub default branch allows deletion",
    category: "Branch protection",
    confidence: "high",
    metadataOnly: true,
    description: "Branch deletion is permitted on the protected default branch.",
    whatItChecks: "The allow_deletions flag on an enabled protection rule.",
    whyItMatters: "The protected branch could be removed.",
    evidence: "Branch name and deletions-allowed flag.",
    remediation: "Disable 'Allow deletions' in branch protection.",
    falsePositiveGuard: "Only evaluated when protection is enabled.",
  },
  {
    key: "github_pr_review_not_required",
    provider: "github",
    severity: "high",
    title: "GitHub default branch does not require PR review",
    category: "Branch protection",
    confidence: "high",
    metadataOnly: true,
    description: "The protected default branch does not require an approving review before merge.",
    whatItChecks: "Whether PR reviews are required and the approving-review count is ≥ 1.",
    whyItMatters: "Unreviewed code can reach production.",
    evidence: "Branch name and required-review count.",
    remediation: "Require at least one approving review; enable dismiss-stale-approvals.",
    falsePositiveGuard: "Only evaluated when protection is enabled.",
  },
  {
    key: "github_status_checks_not_required",
    provider: "github",
    severity: "medium",
    title: "GitHub default branch does not require status checks",
    category: "Branch protection",
    confidence: "high",
    metadataOnly: true,
    description: "The protected default branch does not require status checks before merge.",
    whatItChecks: "The required_status_checks_enabled flag on an enabled protection rule.",
    whyItMatters: "Broken or failing code can be merged.",
    evidence: "Branch name and status-checks-required flag.",
    remediation: "Require status checks to pass before merging.",
    falsePositiveGuard: "Only evaluated when protection is enabled.",
  },
  {
    key: "github_deploy_key_write_access",
    provider: "github",
    severity: "high",
    title: "GitHub deploy key has write access",
    category: "Deploy keys",
    confidence: "high",
    metadataOnly: true,
    description: "A repository deploy key has read-write access.",
    whatItChecks: "The read_only flag on each deploy key.",
    whyItMatters: "A leaked write-capable deploy key allows pushing malicious code.",
    evidence: "Deploy key title, id, and verified flag (never key material).",
    remediation: "Recreate the key as read-only or remove it if unused.",
    falsePositiveGuard: "Missing read_only defaults to read-only (safe), so partial records are ignored.",
  },
  {
    key: "github_env_protection_missing",
    provider: "github",
    severity: "medium",
    title: "GitHub production environment has no protection rules",
    category: "Environment protection",
    confidence: "high",
    metadataOnly: true,
    description: "A production environment has no reviewers, wait timer, or branch policy.",
    whatItChecks: "Environments named production/prod with zero reviewers, zero wait timer, and no branch policy.",
    whyItMatters: "Anyone able to run a workflow can deploy to production without approval.",
    evidence: "Environment name, required reviewers, wait timer, branch-policy flag.",
    remediation: "Add required reviewers and restrict deployments to protected branches.",
    falsePositiveGuard: "Narrowly scoped to environments explicitly named production/prod.",
  },

  // ── GitHub rulesets (M69.5A) ────────────────────────────────────────────────
  {
    key: "github_ruleset_not_enforced",
    provider: "github",
    severity: "high",
    title: "GitHub ruleset is not actively enforced",
    category: "Rulesets",
    confidence: "high",
    metadataOnly: true,
    description: "A ruleset is set to disabled/evaluate rather than actively enforced.",
    whatItChecks: "The ruleset enforcement field; flags anything other than 'active'.",
    whyItMatters: "Repository protection the ruleset defines may not apply, which may weaken protection.",
    evidence: "Ruleset name, enforcement, target, protected-branch flag.",
    remediation: "Set the ruleset enforcement status to 'Active'.",
    falsePositiveGuard: "Reads the enforcement field directly; only fires when it is not 'active'.",
  },
  {
    key: "github_ruleset_force_push_allowed",
    provider: "github",
    severity: "high",
    title: "GitHub ruleset allows force pushes",
    category: "Rulesets",
    confidence: "high",
    metadataOnly: true,
    description: "An active branch ruleset does not block force pushes.",
    whatItChecks: "Whether an active branch ruleset includes a non-fast-forward (block force push) rule.",
    whyItMatters: "History can be rewritten, erasing the audit trail.",
    evidence: "Ruleset name, force-pushes-allowed flag, target.",
    remediation: "Add a 'Block force pushes' (non-fast-forward) rule to the ruleset.",
    falsePositiveGuard: "Only fires for active branch rulesets that lack the non-fast-forward rule.",
  },
  {
    key: "github_ruleset_pr_review_missing",
    provider: "github",
    severity: "high",
    title: "GitHub ruleset does not require pull request review",
    category: "Rulesets",
    confidence: "medium",
    metadataOnly: true,
    description: "An active ruleset targets a protected branch but does not require PR review.",
    whatItChecks: "Whether an active protected-branch ruleset includes a pull_request rule.",
    whyItMatters: "Unreviewed code can reach protected branches.",
    evidence: "Ruleset name, PR-review-required flag, protected-branch flag.",
    remediation: "Add a 'Require a pull request before merging' rule to the ruleset.",
    falsePositiveGuard: "Depends on the protected-branch target heuristic; only active branch rulesets are evaluated.",
  },
  {
    key: "github_ruleset_status_checks_missing",
    provider: "github",
    severity: "medium",
    title: "GitHub ruleset does not require status checks",
    category: "Rulesets",
    confidence: "medium",
    metadataOnly: true,
    description: "An active ruleset targets a protected branch but requires no status checks.",
    whatItChecks: "The required-status-checks count on an active protected-branch ruleset.",
    whyItMatters: "Broken or failing code can be merged.",
    evidence: "Ruleset name, required-status-checks count, protected-branch flag.",
    remediation: "Add a 'Require status checks to pass' rule to the ruleset.",
    falsePositiveGuard: "Depends on the protected-branch target heuristic; only active branch rulesets are evaluated.",
  },
  {
    key: "github_ruleset_bypass_actors_present",
    provider: "github",
    severity: "medium",
    title: "GitHub ruleset has bypass actors",
    category: "Rulesets",
    confidence: "high",
    metadataOnly: true,
    description: "An active ruleset grants one or more actors the ability to skip its rules.",
    whatItChecks: "The bypass-actor count on an active ruleset (counts only, never identities).",
    whyItMatters: "Bypass grants may weaken the protection the ruleset is meant to enforce.",
    evidence: "Ruleset name and bypass-actor count.",
    remediation: "Review the ruleset's bypass list and remove unnecessary actors.",
    falsePositiveGuard: "Reads the bypass-actor count directly; counts only, never identities.",
  },
  {
    key: "github_ruleset_weak_target_coverage",
    provider: "github",
    severity: "medium",
    title: "GitHub ruleset does not cover the default branch",
    category: "Rulesets",
    confidence: "medium",
    metadataOnly: true,
    description: "An active branch ruleset does not appear to target the default/main branch.",
    whatItChecks: "A default-branch coverage heuristic over the ruleset's branch targets.",
    whyItMatters: "Protection may not apply where it matters most.",
    evidence: "Ruleset name, protected-branch flag, target.",
    remediation: "Extend the ruleset's target patterns to cover the default branch.",
    falsePositiveGuard: "Based on a default-branch coverage heuristic; conservative and may under-report.",
  },

  // ── GitHub automation permissions (M69.5B) ──────────────────────────────────
  {
    key: "github_automation_admin_permission",
    provider: "github",
    severity: "high",
    title: "GitHub automation credential has admin repository permission",
    category: "Automation permissions",
    confidence: "high",
    metadataOnly: true,
    description: "The authenticated automation credential has admin permission on this repository.",
    whatItChecks: "The repository permission object GitHub returns for the authenticated credential.",
    whyItMatters: "Admin access broadens the blast radius of the credential beyond what monitoring usually requires.",
    evidence: "Credential type, admin-permission flag, broad-permission count.",
    remediation: "Reduce the automation credential to the least privilege it needs (prefer read-only).",
    falsePositiveGuard: "Reads the credential's repository permission object directly; no value is fabricated.",
  },
  {
    key: "github_automation_write_permission",
    provider: "github",
    severity: "medium",
    title: "GitHub automation credential has write permission",
    category: "Automation permissions",
    confidence: "high",
    metadataOnly: true,
    description: "The authenticated automation credential has write/push permission where read-only would usually be safer.",
    whatItChecks: "The push/maintain flags on the credential's repository permission object.",
    whyItMatters: "Write access may increase the blast radius of the credential.",
    evidence: "Credential type, push/maintain flags, broad-permission count.",
    remediation: "Reduce the automation credential to read-only where possible.",
    falsePositiveGuard: "Only fires when admin is not already set; reads the permission object directly.",
  },
  {
    key: "github_token_broad_scopes",
    provider: "github",
    severity: "high",
    title: "GitHub token appears broadly scoped",
    category: "Automation permissions",
    confidence: "medium",
    metadataOnly: true,
    description: "The automation token carries broad repository/admin OAuth scopes.",
    whatItChecks: "Classic-PAT OAuth scope names from the X-OAuth-Scopes response header.",
    whyItMatters: "A broadly scoped token increases the blast radius of the credential.",
    evidence: "Credential type, broad scope names, scope count.",
    remediation: "Replace the broadly scoped token with a least-privilege fine-grained token or GitHub App.",
    falsePositiveGuard: "Classic-PAT scopes only; fine-grained tokens/Apps expose no scopes, so it may under-report.",
  },
  {
    key: "github_webhook_secret_missing",
    provider: "github",
    severity: "medium",
    title: "GitHub webhook has no secret configured",
    category: "Webhooks",
    confidence: "high",
    metadataOnly: true,
    description: "A GitHub webhook has no signing secret configured.",
    whatItChecks: "Whether the webhook config includes a secret (presence boolean only — never the value).",
    whyItMatters: "Without a secret, delivered payloads cannot be verified, so the endpoint may be easier to spoof.",
    evidence: "Webhook secret-configured boolean.",
    remediation: "Configure a webhook secret and verify signatures on delivery.",
    falsePositiveGuard: "GitHub reliably masks a configured secret and omits the field when none is set.",
  },

  // ── AWS ───────────────────────────────────────────────────────────────────
  {
    key: "aws_public_admin_port",
    provider: "aws",
    severity: "high",
    title: "AWS security group exposes administrative ports to the internet",
    category: "Security groups",
    confidence: "high",
    metadataOnly: true,
    description: "An inbound rule allows public access to admin ports (SSH/RDP/WinRM).",
    whatItChecks: "Ingress rules where is_public is true and port_category is admin.",
    whyItMatters:
      "If the group is attached to an internet-reachable resource, admin ports are reachable from anywhere.",
    evidence: "Security group id, direction, protocol, ports, CIDR, port category.",
    remediation: "Restrict to trusted CIDRs; prefer a bastion/VPN.",
    falsePositiveGuard:
      "Only 0.0.0.0/0 or ::/0 count as public; language is careful since reachability is not proven from the rule alone.",
  },
  {
    key: "aws_public_database_port",
    provider: "aws",
    severity: "critical",
    title: "AWS security group exposes database ports to the internet",
    category: "Security groups",
    confidence: "high",
    metadataOnly: true,
    description: "An inbound rule allows public access to database ports.",
    whatItChecks: "Ingress rules where is_public is true and port_category is database.",
    whyItMatters: "Databases reachable from the public internet are a high-impact exposure.",
    evidence: "Security group id, ports, CIDR, port category.",
    remediation: "Restrict to trusted CIDRs or private networking only.",
    falsePositiveGuard: "Only canonical 'any' CIDRs count as public.",
  },
  {
    key: "aws_public_all_ports",
    provider: "aws",
    severity: "critical",
    title: "AWS security group exposes all ports to the internet",
    category: "Security groups",
    confidence: "high",
    metadataOnly: true,
    description: "An all-traffic inbound rule is open to the public internet.",
    whatItChecks: "Ingress rules where is_public is true and the protocol is all-traffic.",
    whyItMatters: "Every port is reachable from anywhere if attached to a public resource.",
    evidence: "Security group id, protocol, CIDR.",
    remediation: "Replace the all-traffic rule with least-privilege rules.",
    falsePositiveGuard: "Only canonical 'any' CIDRs count as public.",
  },
  {
    key: "aws_s3_public_policy",
    provider: "aws",
    severity: "critical",
    title: "AWS S3 bucket policy allows public access",
    category: "S3 public access",
    confidence: "high",
    metadataOnly: true,
    description: "A bucket policy grants public access (AWS's own determination).",
    whatItChecks: "policy_status_is_public / public_principals_detected on the bucket.",
    whyItMatters: "Objects may be readable or writable by anyone on the internet.",
    evidence: "Bucket name, public-policy flags, public-access-block state.",
    remediation: "Remove public grants and enable S3 Block Public Access.",
    falsePositiveGuard: "Only explicit True flags fire; an unknown/None state is never treated as public.",
  },
  {
    key: "aws_s3_public_acl",
    provider: "aws",
    severity: "critical",
    severityNote: "Critical when public write; high when public read only.",
    title: "AWS S3 bucket ACL grants public access",
    category: "S3 public access",
    confidence: "high",
    metadataOnly: true,
    description: "A bucket ACL grants read or write to AllUsers / AuthenticatedUsers.",
    whatItChecks: "ACL all-users / authenticated-users read & write grants.",
    whyItMatters: "Public ACL grants can expose or allow tampering with objects.",
    evidence: "Bucket name and the specific ACL grant flags.",
    remediation: "Remove public ACL grants; prefer policies and enable Block Public Access.",
    falsePositiveGuard: "Only explicit True grants fire; None is never treated as public.",
  },
  {
    key: "aws_iam_admin_policy_attached",
    provider: "aws",
    severity: "high",
    title: "AWS AdministratorAccess attached to an IAM principal",
    category: "IAM",
    confidence: "high",
    metadataOnly: true,
    description: "The AWS-managed AdministratorAccess policy is attached to a principal.",
    whatItChecks: "Policy attachments whose ARN is exactly arn:aws:iam::aws:policy/AdministratorAccess.",
    whyItMatters: "Over-broad admin grants increase blast radius if the principal is compromised.",
    evidence: "Principal type/name and policy name.",
    remediation: "Replace with least-privilege policies; reserve admin for break-glass roles with MFA.",
    falsePositiveGuard: "Exact ARN match — not a keyword guess.",
  },
  {
    key: "aws_access_key_unused",
    provider: "aws",
    severity: "medium",
    title: "AWS access key is active but unused",
    category: "IAM access keys",
    confidence: "high",
    metadataOnly: true,
    description: "An active access key has not been used in 90+ days.",
    whatItChecks: "Active keys whose last-used age is a concrete value ≥ 90 days.",
    whyItMatters: "Long-lived unused keys are an unnecessary standing credential.",
    evidence: "Username, key id last-4, status, last-used age in days.",
    remediation: "Deactivate then delete; prefer short-lived role credentials.",
    falsePositiveGuard: "An unknown last-used age (never-used vs fetch-failed) is not flagged.",
  },

  // ── Cloudflare ────────────────────────────────────────────────────────────
  {
    key: "cloudflare_ssl_mode_weak",
    provider: "cloudflare",
    severity: "high",
    title: "Cloudflare SSL/TLS mode is weak",
    category: "SSL/TLS",
    confidence: "high",
    metadataOnly: true,
    description: "Zone SSL/TLS mode is 'off' or 'flexible'.",
    whatItChecks: "The zone 'ssl' setting value.",
    whyItMatters: "Traffic to the origin may be sent in cleartext.",
    evidence: "SSL mode value.",
    remediation: "Set SSL/TLS mode to 'Full (strict)'.",
    falsePositiveGuard: "Only off/flexible fire; full/strict are safe.",
  },
  {
    key: "cloudflare_always_https_off",
    provider: "cloudflare",
    severity: "medium",
    title: "Cloudflare 'Always Use HTTPS' is disabled",
    category: "HTTPS",
    confidence: "high",
    metadataOnly: true,
    description: "Plain-HTTP requests are not redirected to HTTPS.",
    whatItChecks: "The 'always_use_https' setting value.",
    whyItMatters: "Visitors may transmit data over an unencrypted connection.",
    evidence: "Setting value.",
    remediation: "Enable 'Always Use HTTPS'.",
    falsePositiveGuard: "Only fires when the value is explicitly 'off'.",
  },
  {
    key: "cloudflare_min_tls_weak",
    provider: "cloudflare",
    severity: "medium",
    title: "Cloudflare minimum TLS version is outdated",
    category: "SSL/TLS",
    confidence: "high",
    metadataOnly: true,
    description: "Minimum TLS version is 1.0 or 1.1.",
    whatItChecks: "The 'min_tls_version' setting value.",
    whyItMatters: "Deprecated TLS versions may weaken transport security.",
    evidence: "Minimum TLS version value.",
    remediation: "Set the minimum TLS version to 1.2 or higher.",
    falsePositiveGuard: "Only 1.0/1.1 fire.",
  },
  {
    key: "cloudflare_security_level_low",
    provider: "cloudflare",
    severity: "medium",
    title: "Cloudflare security level is effectively off",
    category: "WAF / security",
    confidence: "high",
    metadataOnly: true,
    description: "Security level is 'off' or 'essentially_off'.",
    whatItChecks: "The 'security_level' setting value.",
    whyItMatters: "Cloudflare applies little or no challenge to suspicious traffic.",
    evidence: "Security level value.",
    remediation: "Raise the security level to at least 'Medium'.",
    falsePositiveGuard: "low/medium/high are treated as normal; only off/essentially_off fire.",
  },
  {
    key: "cloudflare_development_mode_on",
    provider: "cloudflare",
    severity: "medium",
    title: "Cloudflare development mode is enabled",
    category: "WAF / security",
    confidence: "high",
    metadataOnly: true,
    description: "Development mode bypasses edge cache and some optimizations.",
    whatItChecks: "The 'development_mode' setting value.",
    whyItMatters: "It is meant to be temporary and may reduce protection while active.",
    evidence: "Setting value.",
    remediation: "Turn off development mode when finished.",
    falsePositiveGuard: "Only fires when explicitly 'on'.",
  },
  {
    key: "cloudflare_hsts_disabled",
    provider: "cloudflare",
    severity: "medium",
    title: "Cloudflare HSTS is disabled",
    category: "HTTPS",
    confidence: "high",
    metadataOnly: true,
    description: "HTTP Strict Transport Security is disabled.",
    whatItChecks: "The security_header (HSTS) enabled flag.",
    whyItMatters: "Browsers are not told to use HTTPS, allowing protocol downgrade on first contact.",
    evidence: "HSTS enabled flag.",
    remediation: "Enable HSTS with a reasonable max-age once HTTPS is verified.",
    falsePositiveGuard: "Only an explicit enabled=false fires; indeterminate values are skipped.",
  },
  {
    key: "cloudflare_waf_rule_disabled",
    provider: "cloudflare",
    severity: "high",
    severityNote: "High when a 'block' rule is disabled; medium for challenge rules.",
    title: "Cloudflare WAF rule is disabled",
    category: "WAF / security",
    confidence: "high",
    metadataOnly: true,
    description: "A protective WAF rule (block/challenge) is disabled.",
    whatItChecks: "Per-rule enabled flag for protective actions only.",
    whyItMatters: "The rule no longer blocks or challenges matching traffic.",
    evidence: "Rule description, action, enabled flag, ruleset id (never the expression).",
    remediation: "Re-enable the rule or document why it is intentionally off.",
    falsePositiveGuard: "Disabled log/skip rules are ignored — only protective actions fire.",
  },
  {
    key: "cloudflare_dns_private_origin",
    provider: "cloudflare",
    severity: "high",
    title: "Cloudflare DNS record points to a private or reserved IP",
    category: "DNS",
    confidence: "high",
    metadataOnly: true,
    description: "A public A/AAAA record resolves to a private/loopback/reserved IP.",
    whatItChecks: "A/AAAA record content classified via IP-address rules.",
    whyItMatters: "Usually a misconfiguration that may break routing or leak internal network details.",
    evidence: "Record name, type, content, address kind, proxied flag.",
    remediation: "Point the record at the correct public address or remove it.",
    falsePositiveGuard: "Public/global IPs are normal and never flagged; CNAMEs/non-IP content are ignored.",
  },

  // ── Supabase ──────────────────────────────────────────────────────────────
  {
    key: "supabase_rls_disabled",
    provider: "supabase",
    severity: "high",
    title: "Supabase table has Row Level Security disabled",
    category: "RLS",
    confidence: "high",
    metadataOnly: true,
    description: "Row Level Security is disabled on a table.",
    whatItChecks: "The rls_enabled flag per table.",
    whyItMatters: "Without RLS, rows may be broadly readable or writable by any role that can reach the table.",
    evidence: "Schema and table name.",
    remediation: "Enable RLS and add explicit policies.",
    falsePositiveGuard: "Only an explicit rls_enabled=false fires; missing/unknown is skipped.",
  },
  {
    key: "supabase_anonymous_access_enabled",
    provider: "supabase",
    severity: "medium",
    title: "Supabase anonymous sign-ins are enabled",
    category: "Auth",
    confidence: "medium",
    metadataOnly: true,
    description: "Anonymous authentication is enabled.",
    whatItChecks: "The auth-config anonymous_enabled flag.",
    whyItMatters: "Combined with weak/missing RLS, this may allow unauthenticated data access.",
    evidence: "anonymous_enabled flag.",
    remediation: "Disable anonymous sign-ins if not required; otherwise scope RLS tightly.",
    falsePositiveGuard: "Medium severity and careful wording — anonymous auth is a feature, risky mainly with weak RLS.",
  },
  {
    key: "supabase_jwt_expiry_long",
    provider: "supabase",
    severity: "medium",
    title: "Supabase JWT expiry is very long",
    category: "Auth",
    confidence: "high",
    metadataOnly: true,
    description: "The JWT access-token lifetime is over a day.",
    whatItChecks: "auth-config jwt_exp as a concrete integer > 86400 seconds.",
    whyItMatters: "Long-lived tokens stay valid after sign-out and widen the impact of a leaked token.",
    evidence: "JWT expiry in seconds.",
    remediation: "Shorten the access-token lifetime; rely on refresh-token rotation.",
    falsePositiveGuard: "Only a concrete int over the threshold fires; non-int/None is skipped.",
  },
  {
    key: "supabase_public_select_sensitive_table",
    provider: "supabase",
    severity: "high",
    title: "Supabase public read policy on a sensitive-looking table",
    category: "RLS",
    confidence: "high",
    metadataOnly: true,
    description: "A policy targeting the public/anon role allows SELECT on a table whose name suggests sensitive data. May expose data depending on grants and application access.",
    whatItChecks: "pg_policies metadata (role targets + command) for an active public/anon SELECT policy on an RLS-enabled, sensitively-named table. Never the policy expression, columns, or rows.",
    whyItMatters: "Public read access to sensitive data may increase unauthorized-access risk.",
    evidence: "Schema/table name and a policy count (never the policy expression or row data).",
    remediation: "Scope reads to authenticated, row-scoped policies instead of the public/anon role.",
    falsePositiveGuard: "Only fires when a public/anon SELECT policy is active on an RLS-enabled, sensitively-named table.",
  },
  {
    key: "supabase_public_write_policy",
    provider: "supabase",
    severity: "high",
    title: "Supabase public write policy on a table",
    category: "RLS",
    confidence: "high",
    metadataOnly: true,
    description: "A policy targeting the public/anon role allows insert, update, or delete on a table. May allow broad writes depending on grants and application access.",
    whatItChecks: "pg_policies metadata (role targets + command) for an active public/anon write policy on an RLS-enabled table. Never the policy expression, columns, or rows.",
    whyItMatters: "Public write access may increase unauthorized-access risk to the data.",
    evidence: "Schema/table name and a policy count (never the policy expression or row data).",
    remediation: "Scope writes to authenticated, ownership-checked policies instead of the public/anon role.",
    falsePositiveGuard: "Only fires when a public/anon insert/update/delete policy is active on an RLS-enabled table.",
  },
  {
    key: "supabase_edge_function_jwt_disabled",
    provider: "supabase",
    severity: "medium",
    title: "Supabase Edge Function has JWT verification disabled",
    category: "Edge Functions",
    confidence: "high",
    metadataOnly: true,
    description: "An Edge Function has verify_jwt disabled, so it accepts unauthenticated requests. Severity is higher for sensitive-looking function names.",
    whatItChecks: "Edge Function metadata verify_jwt flag (and the function name for severity).",
    whyItMatters: "An unauthenticated function may increase unauthorized-access risk depending on what it does.",
    evidence: "Function name and the verify_jwt boolean (never source code or secrets).",
    remediation: "Enable JWT verification unless the function is intentionally public; add in-function authorization.",
    falsePositiveGuard: "Only an explicit verify_jwt=false fires; missing/unknown is skipped.",
  },
  {
    key: "supabase_auth_protection_missing",
    provider: "supabase",
    severity: "medium",
    title: "Supabase leaked-password protection is disabled",
    category: "Auth",
    confidence: "medium",
    metadataOnly: true,
    description: "Leaked-password protection (Have I Been Pwned) is disabled, so users may set known-compromised passwords. Notes MFA status when also disabled.",
    whatItChecks: "auth-config leaked_password_protection_enabled (and mfa_totp_enabled for context).",
    whyItMatters: "Allowing known-leaked passwords may increase unauthorized-access risk.",
    evidence: "The two protection booleans (no auth user data).",
    remediation: "Enable leaked-password protection and consider enabling/encouraging MFA.",
    falsePositiveGuard: "Only an explicit leaked-password-protection=false fires; missing/unknown is skipped.",
  },

  // ── Firebase ──────────────────────────────────────────────────────────────
  {
    key: "firebase_rules_public",
    provider: "firebase",
    severity: "critical",
    severityNote: "Critical when public write; high when public read only.",
    title: "Firebase Firestore rules allow public access",
    category: "Security rules",
    confidence: "medium",
    metadataOnly: true,
    description: "The active Firestore ruleset appears to allow public read/write.",
    whatItChecks: "public_read_detected / public_write_detected on the Firestore ruleset.",
    whyItMatters: "Documents may be exposed to unauthenticated reads or writes.",
    evidence: "Release name, public read/write flags, parser confidence (never raw rules).",
    remediation: "Replace broad 'allow if true' rules with auth-scoped checks.",
    falsePositiveGuard: "Low-confidence parses are skipped to avoid false positives.",
  },
  {
    key: "firebase_storage_rules_public",
    provider: "firebase",
    severity: "critical",
    severityNote: "Critical when public write; high when public read only.",
    title: "Firebase Storage rules allow public access",
    category: "Security rules",
    confidence: "medium",
    metadataOnly: true,
    description: "The active Storage ruleset appears to allow public read/write.",
    whatItChecks: "public_read_detected / public_write_detected on the Storage ruleset.",
    whyItMatters: "Stored objects may be exposed to unauthenticated access.",
    evidence: "Release name, public read/write flags, parser confidence.",
    remediation: "Tighten Storage rules to require auth and scope to owners.",
    falsePositiveGuard: "Low-confidence parses are skipped.",
  },
  {
    key: "firebase_anonymous_auth_enabled",
    provider: "firebase",
    severity: "medium",
    title: "Firebase anonymous authentication is enabled",
    category: "Auth",
    confidence: "medium",
    metadataOnly: true,
    description: "Anonymous authentication is enabled.",
    whatItChecks: "The auth-config anonymous_enabled flag.",
    whyItMatters: "With permissive rules, this may allow unauthenticated users to access data.",
    evidence: "Project id and anonymous_enabled flag.",
    remediation: "Disable anonymous auth if not required; otherwise scope rules tightly.",
    falsePositiveGuard: "Medium severity — risky mainly when paired with permissive rules.",
  },
  {
    key: "firebase_database_public_read",
    provider: "firebase",
    severity: "high",
    title: "Firebase Realtime Database rules allow public read",
    category: "Security rules",
    confidence: "high",
    metadataOnly: true,
    description: "The Realtime Database rules appear to allow public (unauthenticated) read.",
    whatItChecks: "public_read_detected on the Realtime Database ruleset (.read expressions).",
    whyItMatters: "Data may be exposed depending on rule evaluation and application access patterns.",
    evidence: "Instance name hash, public-read flag, parser confidence (never raw rules JSON).",
    remediation: "Replace '.read': true with auth-scoped expressions (e.g. auth != null).",
    falsePositiveGuard: "Only an unconditional '.read': true with no auth guard fires; low-confidence parses are skipped.",
  },
  {
    key: "firebase_database_public_write",
    provider: "firebase",
    severity: "critical",
    title: "Firebase Realtime Database rules allow public write",
    category: "Security rules",
    confidence: "high",
    metadataOnly: true,
    description: "The Realtime Database rules appear to allow public (unauthenticated) write.",
    whatItChecks: "public_write_detected on the Realtime Database ruleset (.write expressions).",
    whyItMatters: "May expose data and may increase unauthorized-access risk depending on rule evaluation.",
    evidence: "Instance name hash, public-write flag, parser confidence (never raw rules JSON).",
    remediation: "Replace '.write': true with auth-scoped, ownership-checked expressions.",
    falsePositiveGuard: "Only an unconditional '.write': true with no auth guard fires; low-confidence parses are skipped.",
  },
  {
    key: "firebase_auth_protection_missing",
    provider: "firebase",
    severity: "medium",
    title: "Firebase multi-factor authentication is not enabled",
    category: "Auth",
    confidence: "medium",
    metadataOnly: true,
    description: "MFA is not enabled for the project's Authentication configuration.",
    whatItChecks: "The auth-config mfa_enabled flag.",
    whyItMatters: "Single-factor accounts may increase unauthorized-access risk.",
    evidence: "Project id and mfa_enabled flag.",
    remediation: "Enable multi-factor authentication for Firebase Auth.",
    falsePositiveGuard: "Only an explicit mfa_enabled=false fires; missing/unknown is skipped.",
  },

  // ── Stripe ────────────────────────────────────────────────────────────────
  {
    key: "stripe_webhook_http",
    provider: "stripe",
    severity: "critical",
    title: "Stripe webhook uses plain HTTP",
    category: "Webhooks",
    confidence: "high",
    metadataOnly: true,
    description: "An enabled Stripe webhook endpoint delivers over plain HTTP.",
    whatItChecks: "The endpoint URL scheme for enabled webhook endpoints.",
    whyItMatters: "Event payloads and signature headers may be transmitted in cleartext.",
    evidence: "Endpoint delivery URL.",
    remediation: "Update the endpoint to https:// and verify signature checks still pass.",
    falsePositiveGuard: "Disabled endpoints are not flagged.",
  },
  {
    key: "stripe_webhook_disabled",
    provider: "stripe",
    severity: "medium",
    title: "Stripe webhook endpoint is disabled",
    category: "Webhooks",
    confidence: "high",
    metadataOnly: true,
    description: "A Stripe webhook endpoint is disabled and is not receiving events.",
    whatItChecks: "The endpoint status for webhook endpoints.",
    whyItMatters: "Downstream automation may miss payment/subscription events, which may affect billing/payment operations.",
    evidence: "Endpoint status (disabled).",
    remediation: "Confirm whether the endpoint should be enabled; re-enable or remove it.",
    falsePositiveGuard: "Only an explicit status='disabled' fires; enabled/unknown is skipped.",
  },
  {
    key: "stripe_webhook_broad_events",
    provider: "stripe",
    severity: "medium",
    title: "Stripe webhook subscribes to a very broad set of events",
    category: "Webhooks",
    confidence: "medium",
    metadataOnly: true,
    description: "An enabled webhook subscribes to all events ('*') or a very large number of event types.",
    whatItChecks: "The enabled_events list for enabled endpoints (wildcard or a large count).",
    whyItMatters: "Receiving more events than needed widens the configuration surface and may increase webhook configuration risk.",
    evidence: "Subscribed-event count and whether the wildcard '*' is used (never payloads).",
    remediation: "Scope the webhook to only the events the integration needs.",
    falsePositiveGuard: "Fires on the wildcard '*' or a large explicit event count; a normal scoped list is not flagged.",
  },
  {
    key: "stripe_payment_link_tax_disabled",
    provider: "stripe",
    severity: "medium",
    title: "Stripe payment link has automatic tax disabled",
    category: "Payment links",
    confidence: "high",
    metadataOnly: true,
    description: "An active Stripe payment link does not have automatic tax enabled.",
    whatItChecks: "automatic_tax_enabled on active payment links.",
    whyItMatters: "Tax may not be collected correctly, which may affect billing/payment operations and tax compliance.",
    evidence: "active and automatic_tax_enabled flags (never customer or payment data).",
    remediation: "Enable automatic tax on the link if collection is expected for your markets.",
    falsePositiveGuard: "Only an active link with an explicit automatic_tax_enabled=false fires.",
  },
  {
    key: "stripe_payment_link_promo_codes_enabled",
    provider: "stripe",
    severity: "low",
    title: "Stripe payment link allows promotion codes",
    category: "Payment links",
    confidence: "high",
    metadataOnly: true,
    description: "An active Stripe payment link allows customers to enter promotion codes.",
    whatItChecks: "allow_promotion_codes on active payment links.",
    whyItMatters: "If unintended, this may allow unexpected discounting and may affect billing/payment operations.",
    evidence: "active and allow_promotion_codes flags.",
    remediation: "Disable promotion codes on the link if it is not intended.",
    falsePositiveGuard: "Only an active link with an explicit allow_promotion_codes=true fires; a config-review item, not an exposure.",
  },
  {
    key: "stripe_portal_subscription_cancel_enabled",
    provider: "stripe",
    severity: "low",
    title: "Stripe customer portal allows self-serve cancellation",
    category: "Customer portal",
    confidence: "high",
    metadataOnly: true,
    description: "The active customer portal configuration lets customers cancel their own subscriptions.",
    whatItChecks: "subscription_cancel_enabled on active billing portal configurations.",
    whyItMatters: "If unintended, self-serve cancellation may affect billing/payment operations and retention.",
    evidence: "active and subscription_cancel_enabled flags.",
    remediation: "Disable self-serve cancellation or add a cancellation flow if it is not intended.",
    falsePositiveGuard: "Only an active portal config with an explicit subscription_cancel_enabled=true fires.",
  },
  {
    key: "stripe_portal_login_enabled",
    provider: "stripe",
    severity: "medium",
    title: "Stripe customer portal login page is enabled",
    category: "Customer portal",
    confidence: "high",
    metadataOnly: true,
    description: "The active customer portal configuration has its hosted login page enabled.",
    whatItChecks: "login_page_enabled on active billing portal configurations.",
    whyItMatters: "Customers can request a portal session by email; if unintended this widens the self-serve access surface.",
    evidence: "active and login_page_enabled flags.",
    remediation: "Disable the hosted login page if portal sessions should only be created by your app.",
    falsePositiveGuard: "Only an active portal config with an explicit login_page_enabled=true fires.",
  },
  {
    key: "stripe_account_capability_incomplete",
    provider: "stripe",
    severity: "medium",
    title: "Stripe account is not fully enabled for payments",
    category: "Account",
    confidence: "high",
    metadataOnly: true,
    description: "Charges, payouts, or required-information onboarding are not complete for the account.",
    whatItChecks: "charges_enabled / payouts_enabled / details_submitted on account settings.",
    whyItMatters: "The account may be unable to accept charges or receive payouts, which may affect billing/payment operations.",
    evidence: "charges_enabled, payouts_enabled, details_submitted booleans.",
    remediation: "Complete the account's required information in the Stripe dashboard.",
    falsePositiveGuard: "Only an explicit charges/payouts/details flag of false fires; missing/unknown is skipped.",
  },

  // ── Vercel ────────────────────────────────────────────────────────────────
  {
    key: "vercel_preview_unprotected",
    provider: "vercel",
    severity: "medium",
    title: "Vercel preview deployments are not protected",
    category: "Deployment protection",
    confidence: "medium",
    metadataOnly: true,
    description: "Preview deployments have no Vercel Authentication, password, or preview protection.",
    whatItChecks: "deployment-protection flags: preview protection, SSO, password all off.",
    whyItMatters: "Preview URLs may be publicly accessible and could expose unreleased features or non-production data.",
    evidence: "Project name and the (empty) set of active protections.",
    remediation: "Enable Vercel Authentication or password protection for previews.",
    falsePositiveGuard: "Only fires when every protection mechanism is off; previews are not production data, so severity is medium.",
  },
  {
    key: "vercel_production_branch_missing",
    provider: "vercel",
    severity: "medium",
    title: "Vercel project has no production branch configured",
    category: "Deployment configuration",
    confidence: "medium",
    metadataOnly: true,
    description: "A git-connected project has no production branch set, so production deployments may track an unexpected branch.",
    whatItChecks: "Project git connection plus whether a production branch is configured.",
    whyItMatters: "An unset production branch can cause unintended code to ship to production.",
    evidence: "Project name and a boolean indicating the production branch is unset.",
    remediation: "Set an explicit production branch (for example, main or master) in the project's Git settings.",
    falsePositiveGuard: "Only fires when a git repository is connected but no production branch is configured.",
  },
  {
    key: "vercel_production_branch_unusual",
    provider: "vercel",
    severity: "medium",
    title: "Vercel production branch looks non-production",
    category: "Deployment configuration",
    confidence: "medium",
    metadataOnly: true,
    description: "The production branch matches a conventionally non-production name (dev, staging, preview, etc.).",
    whatItChecks: "The configured production branch name against a list of known non-production names.",
    whyItMatters: "Production deployments may track development or staging code.",
    evidence: "Project name and the production branch name.",
    remediation: "Confirm the production branch is intentional; point it at your release branch if not.",
    falsePositiveGuard: "main/master/prod/production are treated as normal; only known non-production names fire.",
  },
  {
    key: "vercel_domain_unverified",
    provider: "vercel",
    severity: "medium",
    title: "Vercel domain is not verified",
    category: "Domains",
    confidence: "medium",
    metadataOnly: true,
    description: "A domain attached to the project is not verified, which can indicate an incomplete or stale domain configuration.",
    whatItChecks: "Each custom domain's verification status.",
    whyItMatters: "Unverified domains may not serve traffic correctly and can signal stale configuration.",
    evidence: "Domain name and a boolean indicating it is unverified.",
    remediation: "Complete DNS verification or remove the domain if it is no longer used.",
    falsePositiveGuard: "Only an explicit verified=false fires; verified or unknown domains are skipped.",
  },
  {
    key: "vercel_env_var_broad_target",
    provider: "vercel",
    severity: "medium",
    title: "Vercel env var spans production and non-production",
    category: "Environment variables",
    confidence: "medium",
    metadataOnly: true,
    description: "An environment variable is targeted at production and at least one non-production environment, suggesting a shared value across environments.",
    whatItChecks: "The set of target environments (production / preview / development) on each env var. Values are never read.",
    whyItMatters: "A single value shared across environments increases production-change risk.",
    evidence: "Env var key name and its target environment list (never the value).",
    remediation: "Use environment-specific values where production and non-production should differ.",
    falsePositiveGuard: "Only fires when one variable spans production and a non-production environment.",
  },
  {
    key: "vercel_sensitive_env_var_broad_scope",
    provider: "vercel",
    severity: "high",
    title: "Sensitive-looking Vercel env var is broadly scoped",
    category: "Environment variables",
    confidence: "high",
    metadataOnly: true,
    description: "An env var with a secret-suggestive key name (secret/token/key/password/webhook/signing/db) is scoped to a non-production environment. Its metadata suggests broad scope.",
    whatItChecks: "The env var KEY name pattern plus its target environments. The value is never read or stored.",
    whyItMatters: "A secret-suggestive variable exposed beyond production may widen where that value is used.",
    evidence: "Env var key name and its target environment list (never the value).",
    remediation: "Scope sensitive variables to production only, and use separate non-production values.",
    falsePositiveGuard: "Only fires when a secret-suggestive key name is also scoped to a non-production environment; the value is never read.",
  },
  {
    key: "vercel_deploy_hook_production_branch",
    provider: "vercel",
    severity: "medium",
    title: "Vercel deploy hook targets the production branch",
    category: "Deploy hooks",
    confidence: "medium",
    metadataOnly: true,
    description: "A deploy hook targets the production branch. A deploy hook may allow a production deployment if its URL is invoked.",
    whatItChecks: "Each deploy hook's target git ref against known production branch names. The hook URL is never stored.",
    whyItMatters: "A production-targeting deploy hook can trigger production deployments if its URL is known.",
    evidence: "Deploy hook name and target ref (never the hook URL).",
    remediation: "Confirm production deploy hooks are intended and keep their URLs secret; remove unused hooks.",
    falsePositiveGuard: "Only fires when a deploy hook's target ref is the production branch; the hook URL is never stored.",
  },

  // ── Shopify ───────────────────────────────────────────────────────────────
  {
    key: "shopify_webhook_http",
    provider: "shopify",
    severity: "critical",
    title: "Shopify webhook uses plain HTTP",
    category: "Webhooks",
    confidence: "high",
    metadataOnly: true,
    description: "A Shopify webhook delivers to a plain-HTTP endpoint.",
    whatItChecks: "The webhook endpoint scheme.",
    whyItMatters: "Event payloads and HMAC headers may be transmitted in cleartext.",
    evidence: "Webhook topic, endpoint domain, scheme (path is hashed, never stored).",
    remediation: "Switch the webhook endpoint to HTTPS and re-verify HMAC.",
    falsePositiveGuard: "Only an explicit http scheme fires; non-HTTP transports (EventBridge/Pub-Sub) are ignored.",
  },
  {
    key: "shopify_webhook_high_risk_topic",
    provider: "shopify",
    severity: "medium",
    title: "Shopify webhook subscribes to a high-risk topic",
    category: "Webhooks",
    confidence: "medium",
    metadataOnly: true,
    description: "A webhook subscribes to orders, customers, checkouts, fulfillments, refunds, payments, or app-lifecycle events.",
    whatItChecks: "The webhook topic against a curated set of high-risk prefixes/handles.",
    whyItMatters: "High-impact events delivered to the wrong place may affect store / webhook operations.",
    evidence: "Topic and endpoint domain (path is hashed, never stored).",
    remediation: "Confirm the receiving system is owned by your team and HMAC verification is enabled.",
    falsePositiveGuard: "Only a curated set of high-risk topic prefixes / handles fires; generic topics are not flagged.",
  },
  {
    key: "shopify_app_broad_write_scopes",
    provider: "shopify",
    severity: "high",
    severityNote: "High when 4+ high-risk write scopes are granted; medium when 3.",
    title: "Shopify app has broad high-risk write scopes",
    category: "App scopes",
    confidence: "high",
    metadataOnly: true,
    description: "The access token is granted multiple high-risk write scopes (orders/products/customers/inventory/fulfillments/draft_orders/checkouts).",
    whatItChecks: "Intersection of the granted scopes with a curated high-risk write-scope set; fires at >= 3.",
    whyItMatters: "Broad write permissions widen the configuration surface and may affect store operations if misused.",
    evidence: "Count of high-risk write scopes and their names (permission labels — never tokens or secrets).",
    remediation: "Reduce the app's grant to the smallest scope set the integration actually needs.",
    falsePositiveGuard: "Only the curated high-risk write scopes are counted (not generic write_* scopes); fires at >= 3.",
  },
  {
    key: "shopify_app_customer_data_scope",
    provider: "shopify",
    severity: "high",
    title: "Shopify app has customer-data access scopes",
    category: "App scopes",
    confidence: "high",
    metadataOnly: true,
    description: "The access token grants read_customers or write_customers.",
    whatItChecks: "Exact presence of read_customers / write_customers in the granted scope set.",
    whyItMatters: "Customer-data access should be intentional and the receiving system trusted.",
    evidence: "The granted customer-data scope NAMES (permission labels — never customer records).",
    remediation: "Verify the integration needs customer-data access; otherwise remove those scopes from the app's grant.",
    falsePositiveGuard: "Only an exact read_customers / write_customers grant fires; broader 'customer'-substring scopes are not used.",
  },
  {
    key: "shopify_domain_ssl_missing",
    provider: "shopify",
    severity: "high",
    title: "Shopify primary domain does not have SSL enabled",
    category: "Domains",
    confidence: "high",
    metadataOnly: true,
    description: "The shop's primary domain does not have SSL enabled.",
    whatItChecks: "primary=true and ssl_enabled=false on a shop domain record.",
    whyItMatters: "The storefront may serve traffic over plain HTTP, which may affect store/security operations.",
    evidence: "Host and primary/ssl_enabled flags.",
    remediation: "Enable SSL on the primary domain in the Shopify admin.",
    falsePositiveGuard: "Only an explicit ssl_enabled=false on the primary domain fires.",
  },
  {
    key: "shopify_domain_unverified",
    provider: "shopify",
    severity: "medium",
    title: "Shopify primary domain is unverified",
    category: "Domains",
    confidence: "high",
    metadataOnly: true,
    description: "The shop's primary domain is unverified.",
    whatItChecks: "primary=true and verified=false on a shop domain record.",
    whyItMatters: "An unverified primary domain may affect store operations and may require review.",
    evidence: "Host and primary/verified flags.",
    remediation: "Verify the primary domain in the Shopify admin.",
    falsePositiveGuard: "Only an explicit verified=false on the primary domain fires.",
  },
  {
    key: "shopify_policy_missing",
    provider: "shopify",
    severity: "low",
    title: "Shopify standard store policy is missing",
    category: "Store policies",
    confidence: "high",
    metadataOnly: true,
    description: "One of the canonical store policies (refund / privacy / terms of service / shipping) is not present.",
    whatItChecks: "present=false on a baseline store-policy record emitted for canonical policy types.",
    whyItMatters: "A missing standard policy may affect store operations and customer trust.",
    evidence: "Policy type and present=false flag (raw policy body is never stored).",
    remediation: "Draft and publish the missing policy in the Shopify admin.",
    falsePositiveGuard: "Only an explicit present=false on a canonical-policy baseline record fires.",
  },
  // ── Azure — M77B ────────────────────────────────────────────────────────────
  {
    key: "azure_nsg_public_admin_ingress",
    provider: "azure",
    severity: "critical",
    severityNote: "high for SSH (port 22); critical for RDP / WinRM / SQL / MySQL / PostgreSQL / Redis / Elasticsearch / MongoDB.",
    title: "Azure NSG allows public inbound to an administrative port",
    category: "Network security groups",
    confidence: "high",
    metadataOnly: true,
    description: "An NSG inbound Allow rule permits traffic from a public source to a known administrative, database, cache, or search port.",
    whatItChecks: "rules_summary entries with direction=Inbound, access=Allow, source_address_prefix in {*, 0.0.0.0/0, ::/0, Internet, Any}, and destination_port_range covering 22, 3389, 5985/5986, 1433, 3306, 5432, 6379, 9200, or 27017.",
    whyItMatters: "Public access to admin/database ports may expose attached resources and may require review. ConfigTrace does not claim reachability.",
    evidence: "NSG name, resource group, location, matched rule_name, source_address_prefix, destination_port_range, admin_port, protocol.",
    remediation: "Restrict source to a known IP range (e.g. VPN/jump host), use Azure Bastion or Just-In-Time access, or remove the rule.",
    falsePositiveGuard: "Only Inbound+Allow rules from canonical public prefixes on a known admin/database/cache/search port fire.",
  },
  {
    key: "azure_nsg_public_broad_ingress",
    provider: "azure",
    severity: "critical",
    title: "Azure NSG allows broad public inbound access",
    category: "Network security groups",
    confidence: "high",
    metadataOnly: true,
    description: "An NSG inbound Allow rule permits traffic from a public source across all/many ports.",
    whatItChecks: "rules_summary entries with direction=Inbound, access=Allow, source_address_prefix in {*, 0.0.0.0/0, ::/0, Internet, Any}, and destination_port_range of *, Any, 0-65535, or 1-65535.",
    whyItMatters: "Broad public ingress may expose resources using this NSG and may require review.",
    evidence: "NSG name, resource group, location, matched rule_name, source_address_prefix, destination_port_range, protocol.",
    remediation: "Narrow source IP range and destination ports; remove the rule if no longer needed.",
    falsePositiveGuard: "Only Inbound+Allow rules from canonical public prefixes with broad/all-port destination ranges fire.",
  },
  {
    key: "azure_storage_public_blob_access",
    provider: "azure",
    severity: "high",
    title: "Azure Storage account permits public blob access",
    category: "Storage accounts",
    confidence: "high",
    metadataOnly: true,
    description: "Storage account allowBlobPublicAccess=true permits containers/blobs to be made public at the account level.",
    whatItChecks: "allow_blob_public_access=true on a storage account record.",
    whyItMatters: "Public blob access at the account level may allow containers to be made public and may require review. ConfigTrace does not inspect container ACLs.",
    evidence: "Storage account name, resource group, location, allow_blob_public_access flag.",
    remediation: "Disable Allow Blob public access on the storage account and audit each container's public access level.",
    falsePositiveGuard: "Only an explicit allowBlobPublicAccess=true fires; container ACLs are not claimed.",
  },
  {
    key: "azure_storage_public_network_access",
    provider: "azure",
    severity: "high",
    severityNote: "high when defaultAction=Allow is also set; medium otherwise.",
    title: "Azure Storage account allows public network access",
    category: "Storage accounts",
    confidence: "high",
    metadataOnly: true,
    description: "Storage account publicNetworkAccess=Enabled allows public network endpoints. Severity bumps to high when defaultAction=Allow is also set.",
    whatItChecks: "public_network_access ∈ {Enabled, true} on a storage account record; network_default_action=Allow bumps severity.",
    whyItMatters: "Public network access may broaden access to the storage account and may require review.",
    evidence: "Storage account name, resource group, location, public_network_access, network_default_action.",
    remediation: "Restrict to selected networks (VNet rules / Private Endpoint) or disable public network access.",
    falsePositiveGuard: "Only an explicit publicNetworkAccess=Enabled fires; defaultAction=Allow bumps severity when also explicit.",
  },
  {
    key: "azure_storage_weak_tls",
    provider: "azure",
    severity: "medium",
    title: "Azure Storage account allows TLS below 1.2",
    category: "Storage accounts",
    confidence: "high",
    metadataOnly: true,
    description: "Storage account minimum_tls_version is TLS1_0 or TLS1_1.",
    whatItChecks: "minimum_tls_version ∈ {TLS1_0, TLS1_1} on a storage account record.",
    whyItMatters: "Weak transport may be permitted on connections and may require review.",
    evidence: "Storage account name, resource group, location, minimum_tls_version.",
    remediation: "Set minimumTlsVersion to TLS1_2 (or TLS1_3) on the storage account.",
    falsePositiveGuard: "Only explicit minimumTlsVersion=TLS1_0/TLS1_1 fires; missing/unknown is skipped.",
  },
  {
    key: "azure_storage_shared_key_enabled",
    provider: "azure",
    severity: "medium",
    title: "Azure Storage account permits shared-key authorization",
    category: "Storage accounts",
    confidence: "high",
    metadataOnly: true,
    description: "Storage account allowSharedKeyAccess=true permits storage-key-based authorization in addition to Azure AD identities.",
    whatItChecks: "shared_access_key_enabled=true on a storage account record.",
    whyItMatters: "Shared-key authorization may increase credential-management risk and may require review. ConfigTrace does not claim a key exists, was leaked, or was used.",
    evidence: "Storage account name, resource group, location, shared_access_key_enabled flag.",
    remediation: "Migrate clients to Azure AD (Entra ID) RBAC and set allowSharedKeyAccess=false on the account.",
    falsePositiveGuard: "Only an explicit allowSharedKeyAccess=true fires; missing/unknown is skipped.",
  },
  {
    key: "azure_key_vault_public_network_access",
    provider: "azure",
    severity: "high",
    severityNote: "high when defaultAction=Allow is also set; medium otherwise.",
    title: "Azure Key Vault allows public network access",
    category: "Key Vaults",
    confidence: "high",
    metadataOnly: true,
    description: "Key Vault publicNetworkAccess=Enabled allows public endpoints. Severity bumps to high when defaultAction=Allow is also set.",
    whatItChecks: "public_network_access ∈ {Enabled, true} on a Key Vault record; network_default_action=Allow bumps severity.",
    whyItMatters: "Public network access may broaden access to Key Vault endpoints and may require review. ConfigTrace does not claim secrets are exposed.",
    evidence: "Key Vault name, resource group, location, public_network_access, network_default_action.",
    remediation: "Restrict to selected networks (Private Endpoint / VNet) or disable public network access.",
    falsePositiveGuard: "Only an explicit publicNetworkAccess=Enabled fires; defaultAction=Allow bumps severity when also explicit.",
  },
  {
    key: "azure_key_vault_purge_protection_disabled",
    provider: "azure",
    severity: "high",
    severityNote: "high when soft delete is also disabled; medium otherwise.",
    title: "Azure Key Vault has purge protection disabled",
    category: "Key Vaults",
    confidence: "high",
    metadataOnly: true,
    description: "Key Vault enablePurgeProtection=false leaves the vault subject to permanent deletion before the soft-delete retention period ends.",
    whatItChecks: "purge_protection_enabled=false on a Key Vault record; severity bumps to high if soft_delete_enabled=false.",
    whyItMatters: "Without purge protection, vault contents may be permanently removed and may require review.",
    evidence: "Key Vault name, resource group, location, purge_protection_enabled flag, soft_delete_enabled flag.",
    remediation: "Enable purge protection (enablePurgeProtection=true) on the Key Vault and ensure soft delete is on.",
    falsePositiveGuard: "Only an explicit enablePurgeProtection=false fires; missing/unknown is skipped.",
  },
  {
    key: "azure_key_vault_soft_delete_disabled",
    provider: "azure",
    severity: "medium",
    title: "Azure Key Vault has soft delete disabled",
    category: "Key Vaults",
    confidence: "high",
    metadataOnly: true,
    description: "Key Vault enableSoftDelete=false removes the recovery surface for deleted vault contents.",
    whatItChecks: "soft_delete_enabled=false on a Key Vault record.",
    whyItMatters: "Without soft delete, recovery of removed contents is not possible and may require review.",
    evidence: "Key Vault name, resource group, location, soft_delete_enabled flag.",
    remediation: "Enable soft delete (enableSoftDelete=true) on the Key Vault.",
    falsePositiveGuard: "Only an explicit enableSoftDelete=false fires; missing/unknown is skipped.",
  },
  {
    key: "azure_key_vault_rbac_disabled",
    provider: "azure",
    severity: "medium",
    title: "Azure Key Vault uses legacy access policies instead of RBAC",
    category: "Key Vaults",
    confidence: "medium",
    metadataOnly: true,
    description: "Key Vault enableRbacAuthorization=false combined with one or more legacy access policies.",
    whatItChecks: "enable_rbac_authorization=false AND access_policy_count > 0 on a Key Vault record.",
    whyItMatters: "Mixing legacy access policies with Azure RBAC may complicate access governance and may require review. Principal identities are never stored — only the count.",
    evidence: "Key Vault name, resource group, location, enable_rbac_authorization flag, access_policy_count (integer).",
    remediation: "Migrate access policy grants to Azure RBAC role assignments and set enableRbacAuthorization=true.",
    falsePositiveGuard: "Fires only when enableRbacAuthorization=false AND access_policy_count > 0; vaults with no access policies are not flagged.",
  },
  // ── Azure M77C — Identity / Role Assignments ─────────────────────────────
  {
    key: "azure_role_assignment_broad_privilege",
    provider: "azure",
    severity: "high",
    severityNote: "high for subscription scope; medium for resource-group scope.",
    title: "Azure role assignment grants broad privilege at wide scope",
    category: "Identity / Role assignments",
    confidence: "high",
    metadataOnly: true,
    description: "A role assignment grants Owner, Contributor, or User Access Administrator at subscription or resource-group scope.",
    whatItChecks: "role_definition_name in {Owner, Contributor, User Access Administrator} AND scope_type in {subscription, resource_group} on a role assignment record.",
    whyItMatters: "Broad role assignments at wide scope may increase access-governance risk and may require review. ConfigTrace does not claim the assignment is unauthorized or malicious.",
    evidence: "assignment_id (opaque), scope_type, role_definition_name, principal_type (User/Group/ServicePrincipal — not PII), condition_present flag. Principal IDs and email addresses are never stored.",
    remediation: "Review whether this role assignment is still required. Consider narrower built-in roles (Reader, resource-specific roles) or Azure ABAC conditions to reduce scope.",
    falsePositiveGuard: "Only fires for known broad built-in role GUIDs resolved from a static map; custom roles and unknown role GUIDs do not fire.",
  },
  // ── Azure M77C — App Service / Functions ─────────────────────────────────
  {
    key: "azure_app_service_https_disabled",
    provider: "azure",
    severity: "high",
    title: "Azure App Service does not enforce HTTPS",
    category: "App Service / Functions",
    confidence: "high",
    metadataOnly: true,
    description: "App Service httpsOnly=false permits unencrypted HTTP connections.",
    whatItChecks: "https_only=false on an App Service record.",
    whyItMatters: "Unencrypted HTTP traffic may be permitted and may require review.",
    evidence: "app_name, resource group, location, kind, https_only flag.",
    remediation: "Enable 'HTTPS Only' in the App Service TLS/SSL settings.",
    falsePositiveGuard: "Only an explicit httpsOnly=false fires; missing/unknown is skipped.",
  },
  {
    key: "azure_app_service_ftp_enabled",
    provider: "azure",
    severity: "medium",
    title: "Azure App Service allows unencrypted FTP access",
    category: "App Service / Functions",
    confidence: "high",
    metadataOnly: true,
    description: "App Service ftpsState=AllAllowed permits unencrypted FTP connections.",
    whatItChecks: "ftps_state=AllAllowed on an App Service record.",
    whyItMatters: "Unencrypted FTP may allow credentials or data to transit in cleartext and may require review.",
    evidence: "app_name, resource group, location, kind, ftps_state value.",
    remediation: "Set FTP state to 'FTPS Only' or 'Disabled' in App Service → Configuration → General Settings.",
    falsePositiveGuard: "Only ftpsState=AllAllowed fires; FtpsOnly and Disabled do not fire.",
  },
  {
    key: "azure_app_service_weak_tls",
    provider: "azure",
    severity: "medium",
    title: "Azure App Service allows TLS below 1.2",
    category: "App Service / Functions",
    confidence: "high",
    metadataOnly: true,
    description: "App Service minimum TLS version is 1.0 or 1.1.",
    whatItChecks: "min_tls_version in {1.0, 1.1} on an App Service record.",
    whyItMatters: "Weak transport may be permitted on connections and may require review.",
    evidence: "app_name, resource group, location, kind, min_tls_version value.",
    remediation: "Raise the minimum TLS version to 1.2 or higher in App Service → TLS/SSL settings.",
    falsePositiveGuard: "Only explicit minTlsVersion=1.0/1.1 fires; missing/unknown is skipped.",
  },
  {
    key: "azure_app_service_public_network_access",
    provider: "azure",
    severity: "medium",
    title: "Azure App Service allows public network access",
    category: "App Service / Functions",
    confidence: "high",
    metadataOnly: true,
    description: "App Service publicNetworkAccess=Enabled allows public internet endpoints.",
    whatItChecks: "public_network_access=Enabled/true on an App Service record.",
    whyItMatters: "Public network access may broaden the attack surface and may require review.",
    evidence: "app_name, resource group, location, kind, public_network_access value.",
    remediation: "Use VNet integration or private endpoints where public access is not required.",
    falsePositiveGuard: "Only an explicit publicNetworkAccess=Enabled fires; missing/unknown is skipped.",
  },
  // ── Azure M77C — SQL Servers ──────────────────────────────────────────────
  {
    key: "azure_sql_public_network_access",
    provider: "azure",
    severity: "high",
    severityNote: "high when the 'Allow Azure services' firewall rule is also present; medium otherwise.",
    title: "Azure SQL Server allows public network access",
    category: "SQL Servers",
    confidence: "high",
    metadataOnly: true,
    description: "SQL Server publicNetworkAccess=Enabled exposes the SQL endpoint to the public internet.",
    whatItChecks: "public_network_access=Enabled/true on a SQL Server record; has_allow_azure_services_rule bumps severity to high.",
    whyItMatters: "Public network access may broaden access to the SQL endpoint and may require review.",
    evidence: "server_name, resource group, location, public_network_access, firewall_rule_count (integer), has_allow_azure_services_rule flag.",
    remediation: "Disable public network access and use Private Endpoint or VNet service endpoints instead.",
    falsePositiveGuard: "Only an explicit publicNetworkAccess=Enabled fires; has_allow_azure_services_rule is checked only when firewall rule data is available.",
  },
  {
    key: "azure_sql_weak_tls",
    provider: "azure",
    severity: "medium",
    title: "Azure SQL Server allows TLS below 1.2",
    category: "SQL Servers",
    confidence: "high",
    metadataOnly: true,
    description: "SQL Server minimalTlsVersion is 1.0 or 1.1.",
    whatItChecks: "minimum_tls_version in {1.0, 1.1} on a SQL Server record.",
    whyItMatters: "Weak transport may be permitted on client connections and may require review.",
    evidence: "server_name, resource group, location, minimum_tls_version value.",
    remediation: "Set Minimum TLS Version to 1.2 in the SQL Server Firewalls and virtual networks settings.",
    falsePositiveGuard: "Only explicit minimalTlsVersion=1.0/1.1 fires; missing/unknown is skipped.",
  },
  // ── Azure M77C — AKS Clusters ─────────────────────────────────────────────
  {
    key: "azure_aks_local_accounts_enabled",
    provider: "azure",
    severity: "medium",
    title: "Azure AKS cluster has local accounts enabled",
    category: "AKS Clusters",
    confidence: "high",
    metadataOnly: true,
    description: "AKS cluster disableLocalAccounts=false means local Kubernetes accounts are active.",
    whatItChecks: "local_account_disabled=false on an AKS cluster record.",
    whyItMatters: "Local accounts bypass Azure AD authentication and may increase access-control risk. May require review.",
    evidence: "cluster_name, resource group, location, local_account_disabled flag.",
    remediation: "Set disableLocalAccounts=true after configuring Azure AD integration.",
    falsePositiveGuard: "Only an explicit disableLocalAccounts=false fires; missing/unknown is skipped.",
  },
  {
    key: "azure_aks_public_api_access",
    provider: "azure",
    severity: "high",
    title: "Azure AKS API server is publicly accessible with no IP restrictions",
    category: "AKS Clusters",
    confidence: "high",
    metadataOnly: true,
    description: "AKS cluster has a public API server (privateCluster=false) with no authorized IP ranges configured.",
    whatItChecks: "private_cluster_enabled=false AND api_server_authorized_ip_range_count=0 on an AKS cluster record.",
    whyItMatters: "A public API server with no IP restrictions may expose the Kubernetes API to the internet and may require review.",
    evidence: "cluster_name, resource group, location, private_cluster_enabled flag, api_server_authorized_ip_range_count (integer).",
    remediation: "Enable private cluster or configure authorizedIPRanges to allow only known IP ranges.",
    falsePositiveGuard: "Both conditions (public API server AND zero IP ranges) must be explicitly present; partial data (None count) is not flagged.",
  },
  {
    key: "azure_aks_network_policy_missing",
    provider: "azure",
    severity: "medium",
    title: "Azure AKS cluster has no network policy configured",
    category: "AKS Clusters",
    confidence: "medium",
    metadataOnly: true,
    description: "AKS cluster networkPolicy is absent or 'none', meaning pod-to-pod traffic is unrestricted.",
    whatItChecks: "network_policy absent or 'none' on an AKS cluster record.",
    whyItMatters: "Without a network policy, all pod-to-pod traffic is allowed within the cluster. May require review.",
    evidence: "cluster_name, resource group, location, network_policy value.",
    remediation: "Set networkPolicy to 'azure', 'calico', or 'cilium' in the AKS network profile and define Kubernetes NetworkPolicy resources.",
    falsePositiveGuard: "Medium confidence: absence of network policy is the default state; verify whether NetworkPolicy CRDs are in use before remediating.",
  },
  // ── Google Cloud ─────────────────────────────────────────────────────────
  {
    key: "google_cloud_iam_public_member",
    provider: "google_cloud",
    severity: "high",
    title: "Google Cloud IAM policy includes a public member",
    category: "IAM policies",
    confidence: "high",
    metadataOnly: true,
    description:
      "Project-level IAM policy includes the allUsers or allAuthenticatedUsers sentinel as a principal on one or more role bindings.",
    whatItChecks:
      "allusers_binding_present or allauthenticatedusers_binding_present on a Google Cloud IAM policy summary record.",
    whyItMatters:
      "Public sentinels on a project IAM policy may broaden access to project resources and may require review.",
    evidence:
      "project_id, allusers_binding_present flag, allauthenticatedusers_binding_present flag, total binding_count. Member identities are never read or stored.",
    remediation:
      "Remove allUsers / allAuthenticatedUsers from bindings and replace with explicit Google identities (user/group/serviceAccount).",
    falsePositiveGuard:
      "Only an explicit sentinel binding fires; member identities and other counts are not used to infer 'public'.",
  },
  {
    key: "google_cloud_iam_broad_privileged_role",
    provider: "google_cloud",
    severity: "high",
    title: "Google Cloud IAM policy grants broad privileged roles",
    category: "IAM policies",
    confidence: "high",
    metadataOnly: true,
    description:
      "Project-level IAM policy grants one or more broad privileged built-in roles (roles/owner, roles/editor, roles/iam.securityAdmin, roles/resourcemanager.projectIamAdmin, roles/iam.serviceAccountAdmin, roles/iam.serviceAccountKeyAdmin).",
    whatItChecks:
      "role_names on a Google Cloud IAM policy summary record intersected with a curated set of broad project-level role names.",
    whyItMatters:
      "Broad project-level roles concentrate privilege and may increase access-governance risk; may require review.",
    evidence:
      "project_id, matched broad role names, broad_role_count, binding_count, and per-principal-type member counts (no identities).",
    remediation:
      "Replace broad project-level roles with narrower predefined / custom roles scoped to least-privilege.",
    falsePositiveGuard:
      "Only the curated set of broad built-in role names triggers the rule; service-account admin variants fire at medium severity.",
  },
  {
    key: "google_cloud_firewall_public_admin_ingress",
    provider: "google_cloud",
    severity: "critical",
    severityNote: "high for SSH; critical for RDP / WinRM / SQL / MySQL / PostgreSQL / Redis / Elasticsearch / MongoDB.",
    title: "Google Cloud firewall rule allows public inbound on an administrative port",
    category: "Firewall rules",
    confidence: "high",
    metadataOnly: true,
    description:
      "VPC firewall rule allows INGRESS from a public source range (0.0.0.0/0 or ::/0) on a known administrative or database/cache/search port.",
    whatItChecks:
      "direction=INGRESS, disabled=false, source_ranges_summary contains a public range, and allowed_summary contains an entry with an administrative port.",
    whyItMatters:
      "Public ingress on an administrative port may expose targeted resources to the internet. ConfigTrace does not confirm reachability or compromise.",
    evidence:
      "firewall_rule_name, network_name, project_id, direction, priority, source_ranges_summary, matched protocol/ports, target_tag_count, target_service_account_count.",
    remediation:
      "Restrict the source range to known IPs (e.g. VPN / IAP); consider IAP for SSH/RDP administrative access.",
    falsePositiveGuard:
      "Only canonical public ranges (0.0.0.0/0 / ::/0) and a curated admin/database/cache/search port list fire; disabled rules are skipped.",
  },
  {
    key: "google_cloud_firewall_public_broad_ingress",
    provider: "google_cloud",
    severity: "critical",
    title: "Google Cloud firewall rule allows broad public inbound access",
    category: "Firewall rules",
    confidence: "high",
    metadataOnly: true,
    description:
      "VPC firewall rule allows INGRESS from a public source range that covers all ports (or the 'all' protocol).",
    whatItChecks:
      "direction=INGRESS, disabled=false, public source range, and an allowed_summary entry whose protocol is 'all' or whose ports are empty/wildcard/full range.",
    whyItMatters:
      "Broad public ingress significantly widens the network attack surface for any resource matched by the firewall rule and may require review.",
    evidence:
      "firewall_rule_name, network_name, project_id, direction, priority, source_ranges_summary, matched protocol/ports, target_tag_count, target_service_account_count.",
    remediation:
      "Tighten the rule to a narrow source range and specific ports, or disable it if no longer needed.",
    falsePositiveGuard:
      "Only canonical public ranges and broad protocol/port patterns fire; disabled rules are skipped.",
  },
  {
    key: "google_cloud_firewall_rule_no_targets",
    provider: "google_cloud",
    severity: "medium",
    severityNote: "Bumps to high when the same rule is also a broad/admin public ingress.",
    title: "Google Cloud firewall rule has no explicit target tags or service accounts",
    category: "Firewall rules",
    confidence: "medium",
    metadataOnly: true,
    description:
      "VPC firewall rule allows public INGRESS but has no target_tags and no target_service_accounts, so it may apply broadly across the network.",
    whatItChecks:
      "direction=INGRESS, disabled=false, public source range, and target_tag_count=0 AND target_service_account_count=0.",
    whyItMatters:
      "Untargeted rules may apply to more VMs than intended, broadening exposure beyond the resources the rule was designed for.",
    evidence:
      "firewall_rule_name, network_name, project_id, source_ranges_summary, target_tag_count, target_service_account_count.",
    remediation:
      "Scope the firewall rule to target_tags or target_service_accounts so it only applies to the intended VMs.",
    falsePositiveGuard:
      "Both target counts must be explicitly zero AND the rule must be public+enabled+ingress.",
  },
  {
    key: "google_cloud_storage_public_access_prevention_disabled",
    provider: "google_cloud",
    severity: "high",
    severityNote: "Bumps to high when uniform bucket-level access is also disabled; medium otherwise.",
    title: "Google Cloud Storage bucket does not enforce public access prevention",
    category: "Cloud Storage buckets",
    confidence: "high",
    metadataOnly: true,
    description:
      "Bucket-level publicAccessPrevention is missing, inherited, unspecified, or any value other than 'enforced'.",
    whatItChecks:
      "public_access_prevention != 'enforced' on a Google Cloud Storage bucket record.",
    whyItMatters:
      "Without enforced public-access prevention, IAM or object ACLs may independently grant public access; may require review. ConfigTrace does not inspect object ACLs and does not claim objects are public.",
    evidence:
      "bucket_name, location, storage_class, public_access_prevention value, uniform_bucket_level_access_enabled flag.",
    remediation:
      "Set the bucket's publicAccessPrevention to 'enforced'; consider enabling uniform bucket-level access.",
    falsePositiveGuard:
      "Only 'enforced' is treated as safe; missing/inherited/unspecified are flagged.",
  },
  {
    key: "google_cloud_storage_uniform_access_disabled",
    provider: "google_cloud",
    severity: "medium",
    title: "Google Cloud Storage bucket does not enforce uniform bucket-level access",
    category: "Cloud Storage buckets",
    confidence: "high",
    metadataOnly: true,
    description:
      "Uniform bucket-level access is disabled, meaning per-object ACLs can independently grant access.",
    whatItChecks:
      "uniform_bucket_level_access_enabled=false on a Google Cloud Storage bucket record.",
    whyItMatters:
      "Object ACL surface complicates access governance and increases the risk of inconsistent permissions; may require review.",
    evidence:
      "bucket_name, location, storage_class, uniform_bucket_level_access_enabled flag, public_access_prevention value.",
    remediation:
      "Enable uniform bucket-level access; migrate any existing object ACLs to IAM bindings first.",
    falsePositiveGuard:
      "Only an explicit false value fires; missing/unknown is skipped.",
  },
  {
    key: "google_cloud_storage_versioning_disabled",
    provider: "google_cloud",
    severity: "low",
    title: "Google Cloud Storage bucket does not have object versioning enabled",
    category: "Cloud Storage buckets",
    confidence: "high",
    metadataOnly: true,
    description:
      "Object versioning is disabled on the bucket, affecting recoverability of removed or overwritten objects.",
    whatItChecks: "versioning_enabled=false on a Google Cloud Storage bucket record.",
    whyItMatters:
      "Without versioning, accidental deletes or overwrites may not be recoverable; may require review depending on bucket purpose.",
    evidence: "bucket_name, location, storage_class, versioning_enabled flag, lifecycle_rule_count.",
    remediation: "Enable versioning; configure lifecycle rules to prune older noncurrent versions.",
    falsePositiveGuard: "Only an explicit false value fires; missing/unknown is skipped.",
  },
  {
    key: "google_cloud_storage_retention_not_locked",
    provider: "google_cloud",
    severity: "medium",
    severityNote: "Medium when a retention policy is set but unlocked; low when no policy exists.",
    title: "Google Cloud Storage bucket retention policy is not locked",
    category: "Cloud Storage buckets",
    confidence: "medium",
    metadataOnly: true,
    description:
      "Bucket has no retention policy, or the retention policy is configured but not locked.",
    whatItChecks:
      "retention_policy_locked=false OR retention_policy_seconds is absent on a Google Cloud Storage bucket record.",
    whyItMatters:
      "An unlocked or absent retention policy weakens immutability and long-term recoverability posture; may require review.",
    evidence:
      "bucket_name, location, storage_class, retention_policy_seconds, retention_policy_locked flag.",
    remediation:
      "Set a retentionPeriod and lock the retention policy (locking is irreversible — confirm the period first).",
    falsePositiveGuard:
      "Configured-but-unlocked fires at medium; entirely absent retention fires at low.",
  },
  // ── Google Cloud — M78C ───────────────────────────────────────────────────
  {
    key: "google_cloud_sql_public_network_access",
    provider: "google_cloud",
    severity: "high",
    severityNote: "High when authorized_network_count > 0; medium otherwise.",
    title: "Google Cloud SQL instance allows public network access",
    category: "Cloud SQL instances",
    confidence: "high",
    metadataOnly: true,
    description:
      "Cloud SQL instance has a public IP address (ipv4Enabled=true). This may broaden database exposure and may require review.",
    whatItChecks:
      "public_ip_enabled=true on a Google Cloud SQL instance record; severity is high when authorized_network_count > 0.",
    whyItMatters:
      "A public IP on a Cloud SQL instance may allow connection attempts from the internet. ConfigTrace does not confirm reachability, unauthorized access, or data exposure.",
    evidence:
      "instance_name, project_id, region, database_version, state, public_ip_enabled, authorized_network_count.",
    remediation:
      "Switch to private IP with VPC peering or Cloud SQL Auth Proxy. If a public IP is required, restrict authorized networks to the minimum necessary CIDR ranges.",
    falsePositiveGuard:
      "Only an explicit public_ip_enabled=true fires; authorized network count determines severity.",
  },
  {
    key: "google_cloud_sql_weak_tls",
    provider: "google_cloud",
    severity: "medium",
    title: "Google Cloud SQL instance does not require SSL/TLS",
    category: "Cloud SQL instances",
    confidence: "high",
    metadataOnly: true,
    description:
      "Cloud SQL instance does not require SSL/TLS for all connections (require_ssl=false or ssl_mode indicates non-strict mode).",
    whatItChecks:
      "require_ssl=false OR ssl_mode in {ALLOW_UNENCRYPTED_AND_ENCRYPTED, ENCRYPTED_ONLY} on a Cloud SQL instance record.",
    whyItMatters:
      "Allowing unencrypted database connections may expose data in transit and may require review.",
    evidence: "instance_name, project_id, region, require_ssl, ssl_mode.",
    remediation:
      "Set requireSsl=true or ssl_mode=TRUSTED_CLIENT_CERTIFICATE_REQUIRED on the instance IP configuration.",
    falsePositiveGuard:
      "Only explicit require_ssl=false or weak ssl_mode values fire; missing/unknown is skipped.",
  },
  {
    key: "google_cloud_sql_backups_disabled",
    provider: "google_cloud",
    severity: "medium",
    title: "Google Cloud SQL instance does not have automated backups enabled",
    category: "Cloud SQL instances",
    confidence: "high",
    metadataOnly: true,
    description:
      "Cloud SQL instance has automated backups disabled, which may affect recoverability.",
    whatItChecks: "backup_enabled=false on a Cloud SQL instance record.",
    whyItMatters:
      "Without automated backups, recovering from accidental deletion or corruption may not be possible and may require review.",
    evidence: "instance_name, project_id, region, database_version, backup_enabled.",
    remediation:
      "Enable automated backups in the instance settings; consider enabling point-in-time recovery (PITR).",
    falsePositiveGuard: "Only an explicit backup_enabled=false fires; missing/unknown is skipped.",
  },
  {
    key: "google_cloud_sql_deletion_protection_disabled",
    provider: "google_cloud",
    severity: "medium",
    title: "Google Cloud SQL instance does not have deletion protection enabled",
    category: "Cloud SQL instances",
    confidence: "high",
    metadataOnly: true,
    description:
      "Cloud SQL instance does not have deletion protection enabled, which may allow accidental deletion.",
    whatItChecks: "deletion_protection_enabled=false on a Cloud SQL instance record.",
    whyItMatters:
      "Without deletion protection, the instance can be deleted with a single API call and may require review.",
    evidence: "instance_name, project_id, region, database_version, deletion_protection_enabled.",
    remediation:
      "Set deletionProtectionEnabled=true on the instance settings.",
    falsePositiveGuard:
      "Only an explicit deletion_protection_enabled=false fires; missing/unknown is skipped.",
  },
  {
    key: "google_cloud_run_public_invoker",
    provider: "google_cloud",
    severity: "high",
    title: "Google Cloud Run service allows public invocation",
    category: "Cloud Run services",
    confidence: "high",
    metadataOnly: true,
    description:
      "Cloud Run service IAM policy grants roles/run.invoker to allUsers or allAuthenticatedUsers, allowing public invocation.",
    whatItChecks:
      "public_invoker_allowed=true (allUsers or allAuthenticatedUsers in roles/run.invoker binding) on a Cloud Run service record.",
    whyItMatters:
      "Public invocation may broaden service access and may require review. ConfigTrace does not confirm invocation events or unauthorized access.",
    evidence:
      "service_name, project_id, region, ingress, public_invoker_allowed, invoker_policy_summary counts. Member identities are never stored.",
    remediation:
      "Remove allUsers / allAuthenticatedUsers from the service's IAM policy; restrict invocation to specific identities.",
    falsePositiveGuard:
      "Only an explicit public sentinel on roles/run.invoker fires; counts not identities are used.",
  },
  {
    key: "google_cloud_run_all_ingress",
    provider: "google_cloud",
    severity: "high",
    severityNote: "High when public_invoker_allowed is also true; medium otherwise.",
    title: "Google Cloud Run service allows all ingress traffic",
    category: "Cloud Run services",
    confidence: "high",
    metadataOnly: true,
    description:
      "Cloud Run service ingress is set to INGRESS_TRAFFIC_ALL, allowing all traffic including from the public internet.",
    whatItChecks: "ingress=INGRESS_TRAFFIC_ALL on a Cloud Run service record.",
    whyItMatters:
      "All-ingress allows public internet traffic to reach the service endpoint and may require review.",
    evidence: "service_name, project_id, region, ingress, public_invoker_allowed.",
    remediation:
      "Set ingress to INGRESS_TRAFFIC_INTERNAL_ONLY or INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER if public internet access is not required.",
    falsePositiveGuard:
      "Only INGRESS_TRAFFIC_ALL fires; internal or load-balancer-only ingress does not fire.",
  },
  {
    key: "google_cloud_gke_public_control_plane",
    provider: "google_cloud",
    severity: "high",
    title: "GKE cluster control plane appears publicly reachable without authorized network restrictions",
    category: "GKE clusters",
    confidence: "high",
    metadataOnly: true,
    description:
      "GKE cluster has a public control plane endpoint with no master authorized network CIDR restrictions.",
    whatItChecks:
      "public_endpoint_enabled=true AND master_authorized_networks_count=0 on a GKE cluster record.",
    whyItMatters:
      "A publicly reachable control plane with no IP restrictions may require review. ConfigTrace does not confirm actual reachability, compromise, or unauthorized access.",
    evidence:
      "cluster_name, project_id, location, public_endpoint_enabled, master_authorized_networks_count.",
    remediation:
      "Enable masterAuthorizedNetworksConfig with the minimum necessary CIDR ranges, or enable the private endpoint (enablePrivateEndpoint=true).",
    falsePositiveGuard:
      "Fires only when public_endpoint_enabled=true AND master_authorized_networks_count is 0 or absent; clusters with authorized networks are not flagged.",
  },
  {
    key: "google_cloud_gke_legacy_abac_enabled",
    provider: "google_cloud",
    severity: "high",
    title: "GKE cluster has legacy ABAC enabled",
    category: "GKE clusters",
    confidence: "high",
    metadataOnly: true,
    description:
      "GKE cluster has legacy attribute-based access control (ABAC) enabled, which is a deprecated authorization mode.",
    whatItChecks: "legacy_abac_enabled=true on a GKE cluster record.",
    whyItMatters:
      "Legacy ABAC may grant broader access than intended by RBAC policies and may require review.",
    evidence: "cluster_name, project_id, location, legacy_abac_enabled.",
    remediation:
      "Disable legacy ABAC (legacyAbac.enabled=false) and migrate access control to Kubernetes RBAC.",
    falsePositiveGuard: "Only an explicit legacy_abac_enabled=true fires; missing/unknown is skipped.",
  },
  {
    key: "google_cloud_gke_network_policy_disabled",
    provider: "google_cloud",
    severity: "medium",
    title: "GKE cluster does not have network policy enforcement enabled",
    category: "GKE clusters",
    confidence: "medium",
    metadataOnly: true,
    description:
      "GKE cluster does not have a network policy provider enabled, meaning all pod-to-pod traffic is allowed by default.",
    whatItChecks: "network_policy_enabled=false on a GKE cluster record.",
    whyItMatters:
      "Without network policy, lateral movement between pods is unrestricted and may require review.",
    evidence: "cluster_name, project_id, location, network_policy_enabled.",
    remediation:
      "Enable networkPolicy.enabled=true and configure Kubernetes NetworkPolicy resources to restrict pod-to-pod traffic.",
    falsePositiveGuard:
      "Only an explicit network_policy_enabled=false fires; absence of the field is common and treated conservatively at medium confidence.",
  },
  {
    key: "google_cloud_gke_workload_identity_disabled",
    provider: "google_cloud",
    severity: "medium",
    title: "GKE cluster does not have Workload Identity enabled",
    category: "GKE clusters",
    confidence: "medium",
    metadataOnly: true,
    description:
      "GKE cluster does not have Workload Identity configured, meaning workloads may use node-scoped service account credentials.",
    whatItChecks:
      "workload_identity_enabled=false (no workloadPool configured) on a GKE cluster record.",
    whyItMatters:
      "Without Workload Identity, all workloads on a node share the node's service account credentials, which may broaden credential access and may require review.",
    evidence: "cluster_name, project_id, location, workload_identity_enabled.",
    remediation:
      "Enable Workload Identity by configuring workloadIdentityConfig.workloadPool and migrate workloads to per-pod IAM bindings.",
    falsePositiveGuard:
      "Fires when workloadPool is absent/empty; verified absence of workload identity is the default cluster state.",
  },
  {
    key: "google_cloud_service_account_user_managed_keys",
    provider: "google_cloud",
    severity: "high",
    severityNote: "High when user_managed_key_count >= 5; medium otherwise.",
    title: "Google Cloud service accounts have user-managed keys",
    category: "Service account keys",
    confidence: "high",
    metadataOnly: true,
    description:
      "Project has one or more user-managed service account keys, which require manual rotation and may increase credential-management risk.",
    whatItChecks:
      "user_managed_key_count > 0 on the project-level service account key summary record.",
    whyItMatters:
      "User-managed keys are long-lived credentials that must be rotated manually. ConfigTrace does not confirm that keys are in use, were leaked, or represent unauthorized access.",
    evidence:
      "project_id, service_account_count, user_managed_key_count. SA emails and key IDs are never stored.",
    remediation:
      "Migrate to Workload Identity for GCP workloads. For external workloads, use Workload Identity Federation or enforce key rotation policies.",
    falsePositiveGuard:
      "Only fires when user_managed_key_count > 0; SA emails and key material are never read or stored.",
  },
  {
    key: "google_cloud_service_account_old_keys",
    provider: "google_cloud",
    severity: "medium",
    title: "Google Cloud service accounts have aged user-managed keys",
    category: "Service account keys",
    confidence: "high",
    metadataOnly: true,
    description:
      "Project has user-managed service account keys older than 90 days, which may indicate stale credentials requiring rotation.",
    whatItChecks:
      "old_user_managed_key_count > 0 OR oldest_key_age_days >= 90 on the project-level service account key summary record.",
    whyItMatters:
      "Long-lived keys that are not rotated increase the window during which a compromised key could be used and may require review.",
    evidence:
      "project_id, user_managed_key_count, old_user_managed_key_count, oldest_key_age_days.",
    remediation:
      "Rotate or delete user-managed keys older than 90 days. Consider migrating to Workload Identity.",
    falsePositiveGuard:
      "Only fires when old_user_managed_key_count > 0 or oldest_key_age_days >= 90; computed from validAfterTime only — no key material is read.",
  },
  {
    key: "google_cloud_secret_manager_auto_replication_without_cmek",
    provider: "google_cloud",
    severity: "low",
    title: "Google Cloud Secret Manager uses automatic replication without customer-managed encryption",
    category: "Secret Manager",
    confidence: "medium",
    metadataOnly: true,
    description:
      "Project has Secret Manager secrets using automatic replication without customer-managed encryption keys (CMEK).",
    whatItChecks:
      "automatic_replication_count > 0 AND customer_managed_encryption_count == 0 on the project-level Secret Manager summary record.",
    whyItMatters:
      "Secrets are encrypted at rest with Google-managed keys by default. This is a governance posture finding relevant when CMEK is required by policy.",
    evidence:
      "project_id, secret_count, automatic_replication_count, customer_managed_encryption_count. Secret names and values are never stored.",
    remediation:
      "Configure CMEK on Secret Manager secrets where required by policy. Create a Cloud KMS key and grant Secret Manager the necessary role.",
    falsePositiveGuard:
      "Only fires when automatic_replication_count > 0 AND customer_managed_encryption_count == 0; secret names and values are never read.",
  },
  // ── Twilio — M79B ──────────────────────────────────────────────────────────
  {
    key: "twilio_phone_number_sms_webhook_missing",
    provider: "twilio",
    severity: "medium",
    title: "Twilio phone number has SMS capability but no SMS webhook configured",
    category: "Webhook configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "This phone number can receive SMS messages but no inbound webhook URL is configured. Inbound messages may be silently dropped.",
    whatItChecks:
      "capability_sms=true and sms_url_configured=false on a twilio_incoming_phone_number record.",
    whyItMatters:
      "Without an inbound SMS webhook, messages sent to this number may not be processed and could be silently dropped, which may require review.",
    evidence:
      "phone_number_sid, friendly_name, phone_number_last4 (last 4 digits only), iso_country, capability_sms. No full phone number or webhook URL is stored.",
    remediation:
      "Configure an SMS webhook URL for this phone number in the Twilio Console under Phone Numbers > Manage > Active numbers.",
    falsePositiveGuard:
      "Phone numbers used only for outbound SMS or intentionally without inbound handling may not need a webhook.",
  },
  {
    key: "twilio_phone_number_voice_webhook_missing",
    provider: "twilio",
    severity: "medium",
    title: "Twilio phone number has voice capability but no voice webhook configured",
    category: "Webhook configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "This phone number can receive voice calls but no inbound webhook URL is configured. Inbound calls may fail or use default handling.",
    whatItChecks:
      "capability_voice=true and voice_url_configured=false on a twilio_incoming_phone_number record.",
    whyItMatters:
      "Without an inbound voice webhook, calls to this number may fail silently or fall back to default Twilio handling, which may require review.",
    evidence:
      "phone_number_sid, friendly_name, phone_number_last4 (last 4 digits only), iso_country, capability_voice. No full phone number or webhook URL is stored.",
    remediation:
      "Configure a voice webhook URL for this phone number in the Twilio Console under Phone Numbers > Manage > Active numbers.",
    falsePositiveGuard:
      "Phone numbers used only for outbound calls or intentionally without inbound handling may not need a voice webhook.",
  },
  {
    key: "twilio_phone_number_status_callback_missing",
    provider: "twilio",
    severity: "low",
    title: "Twilio phone number has no status callback configured",
    category: "Webhook configuration",
    confidence: "medium",
    metadataOnly: true,
    description:
      "This phone number has no status callback URL configured. Message and call delivery status updates may not be observable.",
    whatItChecks:
      "capability_sms or capability_voice is true, and status_callback_configured=false on a twilio_incoming_phone_number record.",
    whyItMatters:
      "Without a status callback, delivery and call status events are not forwarded, which may reduce observability of message and call outcomes.",
    evidence:
      "phone_number_sid, friendly_name, phone_number_last4 (last 4 digits only), iso_country, capability_sms, capability_voice. No full phone number or URL is stored.",
    remediation:
      "Configure a status callback URL for this phone number in the Twilio Console if delivery observability is required.",
    falsePositiveGuard:
      "Some deployments intentionally omit status callbacks. Only fires when the phone number has SMS or voice capability.",
  },
  {
    key: "twilio_messaging_service_inbound_webhook_missing",
    provider: "twilio",
    severity: "medium",
    title: "Twilio Messaging Service has no inbound webhook configured",
    category: "Webhook configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "This Messaging Service has no inbound webhook URL and is not configured to use number-level webhooks. Inbound messages may not be handled.",
    whatItChecks:
      "inbound_request_url_configured=false and use_inbound_webhook_on_number is not true on a twilio_messaging_service record.",
    whyItMatters:
      "Without an inbound webhook or number-level fallback, inbound messages routed through this service may not be processed, which may require review.",
    evidence:
      "messaging_service_sid, friendly_name, inbound_request_url_configured, use_inbound_webhook_on_number. No URL strings are stored.",
    remediation:
      "Configure an inbound webhook URL or enable number-level webhooks in Twilio Console under Messaging > Services.",
    falsePositiveGuard:
      "Services used only for outbound messaging or with number-level webhooks enabled are not flagged.",
  },
  {
    key: "twilio_messaging_service_fallback_missing",
    provider: "twilio",
    severity: "low",
    title: "Twilio Messaging Service has no fallback URL configured",
    category: "Webhook configuration",
    confidence: "medium",
    metadataOnly: true,
    description:
      "This Messaging Service has no fallback URL. If the primary webhook fails, messages will not have a secondary handler.",
    whatItChecks:
      "fallback_url_configured=false on a twilio_messaging_service record.",
    whyItMatters:
      "Without a fallback URL, a primary webhook failure may result in unhandled inbound messages. Review whether a fallback is required for reliability.",
    evidence:
      "messaging_service_sid, friendly_name, fallback_url_configured. No URL strings are stored.",
    remediation:
      "Configure a fallback URL in Twilio Console under Messaging > Services > Integration settings.",
    falsePositiveGuard:
      "Many deployments intentionally omit a fallback URL. This is a reliability posture item, not a security exposure.",
  },
  {
    key: "twilio_messaging_service_status_callback_missing",
    provider: "twilio",
    severity: "low",
    title: "Twilio Messaging Service has no status callback URL configured",
    category: "Webhook configuration",
    confidence: "medium",
    metadataOnly: true,
    description:
      "This Messaging Service has no status callback URL. Message delivery status updates will not be reported.",
    whatItChecks:
      "status_callback_url_configured=false on a twilio_messaging_service record.",
    whyItMatters:
      "Without a status callback URL, delivery status events are not forwarded, which may reduce observability of message outcomes.",
    evidence:
      "messaging_service_sid, friendly_name, status_callback_url_configured. No URL strings are stored.",
    remediation:
      "Configure a status callback URL in Twilio Console under Messaging > Services > Integration settings.",
    falsePositiveGuard:
      "Many deployments intentionally omit a status callback. This is an observability posture item.",
  },
  {
    key: "twilio_verify_short_code_length",
    provider: "twilio",
    severity: "medium",
    title: "Twilio Verify Service uses a short verification code length",
    category: "Verify services",
    confidence: "high",
    metadataOnly: true,
    description:
      "This Verify Service is configured with fewer than 6 digits for verification codes. Shorter codes may be more susceptible to brute-force enumeration.",
    whatItChecks:
      "code_length < 6 (an explicit integer) on a twilio_verify_service record.",
    whyItMatters:
      "Short verification codes reduce the search space for enumeration attempts and may not meet common security policy requirements.",
    evidence:
      "verify_service_sid, friendly_name, code_length. No customer verification payloads or codes are stored.",
    remediation:
      "Increase the code length to at least 6 digits in Twilio Console under Verify > Services.",
    falsePositiveGuard:
      "Only fires when code_length is an explicit integer less than 6; missing or unknown values are skipped.",
  },
  {
    key: "twilio_verify_lookup_disabled",
    provider: "twilio",
    severity: "low",
    title: "Twilio Verify Service has phone number lookup disabled",
    category: "Verify services",
    confidence: "medium",
    metadataOnly: true,
    description:
      "This Verify Service does not have phone number lookup enabled. Lookup can help detect invalid or non-reachable numbers before sending verification codes.",
    whatItChecks:
      "lookup_enabled=false on a twilio_verify_service record.",
    whyItMatters:
      "Without phone number lookup, verification codes may be sent to invalid or non-reachable numbers, increasing wasted delivery attempts.",
    evidence:
      "verify_service_sid, friendly_name, lookup_enabled. No customer phone numbers or PII are stored.",
    remediation:
      "Review whether phone number lookup should be enabled in Twilio Console under Verify > Services.",
    falsePositiveGuard:
      "Only an explicit lookup_enabled=false fires; missing or unknown values are skipped. Some deployments intentionally disable lookup.",
  },
  {
    key: "twilio_account_suspended",
    provider: "twilio",
    severity: "low",
    title: "Twilio account is not in active status",
    category: "Account",
    confidence: "medium",
    metadataOnly: true,
    description:
      "This Twilio account has a non-active status. Review whether this status reflects an intended configuration or requires action.",
    whatItChecks:
      "account status is not 'active' or empty on a twilio_account record.",
    whyItMatters:
      "A non-active account status may affect communications services relying on this account. Review whether this requires attention.",
    evidence:
      "account_sid_prefix (first 8 characters only), friendly_name, status, account_type. No auth token or full account SID is stored.",
    remediation:
      "Log in to the Twilio Console, review the account status, and contact Twilio support if the status is not intentional.",
    falsePositiveGuard:
      "Only fires when account status is not 'active'; missing or empty status is not flagged.",
  },
  // ── Twilio — M79C ──────────────────────────────────────────────────────────
  {
    key: "twilio_api_key_stale",
    provider: "twilio",
    severity: "medium",
    title: "Twilio API key has not been updated recently",
    category: "API key hygiene",
    confidence: "medium",
    metadataOnly: true,
    description:
      "This Twilio API key metadata indicates the key has not been updated in over 180 days. Stale API keys may require review to confirm they are still in use and meet current security requirements.",
    whatItChecks:
      "date_updated or date_created older than 180 days on a twilio_api_key_summary record.",
    whyItMatters:
      "API keys that have not been rotated or reviewed for an extended period may represent unnecessary long-lived credentials. Regular review helps ensure only needed keys remain active.",
    evidence:
      "api_key_sid, friendly_name, date_created, date_updated. No API key secret is stored.",
    remediation:
      "Review active API keys in the Twilio Console under Account > API keys & tokens. Rotate or deactivate any keys that are no longer needed or no longer meet policy requirements.",
    falsePositiveGuard:
      "Long-lived read-only API keys used for stable integrations may intentionally not be rotated frequently. Only fires when date metadata is present and indicates 180+ days without an update.",
  },
  {
    key: "twilio_messaging_service_observability_gap",
    provider: "twilio",
    severity: "medium",
    title: "Twilio Messaging Service has neither fallback URL nor status callback configured",
    category: "Webhook configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "This Messaging Service has neither a fallback URL nor a status callback URL configured. Message delivery issues may not be detectable or recoverable.",
    whatItChecks:
      "fallback_url_configured=false AND status_callback_url_configured=false simultaneously on a twilio_messaging_service record.",
    whyItMatters:
      "Without both a fallback and a status callback, a primary webhook failure may go undetected and message delivery outcomes will not be observable.",
    evidence:
      "messaging_service_sid, friendly_name, fallback_url_configured, status_callback_url_configured. No URL strings are stored.",
    remediation:
      "Configure a fallback URL and a status callback URL in Twilio Console under Messaging > Services > Integration settings.",
    falsePositiveGuard:
      "Only fires when both fallback_url_configured and status_callback_url_configured are simultaneously false. Services that use number-level callbacks instead may still fire.",
  },
  {
    key: "twilio_messaging_service_number_level_inbound_webhook",
    provider: "twilio",
    severity: "low",
    title: "Twilio Messaging Service delegates inbound webhook handling to individual phone numbers",
    category: "Webhook configuration",
    confidence: "medium",
    metadataOnly: true,
    description:
      "This Messaging Service delegates inbound webhook handling to individual phone numbers rather than a service-level URL. Ensure all associated phone numbers have inbound webhooks configured.",
    whatItChecks:
      "use_inbound_webhook_on_number=true AND inbound_request_url_configured=false on a twilio_messaging_service record.",
    whyItMatters:
      "Number-level webhook delegation may fragment inbound handling across many phone numbers. If any associated number lacks a webhook, inbound messages to that number may not be processed.",
    evidence:
      "messaging_service_sid, friendly_name, use_inbound_webhook_on_number, inbound_request_url_configured. No URL strings are stored.",
    remediation:
      "Verify that all phone numbers associated with this Messaging Service have inbound SMS webhooks configured, or switch to a service-level inbound webhook URL.",
    falsePositiveGuard:
      "Number-level webhook delegation is a supported Twilio pattern. This finding requires review of associated phone numbers, not necessarily a configuration change.",
  },
  {
    key: "twilio_messaging_service_long_validity_period",
    provider: "twilio",
    severity: "low",
    title: "Twilio Messaging Service has a validity period longer than 24 hours",
    category: "Messaging service configuration",
    confidence: "medium",
    metadataOnly: true,
    description:
      "This Messaging Service has a validity period longer than 24 hours. Extended validity periods mean messages may be retried and delivered long after they were originally sent.",
    whatItChecks:
      "validity_period > 86400 (an explicit integer) on a twilio_messaging_service record.",
    whyItMatters:
      "Very long validity periods may cause time-sensitive messages (such as alerts or one-time codes) to be delivered after they are no longer relevant.",
    evidence:
      "messaging_service_sid, friendly_name, validity_period.",
    remediation:
      "Review the validity period in Twilio Console under Messaging > Services and reduce it if messages should not be retried after a shorter window.",
    falsePositiveGuard:
      "Only fires when validity_period is an explicit integer greater than 86400; missing or unknown values are skipped. Some use cases legitimately require long validity periods.",
  },
  {
    key: "twilio_phone_number_messaging_observability_gap",
    provider: "twilio",
    severity: "medium",
    title: "Twilio phone number has SMS capability but no inbound webhook or status callback configured",
    category: "Webhook configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "This phone number has SMS capability but no inbound webhook or status callback is configured. Inbound SMS messages may be silently dropped and delivery status may not be observable.",
    whatItChecks:
      "capability_sms=true AND sms_url_configured=false AND status_callback_configured=false on a twilio_incoming_phone_number record.",
    whyItMatters:
      "With both the inbound webhook and the status callback absent, neither inbound message processing nor delivery status tracking is available for this number.",
    evidence:
      "phone_number_sid, friendly_name, phone_number_last4 (last 4 digits only), iso_country, capability_sms. No full phone number or URL is stored.",
    remediation:
      "Configure an SMS webhook URL and a status callback URL for this phone number in Twilio Console under Phone Numbers > Manage > Active numbers.",
    falsePositiveGuard:
      "Only fires when all three conditions are simultaneously true. Phone numbers used only for outbound SMS may not need an inbound webhook.",
  },
  {
    key: "twilio_phone_number_voice_observability_gap",
    provider: "twilio",
    severity: "medium",
    title: "Twilio phone number has voice capability but no inbound webhook or status callback configured",
    category: "Webhook configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "This phone number has voice capability but no inbound webhook or status callback is configured. Inbound calls may not be handled and call status may not be observable.",
    whatItChecks:
      "capability_voice=true AND voice_url_configured=false AND status_callback_configured=false on a twilio_incoming_phone_number record.",
    whyItMatters:
      "With both the voice webhook and the status callback absent, neither inbound call handling nor call status tracking is available for this number.",
    evidence:
      "phone_number_sid, friendly_name, phone_number_last4 (last 4 digits only), iso_country, capability_voice. No full phone number or URL is stored.",
    remediation:
      "Configure a voice webhook URL and a status callback URL for this phone number in Twilio Console under Phone Numbers > Manage > Active numbers.",
    falsePositiveGuard:
      "Only fires when all three conditions are simultaneously true. Phone numbers used only for outbound calls may not need an inbound voice webhook.",
  },
  {
    key: "twilio_verify_psd2_disabled",
    provider: "twilio",
    severity: "low",
    title: "Twilio Verify Service does not have PSD2 (Strong Customer Authentication) enabled",
    category: "Verify services",
    confidence: "medium",
    metadataOnly: true,
    description:
      "This Verify Service does not have PSD2 (Strong Customer Authentication) enabled. If this service is used for financial transaction verification in regulated markets, PSD2 compliance may require review.",
    whatItChecks:
      "psd2_enabled=false (an explicit boolean) on a twilio_verify_service record.",
    whyItMatters:
      "PSD2/SCA is required for financial transaction authentication in the EU and certain other markets. Services used for payment verification without PSD2 enabled may not meet regulatory requirements.",
    evidence:
      "verify_service_sid, friendly_name, psd2_enabled. No customer verification data is stored.",
    remediation:
      "Review whether PSD2 should be enabled in Twilio Console under Verify > Services. Enable PSD2 if this service is used for financial transaction verification in regulated markets.",
    falsePositiveGuard:
      "Only an explicit psd2_enabled=false fires; missing or unknown values are skipped. PSD2 is only relevant for financial transaction verification use cases in regulated markets.",
  },
  {
    key: "twilio_verify_sms_to_landlines_allowed",
    provider: "twilio",
    severity: "low",
    title: "Twilio Verify Service is configured to send verification SMS to landlines",
    category: "Verify services",
    confidence: "medium",
    metadataOnly: true,
    description:
      "This Verify Service is configured to send verification SMS to landlines, which cannot receive SMS. This may result in verification failures and additional costs.",
    whatItChecks:
      "skip_sms_to_landlines=false (an explicit boolean) on a twilio_verify_service record.",
    whyItMatters:
      "Sending SMS verification codes to landlines always fails, wasting message credits and degrading the user verification experience.",
    evidence:
      "verify_service_sid, friendly_name, skip_sms_to_landlines. No customer phone numbers or PII are stored.",
    remediation:
      "Enable landline SMS filtering in Twilio Console under Verify > Services by setting 'Skip SMS to landlines' to enabled.",
    falsePositiveGuard:
      "Only an explicit skip_sms_to_landlines=false fires; missing or unknown values are skipped. Some deployments may intentionally allow all number types.",
  },
  // ── SendGrid — M80B ──────────────────────────────────────────────────────────
  {
    key: "sendgrid_api_key_broad_scopes",
    provider: "sendgrid",
    severity: "high",
    title: "SendGrid API key is configured with broad access scopes",
    category: "API key scopes",
    confidence: "high",
    metadataOnly: true,
    description:
      "A SendGrid API key has broad or full-access permissions configured. Broad-scope keys may increase the impact of a credential review and may require scope reduction.",
    whatItChecks:
      "has_full_access=true on a sendgrid_api_key record.",
    whyItMatters:
      "Broad API key scopes increase the configuration surface if the key needs rotation or review. Least-privilege key configuration reduces impact.",
    evidence:
      "api_key_id, name (truncated), scopes_count, has_full_access. No API key value or secret is stored.",
    remediation:
      "Review the API key in SendGrid Console under Settings > API Keys. Create a replacement key with only the required scopes (e.g., mail.send only) and rotate integrations.",
    falsePositiveGuard:
      "Only fires when has_full_access=true; keys without broad scopes are not flagged. The API key value is never accessed or stored.",
  },
  {
    key: "sendgrid_sender_identity_unverified",
    provider: "sendgrid",
    severity: "medium",
    title: "SendGrid sender identity has not been verified",
    category: "Sender identities",
    confidence: "high",
    metadataOnly: true,
    description:
      "A SendGrid sender identity is not verified. Unverified sender identities may cause deliverability issues and may not be eligible for sending on all plans.",
    whatItChecks:
      "verified=false on a sendgrid_sender_identity record.",
    whyItMatters:
      "Unverified sender identities may be unable to send email reliably and may affect email deliverability. Completing verification may be required by SendGrid.",
    evidence:
      "sender_id, nickname, from_email_domain (domain only — full email never stored), verified. No personal email address or PII is stored.",
    remediation:
      "Complete sender identity verification in SendGrid Console under Settings > Sender Authentication.",
    falsePositiveGuard:
      "Only fires when verified=false; verified identities are not flagged. Full email addresses are never stored.",
  },
  {
    key: "sendgrid_sender_identity_locked",
    provider: "sendgrid",
    severity: "low",
    title: "SendGrid sender identity is locked",
    category: "Sender identities",
    confidence: "high",
    metadataOnly: true,
    description:
      "A SendGrid sender identity is locked and cannot be edited. Locked identities may indicate an identity actively used by a SendGrid plan feature or one that requires review.",
    whatItChecks:
      "locked=true on a sendgrid_sender_identity record.",
    whyItMatters:
      "A locked sender identity cannot be modified. Review whether the lock is intentional or indicates a configuration posture issue.",
    evidence:
      "sender_id, nickname, verified, locked. No personal email address or PII is stored.",
    remediation:
      "Review the locked sender identity in SendGrid Console under Settings > Sender Authentication. Contact SendGrid support if the lock status is unexpected.",
    falsePositiveGuard:
      "Only fires when locked=true; unlocked identities are not flagged. Some identities are intentionally locked by plan features.",
  },
  {
    key: "sendgrid_domain_authentication_invalid",
    provider: "sendgrid",
    severity: "medium",
    title: "SendGrid domain authentication is not passing DNS validation",
    category: "Domain authentication",
    confidence: "high",
    metadataOnly: true,
    description:
      "A SendGrid domain authentication record shows that at least one DNS check is not passing (valid=false). Invalid domain authentication may affect email deliverability and sender reputation.",
    whatItChecks:
      "valid=false on a sendgrid_domain_authentication record.",
    whyItMatters:
      "Domain authentication failures may cause emails to be treated as unauthenticated by receiving mail servers, affecting deliverability and spam classification.",
    evidence:
      "domain_id, domain name, valid, dns_record_count. No raw DNS record values or DKIM keys are stored.",
    remediation:
      "Review the failing DNS records in SendGrid Console under Settings > Sender Authentication > Domain Authentication. Update DNS records at your domain registrar as required.",
    falsePositiveGuard:
      "Only fires when valid=false; domains with valid=true are not flagged. DNS propagation delays may temporarily cause valid=false.",
  },
  {
    key: "sendgrid_domain_automatic_security_disabled",
    provider: "sendgrid",
    severity: "medium",
    title: "SendGrid domain authentication has automatic security (DKIM rotation) disabled",
    category: "Domain authentication",
    confidence: "high",
    metadataOnly: true,
    description:
      "A SendGrid domain authentication does not have automatic security enabled. Without automatic DKIM key rotation, DKIM keys are static and not rotated automatically, which may require periodic manual rotation.",
    whatItChecks:
      "automatic_security=false on a sendgrid_domain_authentication record.",
    whyItMatters:
      "Static DKIM keys that are never rotated may represent a long-lived configuration posture risk. Automatic security enables SendGrid to manage key rotation.",
    evidence:
      "domain_id, domain name, automatic_security, valid.",
    remediation:
      "Enable automatic security on the domain authentication in SendGrid Console. Update DNS records with the new CNAME values provided by SendGrid after enabling.",
    falsePositiveGuard:
      "Only fires when automatic_security=false; domains with automatic_security=true are not flagged. Some legacy integrations may intentionally use manual DKIM.",
  },
  {
    key: "sendgrid_domain_authentication_legacy",
    provider: "sendgrid",
    severity: "low",
    title: "SendGrid domain is using legacy domain authentication format",
    category: "Domain authentication",
    confidence: "high",
    metadataOnly: true,
    description:
      "A SendGrid domain uses a legacy domain authentication format. SendGrid recommends migrating to the current format which supports automatic DKIM key rotation and modern deliverability features.",
    whatItChecks:
      "legacy=true on a sendgrid_domain_authentication record.",
    whyItMatters:
      "Legacy domain authentication may not support modern DKIM rotation. Migration to the current format is recommended by SendGrid.",
    evidence:
      "domain_id, domain name, legacy, valid.",
    remediation:
      "Migrate to the current SendGrid domain authentication format via SendGrid Console under Settings > Sender Authentication.",
    falsePositiveGuard:
      "Only fires when legacy=true; current-format domains are not flagged. Migration may require DNS changes.",
  },
  {
    key: "sendgrid_spam_check_disabled",
    provider: "sendgrid",
    severity: "medium",
    title: "SendGrid spam check is disabled",
    category: "Mail settings",
    confidence: "high",
    metadataOnly: true,
    description:
      "The SendGrid spam check mail setting is disabled. Without spam checking, outgoing emails are not evaluated for spam-triggering content before delivery, which may affect deliverability.",
    whatItChecks:
      "spam_check_enabled=false on a sendgrid_mail_settings record.",
    whyItMatters:
      "Spam check helps identify content that may trigger spam filters at receiving mail servers, improving deliverability.",
    evidence:
      "spam_check_enabled. No email content or subjects are stored.",
    remediation:
      "Enable the spam check setting in SendGrid Console under Settings > Mail Settings.",
    falsePositiveGuard:
      "Only fires when spam_check_enabled=false; enabled spam check is not flagged.",
  },
  {
    key: "sendgrid_sandbox_mode_enabled",
    provider: "sendgrid",
    severity: "medium",
    title: "SendGrid sandbox mode is enabled — emails are not delivered",
    category: "Mail settings",
    confidence: "high",
    metadataOnly: true,
    description:
      "The SendGrid sandbox mode setting is enabled. In sandbox mode, emails go through the full API processing pipeline but are not delivered to recipients. If left on in production, live email delivery is silently suppressed.",
    whatItChecks:
      "sandbox_mode_enabled=true on a sendgrid_mail_settings record.",
    whyItMatters:
      "Sandbox mode suppresses all email delivery. Unintentional activation in production silently prevents recipients from receiving emails.",
    evidence:
      "sandbox_mode_enabled. No email content is stored.",
    remediation:
      "Disable sandbox mode in SendGrid Console under Settings > Mail Settings if emails should be delivered.",
    falsePositiveGuard:
      "Only fires when sandbox_mode_enabled=true; disabled sandbox mode is not flagged. Testing environments may intentionally use sandbox mode.",
  },
  {
    key: "sendgrid_bcc_enabled",
    provider: "sendgrid",
    severity: "medium",
    title: "SendGrid BCC mail setting is enabled",
    category: "Mail settings",
    confidence: "high",
    metadataOnly: true,
    description:
      "The SendGrid BCC mail setting is enabled. When active, a copy of every outgoing email is sent to a configured BCC address. This behavior may affect data governance and privacy compliance and may require review.",
    whatItChecks:
      "bcc_enabled=true on a sendgrid_mail_settings record.",
    whyItMatters:
      "BCC routing of all outbound email may have data governance and compliance implications and may require documentation.",
    evidence:
      "bcc_enabled. No BCC email address or email content is stored.",
    remediation:
      "Review whether the BCC setting is intentional in SendGrid Console under Settings > Mail Settings. Disable if not required or document the business justification.",
    falsePositiveGuard:
      "Only fires when bcc_enabled=true; disabled BCC is not flagged. The BCC email address is never stored or exposed.",
  },
  {
    key: "sendgrid_click_tracking_enabled",
    provider: "sendgrid",
    severity: "low",
    title: "SendGrid click tracking is enabled",
    category: "Tracking settings",
    confidence: "high",
    metadataOnly: true,
    description:
      "SendGrid click tracking is enabled. Click tracking rewrites links in outgoing emails to route through SendGrid tracking URLs. This may have privacy and compliance implications depending on applicable regulations and may require review.",
    whatItChecks:
      "click_tracking_enabled=true on a sendgrid_tracking_settings record.",
    whyItMatters:
      "Click tracking may require disclosure in your privacy policy and may be subject to privacy regulations such as GDPR or CASL.",
    evidence:
      "click_tracking_enabled. No link URLs, recipient data, or click event data is stored.",
    remediation:
      "Review whether click tracking is required and disclosed in SendGrid Console under Settings > Tracking. Disable if not required or permitted.",
    falsePositiveGuard:
      "Only fires when click_tracking_enabled=true; disabled tracking is not flagged. Many deployments intentionally use click tracking.",
  },
  {
    key: "sendgrid_open_tracking_enabled",
    provider: "sendgrid",
    severity: "low",
    title: "SendGrid open tracking is enabled",
    category: "Tracking settings",
    confidence: "high",
    metadataOnly: true,
    description:
      "SendGrid open tracking is enabled. Open tracking embeds a small invisible image in outgoing emails to detect when recipients open them. This may have privacy and compliance implications depending on applicable regulations and may require review.",
    whatItChecks:
      "open_tracking_enabled=true on a sendgrid_tracking_settings record.",
    whyItMatters:
      "Open tracking may require disclosure in your privacy policy and may be subject to privacy regulations such as GDPR or CASL.",
    evidence:
      "open_tracking_enabled. No recipient data or open event data is stored.",
    remediation:
      "Review whether open tracking is required and disclosed in SendGrid Console under Settings > Tracking. Disable if not required or permitted.",
    falsePositiveGuard:
      "Only fires when open_tracking_enabled=true; disabled tracking is not flagged. Many deployments intentionally use open tracking.",
  },
  {
    key: "sendgrid_subscription_tracking_disabled",
    provider: "sendgrid",
    severity: "medium",
    title: "SendGrid subscription (unsubscribe) tracking is disabled",
    category: "Tracking settings",
    confidence: "high",
    metadataOnly: true,
    description:
      "SendGrid subscription tracking is disabled. Subscription tracking inserts unsubscribe links into outgoing emails, which may be required for commercial email compliance under CAN-SPAM, GDPR, CASL, or other regulations.",
    whatItChecks:
      "subscription_tracking_enabled=false on a sendgrid_tracking_settings record.",
    whyItMatters:
      "Without subscription tracking, commercial email recipients may not have a clear unsubscribe path, which may not meet regulatory requirements for email compliance.",
    evidence:
      "subscription_tracking_enabled. No unsubscribe URLs or recipient data is stored.",
    remediation:
      "Enable subscription tracking in SendGrid Console under Settings > Tracking if you send commercial or marketing email.",
    falsePositiveGuard:
      "Only fires when subscription_tracking_enabled=false; enabled subscription tracking is not flagged. Transactional-only senders may intentionally disable subscription tracking.",
  },
  {
    key: "sendgrid_event_webhook_disabled",
    provider: "sendgrid",
    severity: "medium",
    title: "SendGrid event webhook is disabled",
    category: "Webhook configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "The SendGrid event webhook is disabled. Without an active event webhook, email delivery events (bounces, spam reports, clicks, opens) are not forwarded to your application, creating an observability gap.",
    whatItChecks:
      "event_webhook_enabled=false on a sendgrid_webhook_settings record.",
    whyItMatters:
      "Without event webhook delivery, your application cannot observe email delivery failures, spam reports, or engagement events, which may affect deliverability management.",
    evidence:
      "event_webhook_enabled. No webhook URL or event payload is stored.",
    remediation:
      "Enable the event webhook in SendGrid Console under Settings > Mail Settings > Event Webhook and configure an HTTPS endpoint.",
    falsePositiveGuard:
      "Only fires when event_webhook_enabled=false; enabled webhooks are not flagged. Some accounts may intentionally not use the event webhook.",
  },
  {
    key: "sendgrid_event_webhook_url_missing",
    provider: "sendgrid",
    severity: "medium",
    title: "SendGrid event webhook is enabled but has no URL configured",
    category: "Webhook configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "The SendGrid event webhook is enabled but no delivery URL is configured. Without a URL, webhook events cannot be delivered to any endpoint, making the webhook configuration incomplete.",
    whatItChecks:
      "event_webhook_enabled=true AND event_webhook_has_url=false on a sendgrid_webhook_settings record.",
    whyItMatters:
      "An enabled webhook with no URL cannot deliver events. This may indicate an incomplete configuration that was enabled but never fully set up.",
    evidence:
      "event_webhook_enabled, event_webhook_has_url (boolean), event_count. No webhook URL string is stored.",
    remediation:
      "Configure a delivery URL for the event webhook in SendGrid Console under Settings > Mail Settings > Event Webhook.",
    falsePositiveGuard:
      "Both event_webhook_enabled=true AND event_webhook_has_url=false must be present. The webhook URL is stored as a boolean only — never as a string.",
  },
  {
    key: "sendgrid_suppression_settings_empty",
    provider: "sendgrid",
    severity: "low",
    title: "SendGrid has no suppression groups configured",
    category: "Suppression settings",
    confidence: "medium",
    metadataOnly: true,
    description:
      "No SendGrid Advanced Suppression Manager (ASM) suppression groups are configured. Suppression groups allow recipients to selectively unsubscribe from specific email categories rather than all emails.",
    whatItChecks:
      "suppression_group_count=0 (explicit integer) on a sendgrid_suppression_settings record.",
    whyItMatters:
      "Without suppression groups, recipients cannot selectively opt out of email categories. This may affect compliance with email unsubscribe requirements.",
    evidence:
      "suppression_group_count. No suppressed email addresses or recipient data is stored.",
    remediation:
      "Create suppression groups for your email categories in SendGrid Console under Marketing > Suppressions > Unsubscribe Groups.",
    falsePositiveGuard:
      "Only fires when suppression_group_count is an explicit integer equal to 0. Missing or unknown suppression_group_count is skipped. Some transactional-only senders may intentionally not use suppression groups.",
  },
  // ── M80C additions ────────────────────────────────────────────────────────
  {
    key: "sendgrid_sender_identity_reply_domain_mismatch",
    provider: "sendgrid",
    severity: "low",
    title: "SendGrid sender identity reply-to domain differs from from-email domain",
    category: "Sender identities",
    confidence: "high",
    metadataOnly: true,
    description:
      "This SendGrid sender identity has a reply-to domain that differs from the from-email domain. Mismatched domains may indicate a misconfiguration or may affect recipient trust and deliverability.",
    whatItChecks:
      "from_email_domain and reply_to_domain both non-empty and not equal on a sendgrid_sender_identity record.",
    whyItMatters:
      "Mismatched sender and reply-to domains may confuse recipients or spam filters and may require review for deliverability and trust.",
    evidence:
      "from_email_domain and reply_to_domain (domain portions only — full email addresses are never stored).",
    remediation:
      "Review the sender identity in SendGrid Console under Settings > Sender Authentication and confirm whether the reply-to domain mismatch is intentional.",
    falsePositiveGuard:
      "Only fires when both from_email_domain and reply_to_domain are non-empty and differ. Missing or empty domains are skipped. Some senders intentionally use different reply-to domains.",
  },
  {
    key: "sendgrid_domain_dns_records_missing",
    provider: "sendgrid",
    severity: "medium",
    title: "SendGrid domain authentication has no DNS records configured",
    category: "Domain authentication",
    confidence: "high",
    metadataOnly: true,
    description:
      "This SendGrid domain authentication has zero DNS records configured. Without DNS records, domain authentication cannot be validated and email deliverability may be affected.",
    whatItChecks:
      "dns_record_count=0 (explicit integer) on a sendgrid_domain_authentication record.",
    whyItMatters:
      "Domain authentication without DNS records cannot pass validation, which may affect deliverability and sender reputation. This configuration evidence may require review.",
    evidence:
      "dns_record_count (count only — raw DNS record values are never stored).",
    remediation:
      "In SendGrid Console, navigate to Settings > Sender Authentication > Domain Authentication, select the domain, and add the required DNS records at your DNS provider.",
    falsePositiveGuard:
      "Only fires when dns_record_count is an explicit integer equal to 0. Missing or unknown counts are skipped. Raw DNS record values are never stored.",
  },
  {
    key: "sendgrid_default_domain_authentication_invalid",
    provider: "sendgrid",
    severity: "high",
    title: "SendGrid default domain authentication is not passing DNS validation",
    category: "Domain authentication",
    confidence: "high",
    metadataOnly: true,
    description:
      "The default SendGrid domain authentication is marked as invalid. As the default sender domain, DNS validation failures here may affect all outgoing email deliverability and sender reputation.",
    whatItChecks:
      "default=true AND valid=false on a sendgrid_domain_authentication record.",
    whyItMatters:
      "The default domain is used for all outgoing email unless overridden. An invalid default domain authentication may affect deliverability broadly and may require review.",
    evidence:
      "default, valid, dns_record_count, domain_id, and domain fields from the sendgrid_domain_authentication record.",
    remediation:
      "In SendGrid Console, navigate to Settings > Sender Authentication > Domain Authentication, select the default domain, and fix the failing DNS records.",
    falsePositiveGuard:
      "Only fires when default=true AND valid=false are both explicitly present. Missing or unknown values are skipped.",
  },
  {
    key: "sendgrid_footer_disabled",
    provider: "sendgrid",
    severity: "low",
    title: "SendGrid email footer is disabled",
    category: "Mail settings",
    confidence: "high",
    metadataOnly: true,
    description:
      "The SendGrid email footer setting is disabled. An email footer can include required compliance text and unsubscribe information. Review whether a footer is required for your email program.",
    whatItChecks:
      "footer_enabled=false on a sendgrid_mail_settings record.",
    whyItMatters:
      "A footer may be required for CAN-SPAM compliance (physical mailing address) or other regulations. Disabling it may require review for compliance.",
    evidence:
      "footer_enabled boolean (footer text content is never stored).",
    remediation:
      "In SendGrid Console, navigate to Settings > Mail Settings and enable the Footer setting with required compliance text.",
    falsePositiveGuard:
      "Only fires when footer_enabled=false on a sendgrid_mail_settings record. Some senders intentionally manage compliance text within email templates instead.",
  },
  {
    key: "sendgrid_bounce_purge_disabled",
    provider: "sendgrid",
    severity: "low",
    title: "SendGrid bounce purge is disabled",
    category: "Mail settings",
    confidence: "high",
    metadataOnly: true,
    description:
      "The SendGrid bounce purge mail setting is disabled. Bounce purge automatically removes addresses from the bounce list after a configured number of days, helping maintain list hygiene.",
    whatItChecks:
      "bounce_purge_enabled=false on a sendgrid_mail_settings record.",
    whyItMatters:
      "Without bounce purge, stale bounce entries may accumulate, affecting deliverability metrics and list hygiene over time.",
    evidence:
      "bounce_purge_enabled boolean from the sendgrid_mail_settings record.",
    remediation:
      "In SendGrid Console, navigate to Settings > Mail Settings and enable Bounce Purge with appropriate soft/hard bounce thresholds.",
    falsePositiveGuard:
      "Only fires when bounce_purge_enabled=false. Some senders manage bounce lists manually and may intentionally disable automatic purge.",
  },
  {
    key: "sendgrid_template_engine_enabled",
    provider: "sendgrid",
    severity: "low",
    title: "SendGrid legacy template engine is enabled",
    category: "Mail settings",
    confidence: "high",
    metadataOnly: true,
    description:
      "The SendGrid legacy template engine mail setting is enabled. The legacy template engine applies a default template to all outgoing messages. This dynamic content surface may require review to confirm the template is current and intentional.",
    whatItChecks:
      "template_enabled=true on a sendgrid_mail_settings record.",
    whyItMatters:
      "An enabled legacy template is applied to all outgoing messages. Stale or unintended templates may affect email appearance or deliverability and may require review.",
    evidence:
      "template_enabled boolean (template content is never stored or inspected).",
    remediation:
      "In SendGrid Console, navigate to Settings > Mail Settings, review the Template setting, and disable it if not required. Consider migrating to Dynamic Templates.",
    falsePositiveGuard:
      "Only fires when template_enabled=true. Template content is never stored. Senders who intentionally use the legacy template engine can acknowledge this finding.",
  },
  {
    key: "sendgrid_google_analytics_tracking_enabled",
    provider: "sendgrid",
    severity: "low",
    title: "SendGrid Google Analytics email tracking is enabled",
    category: "Tracking settings",
    confidence: "high",
    metadataOnly: true,
    description:
      "SendGrid Google Analytics tracking is enabled. When active, SendGrid appends UTM tracking parameters to links in outgoing emails, enabling analytics tracking across email interactions.",
    whatItChecks:
      "ganalytics_enabled=true on a sendgrid_tracking_settings record.",
    whyItMatters:
      "Google Analytics email tracking may have privacy and compliance implications depending on applicable regulations. Review whether tracking use is disclosed in your privacy policy.",
    evidence:
      "ganalytics_enabled boolean (GA campaign parameter values and analytics data are never stored).",
    remediation:
      "In SendGrid Console, navigate to Settings > Tracking, review the Google Analytics setting, and disable it if not required or not compliant with applicable privacy policies.",
    falsePositiveGuard:
      "Only fires when ganalytics_enabled=true. GA parameter values are never stored. Many senders intentionally use this for analytics and have appropriate disclosures.",
  },
  {
    key: "sendgrid_event_webhook_broad_event_stream",
    provider: "sendgrid",
    severity: "low",
    title: "SendGrid event webhook is configured with a broad event stream",
    category: "Webhook configuration",
    confidence: "medium",
    metadataOnly: true,
    description:
      "The SendGrid event webhook is enabled and configured to deliver more than 8 event types. A broad event stream may expose delivery event metadata to the webhook endpoint across a wide surface.",
    whatItChecks:
      "event_webhook_enabled=true AND event_count > 8 on a sendgrid_webhook_settings record.",
    whyItMatters:
      "A broad event stream delivers more delivery event metadata to the webhook endpoint. Review whether all configured event types are required by your application.",
    evidence:
      "event_webhook_enabled and event_count (event payloads and recipient data are never stored).",
    remediation:
      "In SendGrid Console, navigate to Settings > Mail Settings > Event Webhook and review the enabled event types, disabling any that are not required.",
    falsePositiveGuard:
      "Only fires when event_webhook_enabled=true AND event_count > 8. Event payloads are never stored. Many senders intentionally subscribe to a broad set of event types for observability.",
  },
  {
    key: "sendgrid_inbound_parse_enabled",
    provider: "sendgrid",
    severity: "medium",
    title: "SendGrid inbound email parse is enabled",
    category: "Webhook configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "SendGrid inbound email parse is enabled. Inbound parse receives emails sent to a configured hostname and delivers the full email content to a webhook endpoint. This inbound email processing surface may require review.",
    whatItChecks:
      "inbound_parse_enabled=true on a sendgrid_webhook_settings record.",
    whyItMatters:
      "Inbound parse creates an email-to-webhook processing surface that delivers email content including sender, subject, and body to an endpoint. The configuration should be confirmed as intentional and the endpoint secured.",
    evidence:
      "inbound_parse_enabled boolean (hostname, URL, email content, and recipient data are never stored).",
    remediation:
      "In SendGrid Console, navigate to Settings > Inbound Parse, review all configured entries, and remove any that are no longer needed.",
    falsePositiveGuard:
      "Only fires when inbound_parse_enabled=true. Hostname and URL strings are never stored. Many senders intentionally use inbound parse for email-to-ticket or similar integrations.",
  },
  {
    key: "sendgrid_inbound_parse_raw_email_enabled",
    provider: "sendgrid",
    severity: "medium",
    title: "SendGrid inbound parse is configured to send raw email content",
    category: "Webhook configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "SendGrid inbound parse is enabled and configured to deliver raw email content (full MIME message including headers, body, and attachments) to the webhook endpoint. This increases the data sensitivity of the inbound parse surface.",
    whatItChecks:
      "inbound_parse_enabled=true AND inbound_parse_send_raw_enabled=true on a sendgrid_webhook_settings record.",
    whyItMatters:
      "Raw email delivery increases the sensitivity of data flowing to the webhook endpoint. Review whether raw delivery is required or whether parsed fields are sufficient.",
    evidence:
      "inbound_parse_enabled and inbound_parse_send_raw_enabled booleans (raw email content and recipient data are never stored).",
    remediation:
      "In SendGrid Console, navigate to Settings > Inbound Parse, and for each entry review whether 'Send Raw' is required. Disable raw email delivery if parsed fields are sufficient.",
    falsePositiveGuard:
      "Only fires when both inbound_parse_enabled=true AND inbound_parse_send_raw_enabled=true. Raw email content is never stored.",
  },
  {
    key: "sendgrid_inbound_parse_spam_check_disabled",
    provider: "sendgrid",
    severity: "medium",
    title: "SendGrid inbound parse spam check is disabled",
    category: "Webhook configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "SendGrid inbound parse is enabled but the spam check filter is disabled. Without spam check, all inbound emails including unsolicited or malicious messages are forwarded to the webhook endpoint without filtering.",
    whatItChecks:
      "inbound_parse_enabled=true AND inbound_parse_spam_check_enabled=false on a sendgrid_webhook_settings record.",
    whyItMatters:
      "Without spam check, the webhook endpoint receives unfiltered inbound email including potential spam and malicious content. Enabling spam check helps reduce this exposure.",
    evidence:
      "inbound_parse_enabled and inbound_parse_spam_check_enabled booleans.",
    remediation:
      "In SendGrid Console, navigate to Settings > Inbound Parse and enable the Spam Check option for each inbound parse entry.",
    falsePositiveGuard:
      "Only fires when inbound_parse_enabled=true AND inbound_parse_spam_check_enabled=false are both explicitly present. Some senders intentionally handle spam filtering at the application level.",
  },
  // ── Auth0 — M81B ──────────────────────────────────────────────────────────
  {
    key: "auth0_tenant_session_lifetime_extended",
    provider: "auth0",
    severity: "medium",
    title: "Auth0 tenant login session lifetime is extended",
    category: "Tenant session",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 tenant is configured with an extended login session lifetime (greater than 7 days). Extended session lifetimes may increase the window during which a session can be used without re-authentication and may require review for your organization's access-management policy.",
    whatItChecks:
      "session_lifetime_category=='extended' on an auth0_tenant_settings record.",
    whyItMatters:
      "Extended login session lifetimes broaden the window during which authentication state persists without re-validation. Reducing the lifetime aligns with least-privilege access posture.",
    evidence:
      "session_lifetime_category (a safe category label only). No tokens or session content is stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Settings > Tenant Settings > Advanced. Review and reduce the Login Session Lifetime to match your access-management policy (e.g. 1–7 days).",
    falsePositiveGuard:
      "Only fires when session_lifetime_category=='extended'. Tenants that intentionally use extended sessions for specific UX requirements can acknowledge this finding.",
  },
  {
    key: "auth0_tenant_idle_session_lifetime_extended",
    provider: "auth0",
    severity: "low",
    title: "Auth0 tenant idle session lifetime is extended",
    category: "Tenant session",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 tenant is configured with an extended idle session lifetime (greater than 7 days). Idle sessions that persist for an extended period without activity may warrant review for alignment with your access-management policy.",
    whatItChecks:
      "idle_session_lifetime_category=='extended' on an auth0_tenant_settings record.",
    whyItMatters:
      "Extended idle session lifetimes increase the duration over which an unattended session can be re-used. Shorter idle timeouts reduce exposure to abandoned sessions.",
    evidence:
      "idle_session_lifetime_category (a safe category label only).",
    remediation:
      "In the Auth0 Dashboard navigate to Settings > Tenant Settings > Advanced. Reduce the Idle Session Lifetime to match your policy.",
    falsePositiveGuard:
      "Only fires when idle_session_lifetime_category=='extended'.",
  },
  {
    key: "auth0_tenant_dynamic_client_registration_enabled",
    provider: "auth0",
    severity: "high",
    title: "Auth0 tenant has dynamic client registration enabled",
    category: "Tenant configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 tenant has the dynamic client registration flag enabled. Dynamic client registration (RFC 7591) allows external parties to register OAuth clients programmatically and may broaden the tenant's OAuth client surface.",
    whatItChecks:
      "flag_enable_dynamic_client_registration=true on an auth0_tenant_settings record.",
    whyItMatters:
      "Dynamic client registration accepts new OAuth clients without pre-approval. Review is warranted to confirm the capability is required and access is appropriately restricted.",
    evidence:
      "flag_enable_dynamic_client_registration boolean only.",
    remediation:
      "In the Auth0 Dashboard navigate to Settings > Advanced. Disable dynamic client registration if it is not required for your use case.",
    falsePositiveGuard:
      "Only fires when the flag is explicitly true. Tenants that integrate with consent frameworks requiring dynamic registration can acknowledge this finding.",
  },
  {
    key: "auth0_application_no_callbacks",
    provider: "auth0",
    severity: "low",
    title: "Auth0 application has no configured callback URLs",
    category: "Application configuration",
    confidence: "medium",
    metadataOnly: true,
    description:
      "The Auth0 application has no callback URLs configured. Web-based applications typically require at least one callback URL for the OAuth authorization flow to redirect authenticated users.",
    whatItChecks:
      "callbacks_count==0 AND app_type is 'spa' or 'regular_web' on an auth0_application record.",
    whyItMatters:
      "An OAuth-capable web application with zero callback URLs cannot complete the authorization redirect flow. The missing configuration may indicate setup that is incomplete or applications that are stale.",
    evidence:
      "client_id, name (truncated), app_type, callbacks_count (integer). Raw callback URLs are never stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications and select the application. Add the appropriate Allowed Callback URLs under Settings.",
    falsePositiveGuard:
      "CLI / Machine-to-Machine / Native applications are skipped — they do not require callback URLs. Only spa/regular_web apps with callbacks_count==0 fire this rule.",
  },
  {
    key: "auth0_application_many_callbacks",
    provider: "auth0",
    severity: "medium",
    title: "Auth0 application has a large number of callback URLs",
    category: "Application configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 application has more than 10 callback URLs configured. A large callback surface increases the set of redirect destinations that Auth0 will accept after authentication and may include stale entries.",
    whatItChecks:
      "callbacks_count > 10 on an auth0_application record.",
    whyItMatters:
      "Every callback URL is a permitted redirect target. A large set may include test/staging URLs that were never removed and may require review for cleanup.",
    evidence:
      "client_id, name, app_type, callbacks_count (integer). Raw callback URLs are NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the application, and review the Allowed Callback URLs. Remove any stale, test, or non-production entries.",
    falsePositiveGuard:
      "Only fires when callbacks_count > 10. Some applications legitimately require many callbacks (multi-environment deployments) and can acknowledge this finding.",
  },
  {
    key: "auth0_application_many_allowed_origins",
    provider: "auth0",
    severity: "medium",
    title: "Auth0 application has a large number of allowed origins",
    category: "Application configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 application has more than 10 allowed/web origins configured (combined). A large origin surface increases the set of domains permitted to make cross-origin requests to Auth0.",
    whatItChecks:
      "(allowed_origins_count + web_origins_count) > 10 on an auth0_application record.",
    whyItMatters:
      "Every allowed origin permits cross-origin authentication requests. A large set may include stale or unintended origins and may require review.",
    evidence:
      "allowed_origins_count and web_origins_count (integers). Raw origin URLs are NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications and select the application. Review the Allowed Web Origins and Allowed Origins lists; remove stale or non-production entries.",
    falsePositiveGuard:
      "Only fires when the combined count exceeds 10. Multi-tenant or multi-region applications may legitimately require many origins.",
  },
  {
    key: "auth0_application_oidc_non_conformant",
    provider: "auth0",
    severity: "medium",
    title: "Auth0 application is not OIDC conformant",
    category: "Application configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 application has OIDC conformance disabled. Non-OIDC-conformant applications use a legacy Auth0 authentication pipeline that may not support the latest OAuth 2.0 / OpenID Connect features.",
    whatItChecks:
      "oidc_conformant is explicitly false on an auth0_application record.",
    whyItMatters:
      "OIDC-conformant mode aligns Auth0 token formats and flows with the modern OAuth 2.0 / OIDC standards. Non-conformant apps miss security improvements available in newer flows.",
    evidence:
      "client_id, name, app_type, oidc_conformant boolean only.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the application, and under Settings > Advanced Settings > OAuth enable OIDC Conformant. Test your integration after enabling.",
    falsePositiveGuard:
      "Only fires when oidc_conformant is explicitly false. Some legacy applications may have specific reasons for staying on the non-conformant pipeline.",
  },
  {
    key: "auth0_application_weak_jwt_algorithm",
    provider: "auth0",
    severity: "high",
    title: "Auth0 application uses a symmetric JWT signing algorithm",
    category: "Application token signing",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 application is configured to use a symmetric (HS-family) or 'none' JWT signing algorithm. Symmetric HMAC algorithms require the signing secret to be shared with the application for token verification, broadening the secret surface compared to asymmetric algorithms.",
    whatItChecks:
      "jwt_alg is HS256, HS384, HS512, or 'none' on an auth0_application record.",
    whyItMatters:
      "Symmetric signing requires the client to hold the signing secret to verify tokens. RS256/PS256 use Auth0's public key (.well-known/jwks.json), so the client never needs the private signing key.",
    evidence:
      "client_id, name, jwt_alg (a short algorithm label only). No signing keys are ever stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the application, and under Settings > Advanced Settings > OAuth change the JsonWebToken Signature Algorithm to RS256. Update token verification to fetch the public key from Auth0's JWKS endpoint.",
    falsePositiveGuard:
      "Only fires for HS256/HS384/HS512/'none'. RS256/PS256 are considered safe and do not fire this rule.",
  },
  {
    key: "auth0_refresh_token_rotation_disabled",
    provider: "auth0",
    severity: "medium",
    title: "Auth0 application has refresh token rotation disabled",
    category: "Refresh token posture",
    confidence: "medium",
    metadataOnly: true,
    description:
      "The Auth0 application issues refresh tokens but does not have refresh token rotation enabled. Without rotation, a refresh token remains valid indefinitely until explicitly revoked.",
    whatItChecks:
      "refresh_token_rotation_enabled is false AND grant_types_summary contains 'refresh_token' on an auth0_application record.",
    whyItMatters:
      "Rotation invalidates a refresh token each time it is used, so a copied token has a short window of validity. Without rotation, the token is reusable until expiration or explicit revocation.",
    evidence:
      "client_id, name, refresh_token_rotation_enabled, grant_types_summary (safe labels only). No tokens are ever stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the application, and under Settings > Refresh Token Rotation enable rotation. Set appropriate rotation and reuse intervals.",
    falsePositiveGuard:
      "Only fires when the application's grant_types include refresh_token. M2M/CLI apps without refresh tokens are skipped.",
  },
  {
    key: "auth0_refresh_token_lifetime_extended",
    provider: "auth0",
    severity: "medium",
    title: "Auth0 application refresh token lifetime is extended",
    category: "Refresh token posture",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 application has an extended refresh token lifetime (greater than 24 hours). Long-lived refresh tokens extend the window during which a copied token could be used and may require review.",
    whatItChecks:
      "refresh_token_lifetime_category=='extended' on an auth0_application record.",
    whyItMatters:
      "Extended refresh token lifetimes broaden the time window for token misuse if a token were obtained by an unauthorized party. Shorter lifetimes (≤ 24 hours) align with current best practice for sensitive contexts.",
    evidence:
      "client_id, name, refresh_token_lifetime_category (a safe category label only).",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the application, and under Settings > Refresh Token Expiration reduce the absolute lifetime to match your policy.",
    falsePositiveGuard:
      "Only fires when the category is 'extended'. Applications with legitimate long-running offline access needs can acknowledge this finding.",
  },
  {
    key: "auth0_connection_no_enabled_clients",
    provider: "auth0",
    severity: "low",
    title: "Auth0 connection has no enabled client applications",
    category: "Connection configuration",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 connection has no enabled client applications. A connection without enabled clients cannot be used for authentication and may indicate stale or inactive configuration.",
    whatItChecks:
      "enabled_clients_count==0 on an auth0_connection record.",
    whyItMatters:
      "Connections that are not enabled for any application are inert but still consume tenant configuration. Stale connections may warrant cleanup.",
    evidence:
      "connection_id, name (truncated), strategy, enabled_clients_count (integer). Connection credentials NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Authentication (Database / Social / Enterprise) and either enable the connection for the appropriate applications or remove it if unused.",
    falsePositiveGuard:
      "Only fires when enabled_clients_count is exactly 0.",
  },
  {
    key: "auth0_connection_weak_password_policy",
    provider: "auth0",
    severity: "high",
    title: "Auth0 database connection has a weak or unconfigured password policy",
    category: "Connection password policy",
    confidence: "medium",
    metadataOnly: true,
    description:
      "The Auth0 database connection has a password policy category of 'none', 'low', 'fair', or unconfigured. Weak password policies may allow low-complexity passwords that are easier to guess or brute-force.",
    whatItChecks:
      "strategy=='auth0' AND password_policy_category is 'none'/'low'/'fair' or missing on an auth0_connection record.",
    whyItMatters:
      "A 'good' or 'excellent' password policy is recommended for production database connections to reduce the impact of credential-based attacks.",
    evidence:
      "connection_id, name, strategy, password_policy_category (a safe category label only). Connection credentials NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Authentication > Database, select the connection, and under Password Policy set the policy to 'Good' or 'Excellent'. Communicate policy changes to users as required.",
    falsePositiveGuard:
      "Only fires for strategy=='auth0' database connections. Social and enterprise connections (Google, GitHub, SAML, etc.) are skipped.",
  },
  {
    key: "auth0_resource_server_offline_access_enabled",
    provider: "auth0",
    severity: "medium",
    title: "Auth0 API allows offline access (refresh tokens)",
    category: "Resource server token posture",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 resource server allows offline access. Offline access permits applications to request refresh tokens (the offline_access scope) that persist beyond the active session.",
    whatItChecks:
      "allow_offline_access=true on an auth0_resource_server record.",
    whyItMatters:
      "Offline access broadens the token footprint for the API. Review is warranted to confirm offline access is needed by all consumers of this resource server.",
    evidence:
      "resource_server_id, name, allow_offline_access boolean only.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > APIs, select the resource server, and disable Allow Offline Access if refresh tokens are not required.",
    falsePositiveGuard:
      "Only fires when allow_offline_access is explicitly true.",
  },
  {
    key: "auth0_resource_server_token_lifetime_extended",
    provider: "auth0",
    severity: "medium",
    title: "Auth0 API access token lifetime is extended",
    category: "Resource server token posture",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 resource server has an extended access token lifetime (greater than 24 hours). Long-lived access tokens extend the period during which a token is valid.",
    whatItChecks:
      "token_lifetime_category=='extended' on an auth0_resource_server record.",
    whyItMatters:
      "Extended access token lifetimes broaden the impact window if a token requires review or rotation. Short-lived tokens (15 minutes to 1 hour) are recommended for production APIs.",
    evidence:
      "resource_server_id, name, token_lifetime_category (a safe category label only).",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > APIs, select the resource server, and reduce the Token Expiration to ≤ 3600 seconds (1 hour) for sensitive APIs.",
    falsePositiveGuard:
      "Only fires when the category is 'extended'.",
  },
  {
    key: "auth0_resource_server_rbac_disabled",
    provider: "auth0",
    severity: "medium",
    title: "Auth0 API does not enforce RBAC policies",
    category: "Resource server authorization",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 resource server does not enforce RBAC policies. Without RBAC enforcement, permissions and roles are not applied to tokens for this API.",
    whatItChecks:
      "rbac_enabled (enforce_policies) is explicitly false on an auth0_resource_server record.",
    whyItMatters:
      "RBAC enforcement controls access by attaching permissions to access tokens based on the caller's roles. Without enforcement, the access surface may be broader than each caller requires.",
    evidence:
      "resource_server_id, name, rbac_enabled boolean only.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > APIs, select the resource server, and under Settings > RBAC Settings enable 'Enable RBAC' and 'Add Permissions in the Access Token'. Define permissions and assign them to roles.",
    falsePositiveGuard:
      "Only fires when rbac_enabled is explicitly false. APIs that do not use Auth0 RBAC (e.g. those using custom authorization in the resource server) can acknowledge this finding.",
  },
  {
    key: "auth0_rule_disabled",
    provider: "auth0",
    severity: "low",
    title: "Auth0 rule has a script but is disabled",
    category: "Auth pipeline rule",
    confidence: "medium",
    metadataOnly: true,
    description:
      "The Auth0 rule has script content configured but the rule is currently disabled. A disabled rule with an existing script may indicate automation that was paused intentionally or unintentionally.",
    whatItChecks:
      "enabled is explicitly false AND script_present=true on an auth0_rule record.",
    whyItMatters:
      "A disabled rule that contains a script may indicate orphaned automation. Review helps confirm the rule should remain disabled or be removed entirely.",
    evidence:
      "rule_id, name, enabled, script_present, stage. Rule script content is NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Auth Pipeline > Rules, review the rule, and either re-enable it or delete it if no longer needed.",
    falsePositiveGuard:
      "Only fires when a rule has script content AND is disabled. Rules without scripts do not fire this rule.",
  },
  {
    key: "auth0_rule_large_script",
    provider: "auth0",
    severity: "low",
    title: "Auth0 rule has a large script",
    category: "Auth pipeline rule",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 rule has a script greater than 2,000 characters. Large rule scripts can be harder to review, audit, and maintain.",
    whatItChecks:
      "script_length_category=='long' on an auth0_rule record.",
    whyItMatters:
      "Large rule scripts increase the surface that must be reviewed for each change. Refactoring into smaller rules or migrating to Auth0 Actions improves maintainability.",
    evidence:
      "rule_id, name, script_length_category (a safe category label only). Rule script content is NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Auth Pipeline > Rules, review the rule, and consider refactoring or migrating the logic to Auth0 Actions (the modern replacement for Rules).",
    falsePositiveGuard:
      "Only fires when script_length_category is 'long' (>2,000 chars).",
  },
  {
    key: "auth0_action_not_deployed",
    provider: "auth0",
    severity: "low",
    title: "Auth0 action has no deployed version",
    category: "Auth pipeline action",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 action has no deployed version. Actions must be deployed to be active in the authentication pipeline. An action without a deployed version is not currently executing.",
    whatItChecks:
      "deployed_version_present is false on an auth0_action record.",
    whyItMatters:
      "An undeployed action contributes to action-library clutter and may indicate work-in-progress that was never finished or a previously deployed action that was undeployed.",
    evidence:
      "action_id, name, status, deployed_version_present, trigger_id. Action code is NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Auth Pipeline > Actions > Library, select the action, and either deploy it if it is ready or delete it if it is no longer needed.",
    falsePositiveGuard:
      "Only fires when deployed_version_present is false.",
  },
  {
    key: "auth0_action_secrets_present",
    provider: "auth0",
    severity: "low",
    title: "Auth0 action has secrets configured",
    category: "Auth pipeline action",
    confidence: "high",
    metadataOnly: true,
    description:
      "The Auth0 action has one or more secrets configured. Action secrets are credentials stored in Auth0 for use within action code. They represent a credential surface that may require periodic review and rotation.",
    whatItChecks:
      "secrets_count > 0 on an auth0_action record.",
    whyItMatters:
      "Action secrets are credentials embedded in the authentication pipeline. Periodic rotation and access review reduce the impact of any leaked secret.",
    evidence:
      "action_id, name, secrets_count (integer). Secret names and values are NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Auth Pipeline > Actions > Library, review the action's secrets, and rotate them per your organization's credential rotation policy. Remove unused secrets.",
    falsePositiveGuard:
      "Only fires when secrets_count > 0. Actions without configured secrets do not fire this rule.",
  },
  {
    key: "auth0_mfa_factor_disabled",
    provider: "auth0",
    severity: "medium",
    title: "Auth0 strong MFA factor is disabled",
    category: "MFA factor posture",
    confidence: "high",
    metadataOnly: true,
    description:
      "An Auth0 strong Guardian/MFA factor (TOTP, WebAuthn, or push notification) is disabled. Strong second factors provide phishing-resistant or time-based authentication.",
    whatItChecks:
      "enabled is explicitly false AND factor_name is otp / webauthn-roaming / push-notification on an auth0_mfa_factor record.",
    whyItMatters:
      "Disabling strong second factors limits users' ability to enroll in robust MFA. Review is warranted if other strong factors are also unavailable.",
    evidence:
      "factor_name, enabled, provider_category (safe labels only). No enrollment data, recovery codes, or user-level factor status are ever stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Security > Multi-factor Auth. Enable the appropriate strong factors and configure the MFA policy.",
    falsePositiveGuard:
      "Only fires for strong factors (otp / webauthn-roaming / push-notification). Tenants relying on alternative strong factors can acknowledge this finding.",
  },
  {
    key: "auth0_custom_domain_not_ready",
    provider: "auth0",
    severity: "medium",
    title: "Auth0 custom domain is not in a ready state",
    category: "Custom domain",
    confidence: "high",
    metadataOnly: true,
    description:
      "An Auth0 custom domain is in 'pending_verification', 'provisioning', or 'disabled' state rather than 'ready'. A non-ready custom domain may indicate pending DNS verification or a provisioning issue.",
    whatItChecks:
      "status in {pending_verification, provisioning, disabled} on an auth0_custom_domain record.",
    whyItMatters:
      "A non-ready custom domain causes users to fall back to the default Auth0 domain for authentication and may indicate setup work that was never completed.",
    evidence:
      "custom_domain_id, status, type, primary. Custom domain name strings are NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Branding > Custom Domains. Complete pending DNS verification or remove the domain if it should not exist.",
    falsePositiveGuard:
      "Only fires for explicit non-ready statuses. A 'ready' or empty status does not fire this rule.",
  },
  {
    key: "auth0_custom_domain_weak_tls_policy",
    provider: "auth0",
    severity: "low",
    title: "Auth0 custom domain uses a compatible (non-recommended) TLS policy",
    category: "Custom domain",
    confidence: "high",
    metadataOnly: true,
    description:
      "An Auth0 custom domain is configured with the 'compatible' TLS policy rather than the 'recommended' policy. The compatible policy supports older TLS versions and cipher suites.",
    whatItChecks:
      "tls_policy_category=='compatible' on an auth0_custom_domain record.",
    whyItMatters:
      "The 'recommended' policy enforces current TLS best practices, while 'compatible' allows legacy clients but may also accept weaker cipher negotiations.",
    evidence:
      "custom_domain_id, tls_policy_category, status. Custom domain name strings are NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Branding > Custom Domains, select the domain, and change the TLS policy to 'Recommended'. Verify legacy clients still work after the change.",
    falsePositiveGuard:
      "Only fires when tls_policy_category=='compatible'. Tenants that need legacy client support may acknowledge this finding.",
  },
  // ── Auth0 — M81C OAuth/application risk expansion ──────────────────────────
  {
    key: "auth0_application_password_grant_enabled",
    provider: "auth0",
    severity: "high",
    confidence: "high",
    metadataOnly: true,
    category: "OAuth grant type posture",
    title: "Auth0 application has the password grant enabled",
    description:
      "The application has the OAuth 2.0 Resource Owner Password Credentials (ROPC) grant enabled. The password grant requires the application to handle user credentials directly, bypassing Auth0 Universal Login.",
    whatItChecks:
      "grant_password_enabled=true on an auth0_application record.",
    whyItMatters:
      "The password grant is deprecated in OAuth 2.1 and reduces phishing resistance by bypassing the identity provider's login UI. Authorization code + PKCE is the recommended replacement.",
    evidence:
      "client_id, name, app_type, grant_password_enabled. No credential values are stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the app, then Advanced Settings > Grant Types and disable Password. Migrate to authorization_code with PKCE.",
    falsePositiveGuard:
      "Only fires when grant_password_enabled=true. Legacy applications that cannot yet migrate may need to acknowledge this finding.",
  },
  {
    key: "auth0_application_implicit_grant_enabled",
    provider: "auth0",
    severity: "high",
    confidence: "high",
    metadataOnly: true,
    category: "OAuth grant type posture",
    title: "Auth0 application has the implicit grant enabled",
    description:
      "The application has the OAuth 2.0 implicit grant enabled. The implicit grant returns access tokens in the URL fragment, which may expose tokens in browser history, referrer headers, and server logs.",
    whatItChecks:
      "grant_implicit_enabled=true on an auth0_application record.",
    whyItMatters:
      "The implicit grant is deprecated in OAuth 2.1 in favor of authorization code + PKCE, which does not expose tokens in the URL.",
    evidence:
      "client_id, name, app_type, grant_implicit_enabled.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the app, then Advanced Settings > Grant Types and disable Implicit. Migrate to authorization_code with PKCE.",
    falsePositiveGuard:
      "Only fires when grant_implicit_enabled=true. Legacy SPAs that cannot yet migrate to PKCE may need to acknowledge this finding.",
  },
  {
    key: "auth0_application_public_client_credentials_enabled",
    provider: "auth0",
    severity: "high",
    confidence: "high",
    metadataOnly: true,
    category: "OAuth grant type posture",
    title: "Auth0 public or client-side application has client credentials grant enabled",
    description:
      "The application has the client_credentials grant enabled, but the application is a public or client-side app (SPA, native, or token_endpoint_auth_method=none). Public apps cannot securely store client secrets.",
    whatItChecks:
      "grant_client_credentials_enabled=true AND (app_type is spa/native OR token_endpoint_auth_method=none) on an auth0_application record.",
    whyItMatters:
      "The client credentials grant requires a confidential client that can protect a client secret. Public apps that expose a client secret may broaden access beyond what is intended.",
    evidence:
      "client_id, name, app_type, grant_client_credentials_enabled, token_endpoint_auth_method. No client secret is stored.",
    remediation:
      "In the Auth0 Dashboard, disable the Client Credentials grant for this application. If M2M access is needed, create a separate non_interactive (M2M) application.",
    falsePositiveGuard:
      "Only fires when client_credentials is enabled AND the application is a public/client-side app. Confidential regular_web and non_interactive apps are not flagged.",
  },
  {
    key: "auth0_application_refresh_grant_without_rotation",
    provider: "auth0",
    severity: "medium",
    confidence: "high",
    metadataOnly: true,
    category: "Refresh token posture",
    title: "Auth0 application has the refresh token grant enabled without rotation",
    description:
      "The application has the refresh_token grant explicitly enabled but does not have refresh token rotation configured. Without rotation, a refresh token remains valid until it expires or is explicitly revoked.",
    whatItChecks:
      "grant_refresh_token_enabled=true AND refresh_token_rotation_enabled=false on an auth0_application record.",
    whyItMatters:
      "Refresh token rotation limits the window during which a token may require review or rotation by issuing a new token on each use and invalidating the previous one.",
    evidence:
      "client_id, name, grant_refresh_token_enabled, refresh_token_rotation_enabled. No token values are stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the app, and enable Refresh Token Rotation under Settings.",
    falsePositiveGuard:
      "Only fires when grant_refresh_token_enabled=true AND rotation is explicitly false.",
  },
  {
    key: "auth0_application_many_grant_types",
    provider: "auth0",
    severity: "medium",
    confidence: "high",
    metadataOnly: true,
    category: "OAuth grant type posture",
    title: "Auth0 application has a broad OAuth grant type surface",
    description:
      "The application has more than 4 OAuth grant types enabled, which may include deprecated or high-risk grant types and increases the number of OAuth flows the application accepts.",
    whatItChecks:
      "grant_types_count > 4 on an auth0_application record.",
    whyItMatters:
      "Each enabled grant type adds an additional OAuth flow surface. Restricting grant types to only what is needed reduces the attack surface.",
    evidence:
      "client_id, name, grant_types_count, grant_types_summary.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the app, then Advanced Settings > Grant Types and disable any grants not required.",
    falsePositiveGuard:
      "Only fires when grant_types_count exceeds 4. Applications with legitimate broad grant type requirements may need to acknowledge this finding.",
  },
  {
    key: "auth0_application_device_code_grant_enabled",
    provider: "auth0",
    severity: "low",
    confidence: "high",
    metadataOnly: true,
    category: "OAuth grant type posture",
    title: "Auth0 application has the device code grant enabled",
    description:
      "The application has the Device Authorization Grant (RFC 8628) enabled. This adds an additional OAuth flow surface designed for input-constrained devices.",
    whatItChecks:
      "grant_device_code_enabled=true on an auth0_application record.",
    whyItMatters:
      "The device code flow adds an additional OAuth surface that may require review if not needed for the application's intended use case.",
    evidence:
      "client_id, name, app_type, grant_device_code_enabled.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the app, then Advanced Settings > Grant Types and disable Device Code if not needed.",
    falsePositiveGuard:
      "Only fires when grant_device_code_enabled=true. IoT and device-flow applications legitimately use this grant.",
  },
  {
    key: "auth0_application_wildcard_callback",
    provider: "auth0",
    severity: "high",
    confidence: "high",
    metadataOnly: true,
    category: "Application callback posture",
    title: "Auth0 application has a wildcard callback URL configured",
    description:
      "The application has one or more callback URLs containing a wildcard character. Wildcard callbacks may allow authorization codes and tokens to be redirected to unexpected destinations.",
    whatItChecks:
      "wildcard_callback_present=true (a boolean derived from callback URLs during normalization) on an auth0_application record.",
    whyItMatters:
      "A wildcard callback may accept redirects to a broad set of destinations, potentially including attacker-controlled domains. Raw callback URL strings are never stored by ConfigTrace.",
    evidence:
      "client_id, name, wildcard_callback_present, callbacks_count. Raw callback URLs are NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the app, and replace wildcard callback URLs with fully-qualified, explicit URLs.",
    falsePositiveGuard:
      "Only fires when wildcard_callback_present=true. Raw callback URLs are never stored or surfaced.",
  },
  {
    key: "auth0_application_wildcard_allowed_origin",
    provider: "auth0",
    severity: "high",
    confidence: "high",
    metadataOnly: true,
    category: "Application origin posture",
    title: "Auth0 application has a wildcard allowed origin configured",
    description:
      "The application has one or more allowed origins containing a wildcard character. Wildcard origins may permit cross-origin requests from a broad set of domains.",
    whatItChecks:
      "wildcard_allowed_origin_present=true (a boolean derived from allowed_origins during normalization) on an auth0_application record.",
    whyItMatters:
      "A wildcard origin may expose targeted resources to unintended callers by permitting cross-origin requests from any domain matching the pattern. Raw origin URL strings are never stored.",
    evidence:
      "client_id, name, wildcard_allowed_origin_present, allowed_origins_count. Raw origin URLs are NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the app, and replace wildcard allowed origins with specific, fully-qualified origins.",
    falsePositiveGuard:
      "Only fires when wildcard_allowed_origin_present=true. Raw origin URLs are never stored or surfaced.",
  },
  {
    key: "auth0_application_wildcard_logout_url",
    provider: "auth0",
    severity: "medium",
    confidence: "high",
    metadataOnly: true,
    category: "Application logout posture",
    title: "Auth0 application has a wildcard logout URL configured",
    description:
      "The application has one or more allowed logout URLs containing a wildcard character. Wildcard logout URLs may allow post-logout redirects to unexpected destinations.",
    whatItChecks:
      "wildcard_logout_url_present=true (a boolean derived from allowed_logout_urls during normalization) on an auth0_application record.",
    whyItMatters:
      "A wildcard logout URL may redirect users to unintended destinations after logout. Raw logout URL strings are never stored by ConfigTrace.",
    evidence:
      "client_id, name, wildcard_logout_url_present. Raw logout URLs are NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the app, and replace wildcard logout URLs with specific, fully-qualified URLs.",
    falsePositiveGuard:
      "Only fires when wildcard_logout_url_present=true. Raw logout URLs are never stored or surfaced.",
  },
  {
    key: "auth0_application_localhost_callback",
    provider: "auth0",
    severity: "low",
    confidence: "high",
    metadataOnly: true,
    category: "Application callback posture",
    title: "Auth0 application has a localhost callback URL configured",
    description:
      "The application has one or more callback URLs pointing to localhost or a loopback address. These are common during local development but may indicate development configuration left in a production application.",
    whatItChecks:
      "localhost_callback_present=true (a boolean derived from callback URLs during normalization) on an auth0_application record.",
    whyItMatters:
      "Localhost callbacks in production applications may indicate stale development configuration that should be reviewed and cleaned up.",
    evidence:
      "client_id, name, localhost_callback_present, callbacks_count. Raw callback URLs are NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the app, and remove localhost callback URLs if this is a production application.",
    falsePositiveGuard:
      "Only fires when localhost_callback_present=true. Development and local-testing applications legitimately use localhost callbacks.",
  },
  {
    key: "auth0_application_localhost_origin",
    provider: "auth0",
    severity: "low",
    confidence: "high",
    metadataOnly: true,
    category: "Application origin posture",
    title: "Auth0 application has a localhost allowed origin configured",
    description:
      "The application has one or more allowed origins pointing to localhost or a loopback address. These are common during local development but may indicate development configuration left in a production application.",
    whatItChecks:
      "localhost_origin_present=true (a boolean derived from allowed_origins during normalization) on an auth0_application record.",
    whyItMatters:
      "Localhost origins in production applications may indicate stale development configuration that should be reviewed.",
    evidence:
      "client_id, name, localhost_origin_present, allowed_origins_count. Raw origin URLs are NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the app, and remove localhost allowed origins if this is a production application.",
    falsePositiveGuard:
      "Only fires when localhost_origin_present=true. Development and local-testing applications legitimately use localhost origins.",
  },
  {
    key: "auth0_application_callback_missing_https",
    provider: "auth0",
    severity: "medium",
    confidence: "high",
    metadataOnly: true,
    category: "Application callback posture",
    title: "Auth0 application has callback URLs using insecure HTTP",
    description:
      "The application has one or more callback URLs configured with http:// rather than https:// (excluding localhost). Unencrypted callbacks may expose authorization codes or tokens in transit.",
    whatItChecks:
      "callbacks_missing_https=true (a boolean derived from callback URLs during normalization, excluding localhost) on an auth0_application record.",
    whyItMatters:
      "HTTP callbacks transmit authorization codes and state in cleartext, which may allow interception. Raw callback URL strings are never stored by ConfigTrace.",
    evidence:
      "client_id, name, callbacks_missing_https, callbacks_count. Raw callback URLs are NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the app, and update any http:// callback URLs to use https://.",
    falsePositiveGuard:
      "Only fires when callbacks_missing_https=true (excluding localhost and loopback). Internal or controlled-network applications may acknowledge this finding.",
  },
  {
    key: "auth0_application_origin_missing_https",
    provider: "auth0",
    severity: "medium",
    confidence: "high",
    metadataOnly: true,
    category: "Application origin posture",
    title: "Auth0 application has allowed origins using insecure HTTP",
    description:
      "The application has one or more allowed origins configured with http:// rather than https:// (excluding localhost). Permitting unencrypted origins may allow cross-origin requests from insecure contexts.",
    whatItChecks:
      "allowed_origins_missing_https=true (a boolean derived from allowed_origins during normalization, excluding localhost) on an auth0_application record.",
    whyItMatters:
      "HTTP origins may expose cross-origin requests to interception. Raw origin URL strings are never stored by ConfigTrace.",
    evidence:
      "client_id, name, allowed_origins_missing_https, allowed_origins_count. Raw origin URLs are NEVER stored.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the app, and update any http:// allowed origins to use https://.",
    falsePositiveGuard:
      "Only fires when allowed_origins_missing_https=true (excluding localhost). Internal or controlled-network applications may acknowledge this finding.",
  },
  {
    key: "auth0_public_client_refresh_tokens_enabled",
    provider: "auth0",
    severity: "medium",
    confidence: "medium",
    metadataOnly: true,
    category: "Refresh token posture",
    title: "Auth0 public client has the refresh token grant enabled",
    description:
      "The application is a public client (SPA or native app) and has the refresh_token grant enabled. Public clients cannot securely store client secrets, making long-lived refresh tokens harder to protect.",
    whatItChecks:
      "grant_refresh_token_enabled=true AND app_type is spa/native on an auth0_application record.",
    whyItMatters:
      "Public clients should use short-lived tokens with refresh token rotation and sender-constraining where possible to reduce the impact window if a token may require review or rotation.",
    evidence:
      "client_id, name, app_type, grant_refresh_token_enabled. No token values are stored.",
    remediation:
      "Ensure refresh token rotation is enabled for this application. Set a short absolute expiry appropriate for the risk profile. In the Auth0 Dashboard navigate to Applications > Applications > Settings > Refresh Token Rotation.",
    falsePositiveGuard:
      "Only fires when grant_refresh_token_enabled=true AND app_type is spa/native. This is expected posture; the finding prompts review of rotation and expiry settings.",
  },
  {
    key: "auth0_application_token_endpoint_auth_none",
    provider: "auth0",
    severity: "medium",
    confidence: "high",
    metadataOnly: true,
    category: "Token endpoint posture",
    title: "Auth0 application has token endpoint authentication method set to none",
    description:
      "The application has token_endpoint_auth_method set to 'none', meaning it does not authenticate to the token endpoint with a client secret or assertion. This is expected for public clients using PKCE but may require review for confidential client types.",
    whatItChecks:
      "token_endpoint_auth_method=='none' on an auth0_application record.",
    whyItMatters:
      "Confidential clients (regular_web, non_interactive) should authenticate to the token endpoint. An auth method of 'none' on a confidential client type may indicate misconfiguration.",
    evidence:
      "client_id, name, app_type, token_endpoint_auth_method.",
    remediation:
      "In the Auth0 Dashboard navigate to Applications > Applications, select the app, and verify the token endpoint authentication method matches the application type. Confidential clients should use client_secret_basic or client_secret_post.",
    falsePositiveGuard:
      "Only fires when token_endpoint_auth_method=='none'. SPAs and native apps using authorization_code + PKCE legitimately use this setting.",
  },

  // ── Datadog (M82B) ────────────────────────────────────────────────────────
  {
    key: "datadog_monitor_disabled",
    provider: "datadog",
    severity: "medium",
    title: "Datadog monitor is disabled",
    category: "Monitor posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog monitor is currently disabled (silenced or muted).",
    whatItChecks: "The enabled boolean on each datadog_monitor record.",
    whyItMatters:
      "Disabled monitors do not send alerts, which may leave gaps in observability coverage and alert posture.",
    evidence: "Monitor record ID, monitor type, enabled status.",
    remediation: "Re-enable the monitor if it should be active, or archive it if no longer needed.",
    falsePositiveGuard:
      "Only fires when enabled is explicitly false. Intentionally silenced monitors may fire; review the context before acting.",
  },
  {
    key: "datadog_monitor_unrestricted_roles",
    provider: "datadog",
    severity: "low",
    title: "Datadog monitor has no restricted roles",
    category: "Monitor posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A Datadog monitor is not restricted to any role, allowing any team member with edit access to modify it.",
    whatItChecks: "The restricted_roles_count on each datadog_monitor record.",
    whyItMatters:
      "Monitors without role restrictions can be muted, modified, or deleted by any Datadog user with editor access.",
    evidence: "Monitor record ID, restricted_roles_count.",
    remediation: "Add role-based access restrictions to the monitor in Organization Settings > Roles.",
    falsePositiveGuard:
      "Many monitors are intentionally open within an organization. Medium confidence — review before acting.",
  },
  {
    key: "datadog_monitor_notify_no_data_disabled",
    provider: "datadog",
    severity: "low",
    title: "Datadog monitor does not notify on missing data",
    category: "Monitor posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A Datadog monitor has the 'notify on no data' option disabled.",
    whatItChecks: "The notify_no_data boolean on each datadog_monitor record.",
    whyItMatters:
      "When data stops arriving (e.g. an agent or integration goes offline), the monitor will not alert, creating a silent monitoring gap.",
    evidence: "Monitor record ID, notify_no_data status.",
    remediation:
      "Enable 'Notify if data is missing' in the monitor settings if the monitor covers a surface where data loss should trigger an alert.",
    falsePositiveGuard:
      "Many monitors legitimately do not require no-data notification (e.g. event-based monitors). Review context before acting.",
  },
  {
    key: "datadog_monitor_long_query",
    provider: "datadog",
    severity: "low",
    title: "Datadog monitor has a long query",
    category: "Monitor posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A Datadog monitor has a query classified as long in length.",
    whatItChecks: "The query_complexity_category on each datadog_monitor record (value: 'long').",
    whyItMatters:
      "Complex, long queries may be harder to audit, more prone to unintended behavior, and more difficult to maintain.",
    evidence: "Monitor record ID, query_complexity_category. Raw query content is never stored.",
    remediation:
      "Review the monitor query for clarity and consider splitting it into multiple focused monitors.",
    falsePositiveGuard:
      "Only fires for 'long' query complexity. Length alone does not indicate a security issue — review the query intent.",
  },
  {
    key: "datadog_slo_no_monitors",
    provider: "datadog",
    severity: "medium",
    title: "Datadog monitor-based SLO has no linked monitors",
    category: "SLO posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog monitor-based SLO has zero linked monitors and may not be measuring anything.",
    whatItChecks: "The slo_type and monitor_count on each datadog_slo record.",
    whyItMatters:
      "An SLO without linked monitors does not track reliability and may represent an incomplete or outdated configuration.",
    evidence: "SLO record ID, slo_type, monitor_count.",
    remediation:
      "Link the relevant monitors to this SLO, or delete the SLO if it is no longer needed.",
    falsePositiveGuard:
      "Only fires for slo_type='monitor' SLOs. Metric-based SLOs are not evaluated by this rule.",
  },
  {
    key: "datadog_slo_low_target",
    provider: "datadog",
    severity: "low",
    title: "Datadog SLO has a target below 95%",
    category: "SLO posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A Datadog SLO has a configured target below 95%.",
    whatItChecks: "The target_category on each datadog_slo record.",
    whyItMatters:
      "A very low reliability target may indicate the SLO is outdated, set as a placeholder, or does not reflect operational expectations.",
    evidence: "SLO record ID, target_category.",
    remediation: "Review and update the SLO target to align with your service-level agreements.",
    falsePositiveGuard:
      "A low target may be a deliberate business decision for non-critical services. Review context before acting.",
  },
  {
    key: "datadog_dashboard_public_url_present",
    provider: "datadog",
    severity: "medium",
    title: "Datadog dashboard has a public sharing URL",
    category: "Dashboard posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog dashboard has a public sharing URL enabled, making it accessible without Datadog authentication.",
    whatItChecks: "The public_url_present boolean on each datadog_dashboard record.",
    whyItMatters:
      "Publicly shared dashboards are accessible to anyone with the URL, which may expose metric names, infrastructure topology, or operational indicators.",
    evidence: "Dashboard record ID, public_url_present. The URL value is never stored.",
    remediation:
      "Revoke the public sharing URL in the dashboard Share settings if external access is not required.",
    falsePositiveGuard:
      "Only fires when public_url_present=true. Public dashboards may be intentional for status pages — review before acting.",
  },
  {
    key: "datadog_dashboard_unrestricted_roles",
    provider: "datadog",
    severity: "low",
    title: "Datadog dashboard has no restricted roles",
    category: "Dashboard posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A Datadog dashboard is not restricted to any role.",
    whatItChecks: "The restricted_roles_count on each datadog_dashboard record.",
    whyItMatters:
      "Dashboards without role restrictions can be viewed and edited by any Datadog user, which may be inappropriate for sensitive operational data.",
    evidence: "Dashboard record ID, restricted_roles_count.",
    remediation: "Add role-based access restrictions to sensitive dashboards in the Dashboard Settings.",
    falsePositiveGuard:
      "Dashboards are commonly open within an organization. Low severity — review sensitive dashboards specifically.",
  },
  {
    key: "datadog_webhook_without_secret_headers",
    provider: "datadog",
    severity: "high",
    title: "Datadog webhook has no secret header",
    category: "Webhook posture",
    confidence: "high",
    metadataOnly: true,
    description:
      "A Datadog webhook integration has a URL configured but no secret header to verify the origin of deliveries.",
    whatItChecks:
      "The url_present and secret_headers_present booleans on each datadog_webhook_integration record.",
    whyItMatters:
      "Without a shared secret header, the receiving endpoint cannot verify that incoming requests originate from Datadog, potentially allowing spoofed deliveries.",
    evidence:
      "Webhook record ID, url_present, secret_headers_present. Webhook URL and header values are never stored.",
    remediation:
      "Add a custom secret header to the webhook in Integrations > Webhooks and validate it on the receiving endpoint.",
    falsePositiveGuard:
      "Only fires when url_present=true AND secret_headers_present=false. Webhook URL values are never read or stored.",
  },
  {
    key: "datadog_webhook_payload_template_present",
    provider: "datadog",
    severity: "low",
    title: "Datadog webhook has a custom payload template",
    category: "Webhook posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A Datadog webhook integration has a custom payload template configured.",
    whatItChecks: "The payload_template_present boolean on each datadog_webhook_integration record.",
    whyItMatters:
      "Custom payload templates define the structure of data sent to webhook endpoints. Templates may include variable substitutions that expose operational details.",
    evidence: "Webhook record ID, payload_template_present. Raw template content is never stored.",
    remediation:
      "Review the webhook payload template in Integrations > Webhooks to confirm it does not include sensitive variable substitutions.",
    falsePositiveGuard:
      "Only fires when payload_template_present=true. Custom templates are commonly used and may be intentional.",
  },
  {
    key: "datadog_notification_integration_no_channels",
    provider: "datadog",
    severity: "low",
    title: "Datadog notification integration has no configured channels",
    category: "Notification integration posture",
    confidence: "medium",
    metadataOnly: true,
    description:
      "A Datadog notification integration is configured but has no channels or handles set up.",
    whatItChecks:
      "The enabled, handle_count, and channel_count on each datadog_notification_integration record.",
    whyItMatters:
      "A notification integration without configured destinations will not deliver alerts, creating a silent routing gap.",
    evidence:
      "Notification integration record ID, integration_type, handle_count, channel_count. Destination handles and channel names are never stored.",
    remediation:
      "Configure the required notification channels in the integration settings, or remove the integration if it is no longer needed.",
    falsePositiveGuard:
      "Only fires when the integration is enabled but both handle_count and channel_count are 0.",
  },
  {
    key: "datadog_application_key_broad_scopes",
    provider: "datadog",
    severity: "medium",
    title: "Datadog application key has a broad scope count",
    category: "Application key posture",
    confidence: "high",
    metadataOnly: true,
    description:
      "A Datadog application key has more than 10 scopes configured, granting broad API access.",
    whatItChecks: "The scopes_count on each datadog_application_key_metadata record.",
    whyItMatters:
      "Application keys with many scopes have broad access to the Datadog organization's API. Limiting scopes reduces the blast radius of a compromised key.",
    evidence:
      "Application key record ID, scopes_count. Scope names and key values are never stored.",
    remediation:
      "Review the application key's scopes in Organization Settings > Application Keys and remove unnecessary permissions.",
    falsePositiveGuard:
      "Only fires when scopes_count exceeds 10. Some automation use cases legitimately require broad scopes.",
  },
  {
    key: "datadog_api_key_disabled",
    provider: "datadog",
    severity: "low",
    title: "Datadog API key is disabled",
    category: "API key posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog API key in the inventory is disabled or revoked.",
    whatItChecks: "The disabled boolean on each datadog_api_key_metadata record.",
    whyItMatters:
      "Disabled keys in the active inventory may represent stale automation credentials or a prior revocation event that should be cleaned up.",
    evidence: "API key record ID, disabled status. Key values are never stored.",
    remediation:
      "Remove disabled API keys from the inventory in Organization Settings > API Keys if they are no longer needed.",
    falsePositiveGuard:
      "Only fires when disabled=true. Disabled keys do not grant access but may warrant inventory cleanup.",
  },
  {
    key: "datadog_role_high_permission_count",
    provider: "datadog",
    severity: "medium",
    title: "Datadog role has a high permission count",
    category: "Role posture",
    confidence: "high",
    metadataOnly: true,
    description:
      "A Datadog role has more than 25 permissions configured, granting broad organizational access.",
    whatItChecks: "The permission_count on each datadog_role record.",
    whyItMatters:
      "Roles with many permissions grant broad access to Datadog resources. Limiting permissions follows the principle of least privilege.",
    evidence:
      "Role record ID, permission_count. User identities assigned to the role are never stored.",
    remediation:
      "Review the role's permissions in Organization Settings > Roles and remove unnecessary grants.",
    falsePositiveGuard:
      "Only fires when permission_count exceeds 25. Some administrative roles legitimately require many permissions.",
  },
  {
    key: "datadog_team_no_members",
    provider: "datadog",
    severity: "low",
    title: "Datadog team has no members",
    category: "Team posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog team has zero members.",
    whatItChecks: "The member_count on each datadog_team record.",
    whyItMatters:
      "An empty team may indicate stale configuration. Notifications and on-call routing that reference this team may not reach any responders.",
    evidence: "Team record ID, member_count. Member identities are never stored.",
    remediation:
      "Add members to the team or delete it if it is no longer needed.",
    falsePositiveGuard:
      "Only fires when member_count==0. Teams are counted at the time of the last sync.",
  },
  {
    key: "datadog_cloud_integration_broad_collection",
    provider: "datadog",
    severity: "medium",
    title: "Datadog cloud integration has all collection types enabled",
    category: "Cloud integration posture",
    confidence: "high",
    metadataOnly: true,
    description:
      "A Datadog cloud integration has resource collection, metric collection, and log collection all simultaneously enabled.",
    whatItChecks:
      "The resource_collection_enabled, metric_collection_enabled, and log_collection_enabled flags on each datadog_cloud_integration record.",
    whyItMatters:
      "Enabling all collection types grants Datadog broad read access to your cloud environment, including logs that may contain application data.",
    evidence:
      "Cloud integration record ID, cloud_provider, collection flags. Account IDs are never stored.",
    remediation:
      "Review the cloud integration's collection scope and disable collection types that are not required.",
    falsePositiveGuard:
      "Only fires when all three collection flags are simultaneously true. Broad collection may be intentional for full observability.",
  },
  {
    key: "datadog_cloud_integration_log_collection_enabled",
    provider: "datadog",
    severity: "low",
    title: "Datadog cloud integration has log collection enabled",
    category: "Cloud integration posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog cloud integration has log collection enabled.",
    whatItChecks: "The log_collection_enabled flag on each datadog_cloud_integration record.",
    whyItMatters:
      "Log collection forwards cloud logs to Datadog, which may include application output, access logs, or other operational data. The scope of log forwarding may warrant review.",
    evidence:
      "Cloud integration record ID, cloud_provider, log_collection_enabled. Log content and account IDs are never stored.",
    remediation:
      "Review log forwarding scope and configure exclusion filters to prevent sensitive application logs from being forwarded.",
    falsePositiveGuard:
      "Log collection is a primary Datadog use case. Low severity — review the log exclusion filter configuration.",
  },

  // ── Datadog (M82C — monitor/webhook risk expansion) ───────────────────────
  {
    key: "datadog_monitor_no_notifications",
    provider: "datadog",
    severity: "medium",
    title: "Datadog monitor has no notification routing",
    category: "Monitor notification posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog monitor's message contains no notification routing (no @mentions).",
    whatItChecks: "The notification_routing_present boolean on each datadog_monitor record (derived from message before discarding).",
    whyItMatters:
      "Without notification routing, alerts from this monitor may not reach the on-call team. Raw message content is never stored.",
    evidence: "Monitor record ID, notification_routing_present, notification_count. Raw message content is never stored.",
    remediation:
      "Add at least one @notification target (e.g. @slack-channel, @pagerduty-service) to the monitor message.",
    falsePositiveGuard:
      "Only fires when notification_routing_present=false. Monitors intentionally without routing (silent monitoring) may fire.",
  },
  {
    key: "datadog_monitor_message_template_present",
    provider: "datadog",
    severity: "low",
    title: "Datadog monitor message uses template variables",
    category: "Monitor notification posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A Datadog monitor's notification message uses template variables (e.g. {{value}}, {{host.name}}).",
    whatItChecks: "The message_template_present boolean on each datadog_monitor record (derived from message before discarding).",
    whyItMatters:
      "Template variables expand to live values at alert time. Reviewing periodically confirms the expanded content is appropriate for the notification channel.",
    evidence: "Monitor record ID, message_template_present. Raw message content is never stored.",
    remediation:
      "Review the monitor notification message template to confirm variable expansions are appropriate for the audience.",
    falsePositiveGuard:
      "Only fires when message_template_present=true. Template variables are very common and expected in most monitors.",
  },
  {
    key: "datadog_monitor_no_warning_threshold",
    provider: "datadog",
    severity: "medium",
    title: "Datadog monitor has a critical threshold but no warning threshold",
    category: "Monitor threshold posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog monitor is configured with a critical threshold but no warning threshold.",
    whatItChecks: "The threshold_critical_present and threshold_warning_present booleans on each datadog_monitor record.",
    whyItMatters:
      "Without a warning threshold, the monitor transitions directly from OK to ALERT with no intermediate state, reducing early-warning signal.",
    evidence: "Monitor record ID, threshold_critical_present, threshold_warning_present. Raw threshold values are never stored.",
    remediation:
      "Add a Warning threshold below the Critical threshold in the monitor alert conditions.",
    falsePositiveGuard:
      "Only fires when threshold_critical_present=true AND threshold_warning_present=false. Some monitor types do not support warning thresholds.",
  },
  {
    key: "datadog_monitor_no_recovery_threshold",
    provider: "datadog",
    severity: "low",
    title: "Datadog monitor has no recovery threshold",
    category: "Monitor threshold posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog monitor has a critical threshold but no recovery threshold configured.",
    whatItChecks: "The threshold_critical_present and threshold_recovery_present booleans on each datadog_monitor record.",
    whyItMatters:
      "Without a recovery threshold, the monitor may remain in alert state or flap frequently between states.",
    evidence: "Monitor record ID, threshold_critical_present, threshold_recovery_present. Raw threshold values are never stored.",
    remediation:
      "Add a recovery threshold in the monitor's advanced alert conditions.",
    falsePositiveGuard:
      "Only fires when threshold_critical_present=true AND threshold_recovery_present=false. Many monitors function correctly without explicit recovery thresholds.",
  },
  {
    key: "datadog_monitor_silenced_scopes_present",
    provider: "datadog",
    severity: "medium",
    title: "Datadog monitor has silenced scopes",
    category: "Monitor posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog monitor has one or more silenced scopes that suppress alerts for specific hosts or tags.",
    whatItChecks: "The silenced_scope_count on each datadog_monitor record (derived from silenced dict before discarding).",
    whyItMatters:
      "Silenced scopes may represent acknowledged maintenance or forgotten suppressions that should be reviewed periodically.",
    evidence: "Monitor record ID, silenced_scope_count. Silenced scope identifiers are never stored.",
    remediation:
      "Review and remove expired or unintended silenced scopes in the Monitors > Manage Monitors > Muting section.",
    falsePositiveGuard:
      "Only fires when silenced_scope_count > 0. Active maintenance silences are expected and may fire intentionally.",
  },
  {
    key: "datadog_monitor_notify_audit_disabled",
    provider: "datadog",
    severity: "low",
    title: "Datadog monitor does not notify on audit changes",
    category: "Monitor posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A Datadog monitor has audit notifications disabled.",
    whatItChecks: "The notify_audit boolean on each datadog_monitor record.",
    whyItMatters:
      "Without audit notifications, changes to monitor settings do not trigger alerts to the monitor's recipients, reducing visibility into configuration changes.",
    evidence: "Monitor record ID, notify_audit.",
    remediation:
      "Enable 'Notify if this alert is modified' in the monitor settings.",
    falsePositiveGuard:
      "Audit notifications are commonly disabled. Low severity — review only for monitors covering sensitive surfaces.",
  },
  {
    key: "datadog_monitor_require_full_window_disabled",
    provider: "datadog",
    severity: "low",
    title: "Datadog monitor does not require a full evaluation window",
    category: "Monitor evaluation posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A Datadog monitor has 'require full window' disabled, allowing evaluation on partial data.",
    whatItChecks: "The require_full_window boolean on each datadog_monitor record.",
    whyItMatters:
      "Evaluating on partial data windows can produce alerts based on incomplete data, leading to false positives.",
    evidence: "Monitor record ID, require_full_window.",
    remediation:
      "Enable 'Require full window of data' in the monitor advanced options if incomplete data periods should not trigger alerts.",
    falsePositiveGuard:
      "Disabled by default for many monitor types. Medium confidence — review for alerting-sensitive monitors.",
  },
  {
    key: "datadog_monitor_query_wildcard_scope",
    provider: "datadog",
    severity: "medium",
    title: "Datadog monitor uses a wildcard scope",
    category: "Monitor query posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog monitor's query uses a wildcard scope ({*}), monitoring all hosts/services/metrics.",
    whatItChecks: "The query_uses_wildcard_scope boolean on each datadog_monitor record (derived from query before discarding).",
    whyItMatters:
      "Wildcard-scoped monitors can generate high alert volumes and may mask issues with specific services. Raw query content is never stored.",
    evidence: "Monitor record ID, query_uses_wildcard_scope. Raw query content is never stored.",
    remediation:
      "Review and narrow the monitor scope to specific environments, services, or hosts where possible.",
    falsePositiveGuard:
      "Only fires when {*} is present in the query. Wildcard scopes are valid for infrastructure-wide monitors.",
  },
  {
    key: "datadog_monitor_broad_group_by",
    provider: "datadog",
    severity: "low",
    title: "Datadog monitor has broad group-by configuration",
    category: "Monitor query posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog monitor has 3 or more group-by clauses in its query.",
    whatItChecks: "The query_group_by_count on each datadog_monitor record (derived from query before discarding).",
    whyItMatters:
      "Many group-by dimensions create a large number of alert groups, which can produce high alert volumes and make alert management difficult.",
    evidence: "Monitor record ID, query_group_by_count. Raw query content is never stored.",
    remediation:
      "Review and reduce the group-by dimensions in the monitor query to focus on the most actionable signals.",
    falsePositiveGuard:
      "Only fires when query_group_by_count >= 3. Multiple group-by dimensions are sometimes necessary for granular alerting.",
  },
  {
    key: "datadog_monitor_long_no_data_timeframe",
    provider: "datadog",
    severity: "low",
    title: "Datadog monitor has a long no-data timeframe",
    category: "Monitor no-data posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog monitor has a no-data timeframe of 2 hours or more.",
    whatItChecks: "The no_data_timeframe_category on each datadog_monitor record.",
    whyItMatters:
      "A long no-data window delays detection of agent or integration outages, reducing the speed of incident response.",
    evidence: "Monitor record ID, no_data_timeframe_category.",
    remediation:
      "Reduce the no-data timeframe to a value appropriate for the expected data ingestion frequency.",
    falsePositiveGuard:
      "Only fires when no_data_timeframe_category=='extended' (>= 2 hours). Long timeframes may be appropriate for infrequent data sources.",
  },
  {
    key: "datadog_webhook_custom_headers_without_secret_headers",
    provider: "datadog",
    severity: "medium",
    title: "Datadog webhook has custom headers but no secret header",
    category: "Webhook posture",
    confidence: "high",
    metadataOnly: true,
    description:
      "A Datadog webhook has custom HTTP headers configured but no dedicated secret header for delivery integrity.",
    whatItChecks:
      "The custom_headers_present and secret_headers_present booleans on each datadog_webhook_integration record.",
    whyItMatters:
      "Without a secret header, the receiving endpoint cannot verify the origin and integrity of webhook deliveries, even when custom auth headers are present.",
    evidence:
      "Webhook record ID, custom_headers_present, custom_header_count, secret_headers_present. Header names and values are never stored.",
    remediation:
      "Add a dedicated secret header in the Webhooks configuration for delivery integrity verification.",
    falsePositiveGuard:
      "Only fires when custom_headers_present=true AND secret_headers_present=false. Distinct from M82B's no-secret-headers rule which checks url_present.",
  },
  {
    key: "datadog_webhook_large_payload_template",
    provider: "datadog",
    severity: "low",
    title: "Datadog webhook has a large payload template",
    category: "Webhook posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A Datadog webhook integration has a payload template classified as large in length.",
    whatItChecks: "The payload_template_length_category on each datadog_webhook_integration record.",
    whyItMatters:
      "Large payload templates may contain many variable substitutions or embedded content that is harder to audit and maintain.",
    evidence: "Webhook record ID, payload_template_length_category. Raw template content is never stored.",
    remediation:
      "Review and simplify the webhook payload template, or use the default Datadog payload if the receiving service supports it.",
    falsePositiveGuard:
      "Only fires when payload_template_length_category=='long'. Large templates are sometimes necessary for complex integrations.",
  },
  {
    key: "datadog_webhook_auth_material_present",
    provider: "datadog",
    severity: "medium",
    title: "Datadog webhook configuration includes authentication material",
    category: "Webhook posture",
    confidence: "high",
    metadataOnly: true,
    description:
      "A Datadog webhook has custom headers that appear to contain authentication material (e.g. Authorization, API-Key, or Token headers).",
    whatItChecks:
      "The auth_material_present boolean on each datadog_webhook_integration record (derived by checking header key names before discarding).",
    whyItMatters:
      "Authentication headers embedded in webhook configurations may require periodic rotation review. Header names and values are never stored.",
    evidence: "Webhook record ID, auth_material_present. Header names and values are never stored.",
    remediation:
      "Review and rotate any credentials in the webhook custom headers. Consider using a secret header for delivery verification instead.",
    falsePositiveGuard:
      "Only fires when auth-pattern header names are detected. Header names are checked but never stored — no header values are accessed.",
  },
  {
    key: "datadog_webhook_non_https_endpoint",
    provider: "datadog",
    severity: "high",
    title: "Datadog webhook endpoint uses insecure HTTP",
    category: "Webhook posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Datadog webhook integration is configured with an endpoint using plain HTTP rather than HTTPS.",
    whatItChecks: "The url_scheme_category on each datadog_webhook_integration record (derived from URL before discarding).",
    whyItMatters:
      "Webhook payloads delivered over HTTP are transmitted without transport-layer encryption. The webhook URL string is never stored.",
    evidence: "Webhook record ID, url_scheme_category. The full URL string is never stored.",
    remediation:
      "Update the webhook endpoint URL to use HTTPS in Integrations > Webhooks.",
    falsePositiveGuard:
      "Only fires when url_scheme_category=='http'. The URL value itself is never stored — only the scheme category.",
  },

  // ── Clerk — M83B core security rules ──────────────────────────────────────
  {
    key: "clerk_instance_mfa_disabled",
    provider: "clerk",
    severity: "medium",
    title: "Clerk instance has MFA disabled",
    category: "Instance MFA posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk instance does not have MFA enabled at the instance level.",
    whatItChecks: "The mfa_enabled boolean on the clerk_instance_settings record.",
    whyItMatters: "Without MFA, users authenticate with a single factor. This is configuration evidence — it does not confirm unauthorized access.",
    evidence: "Instance record ID, mfa_enabled. No secret key values or user data are stored.",
    remediation: "Enable MFA in the Clerk Dashboard under User & Authentication > Multi-factor.",
    falsePositiveGuard: "Only fires when mfa_enabled is explicitly false on a clerk_instance_settings record.",
  },
  {
    key: "clerk_instance_password_without_mfa",
    provider: "clerk",
    severity: "medium",
    title: "Clerk instance has password authentication enabled without MFA",
    category: "Instance authentication posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk instance has password-based authentication enabled but MFA is not enabled.",
    whatItChecks: "The password_enabled and mfa_enabled booleans on the clerk_instance_settings record.",
    whyItMatters: "Password-only authentication provides a single barrier. This is configuration evidence — it does not confirm unauthorized access.",
    evidence: "Instance record ID, password_enabled, mfa_enabled. No secret key values or user data are stored.",
    remediation: "Enable MFA in the Clerk Dashboard under User & Authentication > Multi-factor.",
    falsePositiveGuard: "Only fires when password_enabled=true AND mfa_enabled=false on a clerk_instance_settings record.",
  },
  {
    key: "clerk_instance_sign_up_enabled",
    provider: "clerk",
    severity: "low",
    title: "Clerk instance has public sign-up enabled",
    category: "Instance sign-up posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk instance has sign-up enabled, allowing new users to register.",
    whatItChecks: "The sign_up_enabled boolean on the clerk_instance_settings record.",
    whyItMatters: "Public sign-up posture may require review for production environments. This is configuration evidence — it does not confirm unauthorized access.",
    evidence: "Instance record ID, sign_up_enabled, sign_in_mode. No user data is stored.",
    remediation: "Review sign-up configuration in the Clerk Dashboard. Consider enabling allowlists or invitation-only mode if open registration is not intended.",
    falsePositiveGuard: "Only fires when sign_up_enabled=true. Many production applications intentionally allow public sign-up.",
  },
  {
    key: "clerk_application_mfa_not_required",
    provider: "clerk",
    severity: "medium",
    title: "Clerk application does not require MFA",
    category: "Application MFA posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk application does not have MFA required at the application level.",
    whatItChecks: "The mfa_required boolean on each clerk_application record.",
    whyItMatters: "Without required MFA, users may authenticate with a single factor. This is configuration evidence — it does not confirm unauthorized access.",
    evidence: "Application record ID, application name (truncated), mfa_required. No client secrets or redirect URLs are stored.",
    remediation: "Enable required MFA for this application in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when mfa_required is explicitly false on a clerk_application record.",
  },
  {
    key: "clerk_domain_unverified",
    provider: "clerk",
    severity: "medium",
    title: "Clerk domain is not verified",
    category: "Domain posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk domain is not in a verified state.",
    whatItChecks: "The verified boolean on each clerk_domain record.",
    whyItMatters: "An unverified domain may affect authentication routing. Raw domain name strings are never stored.",
    evidence: "Domain record ID, domain_type, verified. Raw domain name strings are never stored.",
    remediation: "Complete domain verification in the Clerk Dashboard under Domains.",
    falsePositiveGuard: "Only fires when verified is explicitly false on a clerk_domain record. Raw domain name strings are NEVER stored.",
  },
  {
    key: "clerk_domain_ssl_disabled",
    provider: "clerk",
    severity: "high",
    title: "Clerk domain has SSL disabled",
    category: "Domain SSL posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk domain has SSL disabled.",
    whatItChecks: "The ssl_enabled boolean on each clerk_domain record.",
    whyItMatters: "Authentication traffic without SSL may be transmitted without transport-layer encryption. Raw domain name strings are never stored.",
    evidence: "Domain record ID, domain_type, ssl_enabled. Raw domain name strings are never stored.",
    remediation: "Enable SSL for this domain in the Clerk Dashboard under Domains.",
    falsePositiveGuard: "Only fires when ssl_enabled is explicitly false on a clerk_domain record. Raw domain name strings are NEVER stored.",
  },
  {
    key: "clerk_redirect_url_non_https",
    provider: "clerk",
    severity: "high",
    title: "Clerk redirect URL uses a non-HTTPS scheme",
    category: "Redirect URL posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk redirect URL is configured with a scheme other than HTTPS.",
    whatItChecks: "The url_present and url_scheme_category fields on each clerk_redirect_url_config record.",
    whyItMatters: "Non-HTTPS redirect URLs may expose authorization codes or tokens in transit. Raw URL strings are never stored.",
    evidence: "Redirect URL record ID, url_present, url_scheme_category. Raw URL strings are never stored.",
    remediation: "Update redirect URLs to use HTTPS in the Clerk Dashboard application settings.",
    falsePositiveGuard: "Only fires when url_present=true AND url_scheme_category is not 'https'. Raw URL strings are NEVER stored — only the scheme category.",
  },
  {
    key: "clerk_redirect_url_wildcard_present",
    provider: "clerk",
    severity: "medium",
    title: "Clerk redirect URL contains a wildcard",
    category: "Redirect URL posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk redirect URL contains a wildcard character.",
    whatItChecks: "The wildcard_present boolean on each clerk_redirect_url_config record.",
    whyItMatters: "Wildcard redirect URLs may allow redirects to unexpected destinations. Raw URL strings are never stored.",
    evidence: "Redirect URL record ID, wildcard_present. Raw URL strings are never stored.",
    remediation: "Replace wildcard redirect URLs with explicit, fully-qualified URLs in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when wildcard_present=true (derived from the URL pattern before discarding). Raw URL strings are NEVER stored.",
  },
  {
    key: "clerk_redirect_url_localhost_present",
    provider: "clerk",
    severity: "low",
    title: "Clerk redirect URL points to localhost",
    category: "Redirect URL posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk redirect URL is configured to redirect to localhost or a loopback address.",
    whatItChecks: "The localhost_present boolean on each clerk_redirect_url_config record.",
    whyItMatters: "Localhost redirect URLs may indicate development configuration left in production. Raw URL strings are never stored.",
    evidence: "Redirect URL record ID, localhost_present. Raw URL strings are never stored.",
    remediation: "Remove localhost redirect URLs from production Clerk instances.",
    falsePositiveGuard: "Only fires when localhost_present=true (derived from the URL before discarding). Raw URL strings are NEVER stored.",
  },
  {
    key: "clerk_jwt_template_custom_claims_present",
    provider: "clerk",
    severity: "low",
    title: "Clerk JWT template has custom claims configured",
    category: "JWT template posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk JWT template has custom claims configured.",
    whatItChecks: "The custom_claims_present boolean and claims_count on each clerk_jwt_template record.",
    whyItMatters: "Custom claims embed additional data in JWTs and may require periodic review. Claim names, values, and template body are never stored.",
    evidence: "JWT template record ID, template name (truncated), custom_claims_present, claims_count. Claim content and template body are never stored.",
    remediation: "Review custom claims in Clerk Dashboard JWT Templates periodically to confirm they are current and minimal.",
    falsePositiveGuard: "Only fires when custom_claims_present=true on a clerk_jwt_template record. Claim content and template body are NEVER stored.",
  },
  {
    key: "clerk_jwt_template_long_lifetime",
    provider: "clerk",
    severity: "medium",
    title: "Clerk JWT template has an extended token lifetime",
    category: "JWT template lifetime posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk JWT template has a token lifetime classified as extended.",
    whatItChecks: "The lifetime_category on each clerk_jwt_template record.",
    whyItMatters: "Long-lived JWTs increase the window during which a token remains valid. No token values are stored.",
    evidence: "JWT template record ID, template name (truncated), lifetime_category. No token values are stored.",
    remediation: "Review and reduce the token lifetime in Clerk Dashboard JWT Templates.",
    falsePositiveGuard: "Only fires when lifetime_category is 'extended' or 'long' on a clerk_jwt_template record.",
  },
  {
    key: "clerk_webhook_endpoint_disabled",
    provider: "clerk",
    severity: "low",
    title: "Clerk webhook endpoint is disabled",
    category: "Webhook endpoint posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk webhook endpoint is currently disabled.",
    whatItChecks: "The enabled boolean on each clerk_webhook_endpoint record.",
    whyItMatters: "A disabled webhook endpoint will not deliver events. This is an integration reliability posture item — it does not confirm a security incident.",
    evidence: "Webhook record ID, enabled. Webhook URL and secret values are never stored.",
    remediation: "Review and re-enable the webhook endpoint in the Clerk Dashboard if the integration should receive events.",
    falsePositiveGuard: "Only fires when enabled is explicitly false on a clerk_webhook_endpoint record. May be intentionally disabled.",
  },
  {
    key: "clerk_webhook_without_signing",
    provider: "clerk",
    severity: "high",
    title: "Clerk webhook endpoint has no signing secret configured",
    category: "Webhook signing posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk webhook endpoint has a URL configured but no signing secret present.",
    whatItChecks: "The url_present and secret_present booleans on each clerk_webhook_endpoint record.",
    whyItMatters: "Without a signing secret, the receiving endpoint cannot verify that deliveries originate from Clerk. Webhook URLs and secret values are never stored.",
    evidence: "Webhook record ID, url_present, secret_present. Webhook URL and secret values are never stored.",
    remediation: "Configure a signing secret for this webhook endpoint in the Clerk Dashboard and validate the svix-signature header on each delivery.",
    falsePositiveGuard: "Only fires when url_present=true AND secret_present=false on a clerk_webhook_endpoint record. Webhook URL and secret values are NEVER stored.",
  },
  {
    key: "clerk_webhook_non_https",
    provider: "clerk",
    severity: "high",
    title: "Clerk webhook endpoint uses a non-HTTPS URL",
    category: "Webhook endpoint posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk webhook endpoint is configured with a URL that does not use HTTPS.",
    whatItChecks: "The url_present and url_scheme_category fields on each clerk_webhook_endpoint record.",
    whyItMatters: "Webhook payloads over unencrypted connections may expose event content in transit. Webhook URL strings are never stored.",
    evidence: "Webhook record ID, url_present, url_scheme_category. Webhook URL strings are never stored.",
    remediation: "Update the webhook endpoint URL to use HTTPS in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when url_present=true AND url_scheme_category is not 'https'. Webhook URL strings are NEVER stored — only the scheme category.",
  },
  {
    key: "clerk_email_sms_custom_sender_present",
    provider: "clerk",
    severity: "low",
    title: "Clerk email/SMS settings include a custom sender",
    category: "Email/SMS sender posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk instance has a custom sender domain or address configured for email or SMS delivery.",
    whatItChecks: "The custom_sender_present boolean on the clerk_email_sms_settings record.",
    whyItMatters: "Custom senders affect deliverability and email authentication posture and may require periodic review. Sender addresses are never stored.",
    evidence: "Settings record ID, custom_sender_present. Sender addresses are never stored.",
    remediation: "Review the custom sender configuration in the Clerk Dashboard. Confirm SPF, DKIM, and DMARC records are valid.",
    falsePositiveGuard: "Only fires when custom_sender_present=true on a clerk_email_sms_settings record. Sender addresses are NEVER stored.",
  },
  {
    key: "clerk_auth_strategy_mfa_not_required",
    provider: "clerk",
    severity: "medium",
    title: "Clerk authentication strategy supports MFA but does not require it",
    category: "Authentication strategy posture",
    confidence: "medium",
    metadataOnly: true,
    description: "The Clerk instance has MFA available but does not require it.",
    whatItChecks: "The mfa_enabled and mfa_required booleans on the clerk_auth_strategy record.",
    whyItMatters: "When MFA is optional, users may skip enrollment. This is configuration evidence — it does not confirm unauthorized access.",
    evidence: "Auth strategy record ID, mfa_enabled, mfa_required. No credential values are stored.",
    remediation: "Consider making MFA required for all users in the Clerk Dashboard under User & Authentication > Multi-factor.",
    falsePositiveGuard: "Only fires when mfa_enabled=true AND mfa_required=false. Optional MFA is a valid and common configuration — medium confidence.",
  },
  {
    key: "clerk_auth_strategy_password_without_mfa",
    provider: "clerk",
    severity: "medium",
    title: "Clerk authentication strategy has password enabled without required MFA",
    category: "Authentication strategy posture",
    confidence: "medium",
    metadataOnly: true,
    description: "The Clerk instance has password-based authentication as a strategy but MFA is not required.",
    whatItChecks: "The password_enabled and mfa_required booleans on the clerk_auth_strategy record.",
    whyItMatters: "Password-only authentication may be strengthened by requiring a second factor. This is configuration evidence — it does not confirm unauthorized access.",
    evidence: "Auth strategy record ID, password_enabled, mfa_required. No credential values are stored.",
    remediation: "Enable and require MFA alongside password authentication in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when password_enabled=true AND mfa_required=false on a clerk_auth_strategy record. No connection credentials are stored.",
  },
  {
    key: "clerk_session_lifetime_extended",
    provider: "clerk",
    severity: "medium",
    title: "Clerk session lifetime is extended",
    category: "Session lifetime posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk session policy is configured with an extended session lifetime.",
    whatItChecks: "The session_lifetime_category on the clerk_session_policy record.",
    whyItMatters: "Extended sessions increase the validity window for session tokens without re-authentication. No session token values are stored.",
    evidence: "Session policy record ID, session_lifetime_category. No session token values are stored.",
    remediation: "Review and reduce the session lifetime in the Clerk Dashboard under Sessions.",
    falsePositiveGuard: "Only fires when session_lifetime_category is 'extended' or 'very_long' on a clerk_session_policy record.",
  },
  {
    key: "clerk_session_inactivity_timeout_extended",
    provider: "clerk",
    severity: "low",
    title: "Clerk session inactivity timeout is extended",
    category: "Session inactivity posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk session policy has an extended inactivity timeout.",
    whatItChecks: "The inactivity_timeout_category on the clerk_session_policy record.",
    whyItMatters: "Extended inactivity timeouts allow idle sessions to persist longer than may be appropriate for your policy. No session token values are stored.",
    evidence: "Session policy record ID, inactivity_timeout_category. No session token values are stored.",
    remediation: "Review and reduce the inactivity timeout in the Clerk Dashboard under Sessions.",
    falsePositiveGuard: "Only fires when inactivity_timeout_category=='extended' on a clerk_session_policy record.",
  },
  {
    key: "clerk_session_single_session_disabled",
    provider: "clerk",
    severity: "low",
    title: "Clerk single-session mode is disabled",
    category: "Session policy posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk session policy does not enforce single-session mode.",
    whatItChecks: "The single_session_mode boolean on the clerk_session_policy record.",
    whyItMatters: "Without single-session enforcement, a user can maintain concurrent active sessions. This may be intentional but may require review for high-security applications. No session data is stored.",
    evidence: "Session policy record ID, single_session_mode. No session data is stored.",
    remediation: "Review whether single-session mode should be enabled in the Clerk Dashboard under Sessions.",
    falsePositiveGuard: "Only fires when single_session_mode is explicitly false. Multi-session is the common default — review whether single-session is appropriate for the use case.",
  },
  {
    key: "clerk_session_token_rotation_disabled",
    provider: "clerk",
    severity: "medium",
    title: "Clerk session token rotation is disabled",
    category: "Session token rotation posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk session policy does not have token rotation enabled.",
    whatItChecks: "The token_rotation_enabled boolean on the clerk_session_policy record.",
    whyItMatters: "Without token rotation, session tokens remain valid until they expire or are revoked. No token values are stored.",
    evidence: "Session policy record ID, token_rotation_enabled. No token values are stored.",
    remediation: "Enable session token rotation in the Clerk Dashboard under Sessions.",
    falsePositiveGuard: "Only fires when token_rotation_enabled is explicitly false on a clerk_session_policy record. No token values are NEVER stored.",
  },

  // ── Clerk — M83C auth/application risk expansion ─────────────────────────
  {
    key: "clerk_application_sign_up_enabled",
    provider: "clerk",
    severity: "low",
    title: "Clerk application has sign-up enabled",
    category: "Application sign-up posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk application has sign-up enabled at the application level.",
    whatItChecks: "The sign_up_enabled boolean on each clerk_application record.",
    whyItMatters: "Public sign-up posture may require review for production applications. This is configuration evidence — it does not confirm unauthorized access.",
    evidence: "Application record ID, application name (truncated), sign_up_enabled. No client secrets or redirect URLs are stored.",
    remediation: "Review sign-up configuration in the Clerk Dashboard. Consider enabling allowlists or invitation-only mode if open registration is not intended.",
    falsePositiveGuard: "Only fires when sign_up_enabled=true on a clerk_application record. Many production applications intentionally allow public sign-up.",
  },
  {
    key: "clerk_application_password_without_mfa",
    provider: "clerk",
    severity: "medium",
    title: "Clerk application has password authentication without required MFA",
    category: "Application authentication posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk application has password-based authentication enabled but does not require MFA.",
    whatItChecks: "The password_enabled and mfa_required booleans on each clerk_application record.",
    whyItMatters: "Password-only authentication provides a single barrier. This is configuration evidence — it does not confirm unauthorized access.",
    evidence: "Application record ID, application name (truncated), password_enabled, mfa_required. No client secrets are stored.",
    remediation: "Enable required MFA alongside password authentication in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when password_enabled=true AND mfa_required=false on a clerk_application record.",
  },
  {
    key: "clerk_application_oauth_without_mfa",
    provider: "clerk",
    severity: "medium",
    title: "Clerk application has OAuth providers configured without required MFA",
    category: "Application OAuth posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk application has OAuth providers enabled but does not require MFA.",
    whatItChecks: "The oauth_provider_count and mfa_required fields on each clerk_application record.",
    whyItMatters: "OAuth sign-in without required MFA relies on the OAuth provider's security posture. This is configuration evidence — it does not confirm unauthorized access.",
    evidence: "Application record ID, application name (truncated), oauth_provider_count, mfa_required. No provider identities or secrets are stored.",
    remediation: "Consider enabling required MFA for this application alongside OAuth authentication in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when oauth_provider_count > 0 AND mfa_required=false. Count only — no OAuth provider identities are stored.",
  },
  {
    key: "clerk_application_saml_without_mfa",
    provider: "clerk",
    severity: "medium",
    title: "Clerk application has SAML enabled without required MFA",
    category: "Application SAML posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk application has SAML authentication enabled but does not require MFA.",
    whatItChecks: "The saml_enabled and mfa_required booleans on each clerk_application record.",
    whyItMatters: "SAML-based authentication without required MFA delegates authentication security to the SAML identity provider. No SAML certificates or credentials are stored.",
    evidence: "Application record ID, application name (truncated), saml_enabled, mfa_required. No SAML certificates or credentials are stored.",
    remediation: "Confirm the SAML identity provider enforces MFA, or enable application-level MFA requirements in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when saml_enabled=true AND mfa_required=false. No SAML certificates or credentials are NEVER stored.",
  },
  {
    key: "clerk_application_many_redirect_urls",
    provider: "clerk",
    severity: "low",
    title: "Clerk application has a large number of redirect URLs",
    category: "Application redirect URL posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk application has a large number of redirect URLs configured.",
    whatItChecks: "The redirect_url_count on each clerk_application record.",
    whyItMatters: "A broad redirect URL surface may include stale or unintended entries. Raw redirect URL strings are never stored.",
    evidence: "Application record ID, application name (truncated), redirect_url_count. Raw redirect URL strings are never stored.",
    remediation: "Review and prune stale or unintended redirect URLs in the Clerk Dashboard application settings.",
    falsePositiveGuard: "Only fires when redirect_url_count exceeds the conservative threshold. Raw redirect URLs are NEVER stored — only the count.",
  },
  {
    key: "clerk_application_many_allowed_origins",
    provider: "clerk",
    severity: "low",
    title: "Clerk application has a large number of allowed origins",
    category: "Application origin posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk application has a large number of allowed origins configured.",
    whatItChecks: "The allowed_origin_count on each clerk_application record.",
    whyItMatters: "A broad allowed-origin surface may permit cross-origin requests from an unintended range of domains. Raw origin strings are never stored.",
    evidence: "Application record ID, application name (truncated), allowed_origin_count. Raw origin strings are never stored.",
    remediation: "Review and prune stale or unintended allowed origins in the Clerk Dashboard application settings.",
    falsePositiveGuard: "Only fires when allowed_origin_count exceeds the conservative threshold. Raw origin strings are NEVER stored — only the count.",
  },
  {
    key: "clerk_redirect_url_custom_scheme_present",
    provider: "clerk",
    severity: "medium",
    title: "Clerk redirect URL uses a custom (non-HTTP/HTTPS) scheme",
    category: "Redirect URL scheme posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk redirect URL uses a custom scheme (e.g. a mobile deep link protocol).",
    whatItChecks: "The custom_scheme_present boolean on each clerk_redirect_url_config record.",
    whyItMatters: "Custom scheme redirect URLs may receive authorization codes or tokens and may require review to confirm the receiving application handles tokens securely. Raw URL strings are never stored.",
    evidence: "Redirect URL record ID, custom_scheme_present. Raw URL strings are never stored.",
    remediation: "Review custom scheme redirect URLs in the Clerk Dashboard. Confirm each is intentional and the receiving application validates token handling.",
    falsePositiveGuard: "Only fires when custom_scheme_present=true (derived from URL before discarding). Raw URL strings are NEVER stored.",
  },
  {
    key: "clerk_jwt_template_audience_missing",
    provider: "clerk",
    severity: "medium",
    title: "Clerk JWT template has no audience configured",
    category: "JWT template audience posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk JWT template does not have an audience (aud) claim configured.",
    whatItChecks: "The audience_present boolean on each clerk_jwt_template record.",
    whyItMatters: "JWTs without an audience claim are not scoped to a specific relying party. Audience URI values are never stored.",
    evidence: "JWT template record ID, template name (truncated), audience_present. Audience URI values are never stored.",
    remediation: "Add an audience claim to restrict JWT acceptance to intended consumers in Clerk Dashboard JWT Templates.",
    falsePositiveGuard: "Only fires when audience_present is explicitly false. Audience URI values are NEVER stored.",
  },
  {
    key: "clerk_jwt_template_issuer_missing",
    provider: "clerk",
    severity: "low",
    title: "Clerk JWT template has no issuer configured",
    category: "JWT template issuer posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk JWT template does not have an explicit issuer (iss) claim configured.",
    whatItChecks: "The issuer_present boolean on each clerk_jwt_template record.",
    whyItMatters: "JWTs without an explicit issuer may rely on Clerk's default issuer, which may require review for applications that validate the iss claim strictly. Issuer URI values are never stored.",
    evidence: "JWT template record ID, template name (truncated), issuer_present. Issuer URI values are never stored.",
    remediation: "Review the issuer configuration for this JWT template in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when issuer_present is explicitly false. Issuer URI values are NEVER stored.",
  },
  {
    key: "clerk_jwt_template_many_claims",
    provider: "clerk",
    severity: "low",
    title: "Clerk JWT template has a large number of claims",
    category: "JWT template claims posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk JWT template has a large number of claims configured.",
    whatItChecks: "The claims_count on each clerk_jwt_template record.",
    whyItMatters: "JWT templates with many claims embed more data in each token and may warrant review for currency and necessity. Claim names and values are never stored.",
    evidence: "JWT template record ID, template name (truncated), claims_count. Claim names and values are never stored.",
    remediation: "Review and reduce claims in this JWT template to the minimum necessary in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when claims_count exceeds the conservative threshold. Claim names and values are NEVER stored — only the count.",
  },
  {
    key: "clerk_webhook_broad_event_scope",
    provider: "clerk",
    severity: "low",
    title: "Clerk webhook endpoint subscribes to a broad set of events",
    category: "Webhook event scope posture",
    confidence: "high",
    metadataOnly: true,
    description: "A Clerk webhook endpoint subscribes to a large number of event types.",
    whatItChecks: "The event_count on each clerk_webhook_endpoint record.",
    whyItMatters: "A broad event subscription may deliver more data to the receiving endpoint than is necessary. Event names are never stored — only the count.",
    evidence: "Webhook record ID, event_count. Event names are never stored.",
    remediation: "Review and reduce the webhook event subscription to only required event types in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when event_count exceeds the conservative threshold. Event names are NEVER stored — only the count.",
  },
  {
    key: "clerk_org_verified_domains_not_required",
    provider: "clerk",
    severity: "medium",
    title: "Clerk organizations do not require verified domains",
    category: "Organization domain posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk instance has organizations enabled but does not require verified domains for membership.",
    whatItChecks: "The organizations_enabled and verified_domains_required booleans on the clerk_organization_settings record.",
    whyItMatters: "Without verified domain requirements, users from unverified email domains may join organizations. No member identities are stored.",
    evidence: "Organization settings record ID, organizations_enabled, verified_domains_required. No member identities are stored.",
    remediation: "Consider enabling verified domain requirements for organization membership in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when organizations_enabled=true AND verified_domains_required=false. Member identities are NEVER stored.",
  },
  {
    key: "clerk_org_invitations_enabled",
    provider: "clerk",
    severity: "low",
    title: "Clerk organizations have invitations enabled",
    category: "Organization invitation posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk instance has organizations enabled and organization invitations are enabled.",
    whatItChecks: "The organizations_enabled and invitation_enabled booleans on the clerk_organization_settings record.",
    whyItMatters: "Organization invitations allow users to be added via email invite and may require periodic review. Member identities and invitation content are never stored.",
    evidence: "Organization settings record ID, organizations_enabled, invitation_enabled. Member identities and invitation content are never stored.",
    remediation: "Review whether invitation access is appropriately restricted in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when organizations_enabled=true AND invitation_enabled=true. Member identities and invitation content are NEVER stored.",
  },
  {
    key: "clerk_org_admin_role_missing",
    provider: "clerk",
    severity: "medium",
    title: "Clerk organizations have no admin role configured",
    category: "Organization role posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk instance has organizations enabled but does not have an admin role configured.",
    whatItChecks: "The organizations_enabled and admin_role_present booleans on the clerk_organization_settings record.",
    whyItMatters: "Without an admin role, organization management capabilities may not be properly scoped. No member identities are stored.",
    evidence: "Organization settings record ID, organizations_enabled, admin_role_present. No member identities are stored.",
    remediation: "Configure an admin role for organization management in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when organizations_enabled=true AND admin_role_present is explicitly false. No member identities are NEVER stored.",
  },
  {
    key: "clerk_org_high_role_count",
    provider: "clerk",
    severity: "low",
    title: "Clerk organizations have a high number of roles configured",
    category: "Organization role posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk instance has a large number of organization roles configured.",
    whatItChecks: "The role_count on the clerk_organization_settings record.",
    whyItMatters: "A large number of roles may indicate role proliferation that is harder to audit. Role names and member identities are never stored.",
    evidence: "Organization settings record ID, organizations_enabled, role_count. Role names and member identities are never stored.",
    remediation: "Review and consolidate organization roles in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when role_count exceeds the conservative threshold. Role names and member identities are NEVER stored — only the count.",
  },
  {
    key: "clerk_org_high_permission_count",
    provider: "clerk",
    severity: "medium",
    title: "Clerk organizations have a high number of permissions configured",
    category: "Organization permission posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk instance has a large number of organization permissions configured.",
    whatItChecks: "The permission_count on the clerk_organization_settings record.",
    whyItMatters: "A large permission surface may broaden role-based access. Permission names and member identities are never stored.",
    evidence: "Organization settings record ID, organizations_enabled, permission_count. Permission names and member identities are never stored.",
    remediation: "Review and reduce organization permissions to the minimum necessary in the Clerk Dashboard.",
    falsePositiveGuard: "Only fires when permission_count exceeds the conservative threshold. Permission names and member identities are NEVER stored — only the count.",
  },
  {
    key: "clerk_session_device_tracking_disabled",
    provider: "clerk",
    severity: "low",
    title: "Clerk session device tracking is disabled",
    category: "Session device tracking posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk session policy does not have device tracking enabled.",
    whatItChecks: "The device_tracking_enabled boolean on the clerk_session_policy record.",
    whyItMatters: "Device tracking allows sessions to be associated with specific devices. This is configuration evidence — no session data is stored.",
    evidence: "Session policy record ID, device_tracking_enabled. No session data is stored.",
    remediation: "Review whether device tracking should be enabled in the Clerk Dashboard under Sessions.",
    falsePositiveGuard: "Only fires when device_tracking_enabled is explicitly false on a clerk_session_policy record. No session data is NEVER stored.",
  },
  {
    key: "clerk_session_reverification_disabled",
    provider: "clerk",
    severity: "medium",
    title: "Clerk session reverification is disabled",
    category: "Session reverification posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk session policy does not require reverification for sensitive operations.",
    whatItChecks: "The reverification_required boolean on the clerk_session_policy record.",
    whyItMatters: "Reverification prompts users to re-authenticate before high-risk actions. This is configuration evidence — no session token values are stored.",
    evidence: "Session policy record ID, reverification_required. No session token values are stored.",
    remediation: "Enable reverification for sensitive operations in the Clerk Dashboard under Sessions.",
    falsePositiveGuard: "Only fires when reverification_required is explicitly false on a clerk_session_policy record. No session token values are NEVER stored.",
  },
  {
    key: "clerk_session_long_lifetime_without_single_session",
    provider: "clerk",
    severity: "medium",
    title: "Clerk session policy has extended lifetime without single-session enforcement",
    category: "Session lifetime posture",
    confidence: "high",
    metadataOnly: true,
    description: "The Clerk session policy has an extended session lifetime and single-session mode is not enforced.",
    whatItChecks: "The session_lifetime_category and single_session_mode fields on the clerk_session_policy record.",
    whyItMatters: "Extended lifetime without single-session enforcement allows multiple long-lived concurrent sessions. No session token values are stored.",
    evidence: "Session policy record ID, session_lifetime_category, single_session_mode. No session token values are stored.",
    remediation: "Review session lifetime and single-session mode together in the Clerk Dashboard under Sessions.",
    falsePositiveGuard: "Only fires when session_lifetime_category is 'extended' or 'very_long' AND single_session_mode is explicitly false.",
  },

  // ── PagerDuty — M84B core security rules ────────────────────────────────
  {
    key: "pagerduty_service_no_escalation_policy",
    provider: "pagerduty",
    severity: "high",
    title: "PagerDuty service has no escalation policy",
    category: "Service routing posture",
    confidence: "high",
    metadataOnly: true,
    description: "A PagerDuty service does not have an escalation policy configured.",
    whatItChecks: "The escalation_policy_id field on each pagerduty_service record.",
    whyItMatters: "Without an escalation policy, incidents on this service will not be automatically routed to on-call responders. This configuration posture may require review and does not confirm compromise or data exposure.",
    evidence: "Service record ID, escalation_policy_id. No PagerDuty API tokens, routing keys, integration keys, or incident data are stored.",
    remediation: "Assign an escalation policy to this service in the PagerDuty Service Directory.",
    falsePositiveGuard: "Only fires when escalation_policy_id is empty on a pagerduty_service record.",
  },
  {
    key: "pagerduty_service_no_integrations",
    provider: "pagerduty",
    severity: "medium",
    title: "PagerDuty service has no integrations",
    category: "Service integration posture",
    confidence: "high",
    metadataOnly: true,
    description: "A PagerDuty service has zero integrations configured.",
    whatItChecks: "The integration_count field on each pagerduty_service record.",
    whyItMatters: "Services with no integrations cannot receive events from monitoring tools and will not trigger incidents automatically. This configuration posture may require review.",
    evidence: "Service record ID, integration_count. No integration key or routing key values are stored.",
    remediation: "Add at least one integration to this service under the Integrations tab.",
    falsePositiveGuard: "Only fires when integration_count is exactly 0.",
  },
  {
    key: "pagerduty_service_ack_timeout_disabled",
    provider: "pagerduty",
    severity: "medium",
    title: "PagerDuty service acknowledgement timeout is disabled",
    category: "Service timeout posture",
    confidence: "high",
    metadataOnly: true,
    description: "A PagerDuty service has the acknowledgement timeout disabled.",
    whatItChecks: "The acknowledgement_timeout_category field on each pagerduty_service record.",
    whyItMatters: "Without an acknowledgement timeout, incidents acknowledged but not resolved remain acknowledged indefinitely. This configuration posture may require review.",
    evidence: "Service record ID, acknowledgement_timeout_category. No incident data is stored.",
    remediation: "Enable an acknowledgement timeout for this service in the Service Directory.",
    falsePositiveGuard: "Only fires when acknowledgement_timeout_category is 'disabled'.",
  },
  {
    key: "pagerduty_service_auto_resolve_disabled",
    provider: "pagerduty",
    severity: "medium",
    title: "PagerDuty service auto-resolve timeout is disabled",
    category: "Service timeout posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A PagerDuty service has no auto-resolve timeout configured.",
    whatItChecks: "The auto_resolve_timeout_category field on each pagerduty_service record.",
    whyItMatters: "Without auto-resolve, incidents must be manually resolved, which may result in stale open incidents. This configuration posture may require review.",
    evidence: "Service record ID, auto_resolve_timeout_category. No incident data is stored.",
    remediation: "Configure an auto-resolve timeout for this service in the Service Directory.",
    falsePositiveGuard: "Fires when auto_resolve_timeout_category is 'disabled'; some teams intentionally disable auto-resolve for high-severity services.",
  },
  {
    key: "pagerduty_service_alert_creation_limited",
    provider: "pagerduty",
    severity: "low",
    title: "PagerDuty service uses incident-only alert creation",
    category: "Service alert creation posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A PagerDuty service is configured to create incidents only, not separate alerts.",
    whatItChecks: "The alert_creation_category field on each pagerduty_service record.",
    whyItMatters: "Without alert-based grouping, deduplication and alert aggregation features are unavailable, which may increase incident noise. This configuration posture may require review.",
    evidence: "Service record ID, alert_creation_category. No alert payloads are stored.",
    remediation: "Enable 'Create alerts and incidents' on the service to allow deduplication.",
    falsePositiveGuard: "Fires when alert_creation_category is 'incidents_only'; some teams intentionally route alerts as incidents only.",
  },
  {
    key: "pagerduty_service_no_teams",
    provider: "pagerduty",
    severity: "low",
    title: "PagerDuty service has no team assigned",
    category: "Service ownership posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A PagerDuty service has no team assigned.",
    whatItChecks: "The team_count field on each pagerduty_service record.",
    whyItMatters: "Services without team ownership may be harder to audit for responsibility and access. This configuration posture may require review.",
    evidence: "Service record ID, team_count. Team member identities are never stored.",
    remediation: "Assign a team to this service in the Service Directory.",
    falsePositiveGuard: "Fires when team_count is exactly 0.",
  },
  {
    key: "pagerduty_escalation_policy_no_rules",
    provider: "pagerduty",
    severity: "high",
    title: "PagerDuty escalation policy has no escalation rules",
    category: "Escalation policy posture",
    confidence: "high",
    metadataOnly: true,
    description: "A PagerDuty escalation policy has zero escalation rules configured.",
    whatItChecks: "The escalation_rule_count field on each pagerduty_escalation_policy record.",
    whyItMatters: "Without escalation rules, incidents will not be routed to any responders and will go unacknowledged indefinitely. This configuration posture requires review.",
    evidence: "Escalation policy record ID, escalation_rule_count. No user identities or contact details are stored.",
    remediation: "Add at least one escalation rule with targets to this policy.",
    falsePositiveGuard: "Only fires when escalation_rule_count is exactly 0.",
  },
  {
    key: "pagerduty_escalation_policy_single_level",
    provider: "pagerduty",
    severity: "medium",
    title: "PagerDuty escalation policy has only a single escalation level",
    category: "Escalation policy posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A PagerDuty escalation policy has only one escalation level.",
    whatItChecks: "The escalation_level_count and escalation_rule_count fields on each pagerduty_escalation_policy record.",
    whyItMatters: "If the first-level responder does not acknowledge, the incident will not escalate further. Additional escalation levels improve incident-response coverage. This configuration posture may require review.",
    evidence: "Escalation policy record ID, escalation_rule_count, escalation_level_count. No user identities are stored.",
    remediation: "Add a second escalation level with backup responders.",
    falsePositiveGuard: "Fires when escalation_level_count <= 1 and escalation_rule_count > 0; some on-call rotations are intentionally single-level.",
  },
  {
    key: "pagerduty_schedule_no_layers",
    provider: "pagerduty",
    severity: "medium",
    title: "PagerDuty schedule has no schedule layers",
    category: "Schedule posture",
    confidence: "high",
    metadataOnly: true,
    description: "A PagerDuty on-call schedule has no schedule layers configured.",
    whatItChecks: "The layer_count field on each pagerduty_schedule record.",
    whyItMatters: "A schedule without layers will not produce any on-call coverage. This configuration posture may require review.",
    evidence: "Schedule record ID, layer_count. User identities are never stored.",
    remediation: "Add at least one schedule layer with rotation coverage.",
    falsePositiveGuard: "Only fires when layer_count is exactly 0.",
  },
  {
    key: "pagerduty_schedule_no_teams",
    provider: "pagerduty",
    severity: "low",
    title: "PagerDuty schedule has no team assigned",
    category: "Schedule ownership posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A PagerDuty on-call schedule has no team assigned.",
    whatItChecks: "The team_count field on each pagerduty_schedule record.",
    whyItMatters: "Schedules without team ownership may be harder to audit for accountability. This configuration posture may require review.",
    evidence: "Schedule record ID, team_count. Team member identities are never stored.",
    remediation: "Assign a team to this schedule.",
    falsePositiveGuard: "Fires when team_count is exactly 0.",
  },
  {
    key: "pagerduty_service_integration_missing_key_indicator",
    provider: "pagerduty",
    severity: "medium",
    title: "PagerDuty service integration has no integration key configured",
    category: "Service integration posture",
    confidence: "high",
    metadataOnly: true,
    description: "A PagerDuty service integration does not have an integration key or routing key present.",
    whatItChecks: "The has_integration_key boolean on each pagerduty_service_integration record.",
    whyItMatters: "Without a key, the integration cannot receive events from monitoring tools. This configuration posture may require review.",
    evidence: "Integration record ID, has_integration_key, type_category. No integration key or routing key values are stored.",
    remediation: "Generate or assign an integration key for this integration.",
    falsePositiveGuard: "Only fires when has_integration_key is explicitly false; the integration key value itself is never stored.",
  },
  {
    key: "pagerduty_service_integration_email_type",
    provider: "pagerduty",
    severity: "low",
    title: "PagerDuty service integration uses email as its event source",
    category: "Service integration posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A PagerDuty service integration uses email as its event-delivery mechanism.",
    whatItChecks: "The type_category field on each pagerduty_service_integration record.",
    whyItMatters: "Email integrations are less reliable than API-based integrations and may result in delayed or dropped incident triggers. This configuration posture may require review.",
    evidence: "Integration record ID, type_category. No email addresses are stored.",
    remediation: "Consider migrating to an Events API v2 or vendor integration.",
    falsePositiveGuard: "Fires when type_category is 'email'; some teams intentionally use email-based ingestion.",
  },
  {
    key: "pagerduty_webhook_subscription_inactive",
    provider: "pagerduty",
    severity: "medium",
    title: "PagerDuty webhook subscription is inactive",
    category: "Webhook subscription posture",
    confidence: "high",
    metadataOnly: true,
    description: "A PagerDuty V3 webhook subscription is currently inactive.",
    whatItChecks: "The active boolean on each pagerduty_webhook_subscription record.",
    whyItMatters: "An inactive subscription will not deliver events to the configured endpoint. This may indicate a previously failed delivery or an intentionally paused webhook. This configuration posture may require review.",
    evidence: "Webhook subscription record ID, active. Delivery URLs and webhook secrets are never stored.",
    remediation: "Review and re-enable this webhook subscription if still needed.",
    falsePositiveGuard: "Only fires when active is explicitly false.",
  },
  {
    key: "pagerduty_webhook_subscription_non_https",
    provider: "pagerduty",
    severity: "high",
    title: "PagerDuty webhook subscription uses a non-HTTPS delivery URL",
    category: "Webhook transport posture",
    confidence: "high",
    metadataOnly: true,
    description: "A PagerDuty V3 webhook subscription is configured with a delivery URL that does not use HTTPS.",
    whatItChecks: "The delivery_url_scheme_category field on each pagerduty_webhook_subscription record.",
    whyItMatters: "Webhook payloads delivered over plain HTTP may be transmitted without transport-layer encryption. This configuration posture may require review.",
    evidence: "Webhook subscription record ID, delivery_url_scheme_category. The delivery URL value itself is never stored — only the scheme category.",
    remediation: "Update the webhook delivery URL to use HTTPS.",
    falsePositiveGuard: "Only fires when delivery_url_scheme_category is a non-https, non-absent scheme (e.g. 'http' or 'other').",
  },
  {
    key: "pagerduty_webhook_subscription_broad_event_scope",
    provider: "pagerduty",
    severity: "medium",
    title: "PagerDuty webhook subscription subscribes to a broad set of event types",
    category: "Webhook subscription posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A PagerDuty V3 webhook subscription subscribes to more than 10 event types.",
    whatItChecks: "The event_count field on each pagerduty_webhook_subscription record.",
    whyItMatters: "Broad subscriptions increase event volume and may exceed the intended scope of the integration. This configuration posture may require review.",
    evidence: "Webhook subscription record ID, event_count. Event type names are not stored.",
    remediation: "Narrow the event-type subscription to only what the endpoint requires.",
    falsePositiveGuard: "Fires when event_count is greater than 10; some intentionally broad webhooks subscribe to many event types.",
  },
  {
    key: "pagerduty_event_orchestration_no_routes",
    provider: "pagerduty",
    severity: "medium",
    title: "PagerDuty event orchestration has no routes configured",
    category: "Event orchestration posture",
    confidence: "high",
    metadataOnly: true,
    description: "A PagerDuty event orchestration has zero routes.",
    whatItChecks: "The route_count field on each pagerduty_event_orchestration record.",
    whyItMatters: "Without routes, incoming events will not be directed to the appropriate services or actions. This configuration posture may require review.",
    evidence: "Event orchestration record ID, route_count. Routing rule expressions are never stored.",
    remediation: "Add routes to this event orchestration.",
    falsePositiveGuard: "Only fires when route_count is exactly 0.",
  },
  {
    key: "pagerduty_event_orchestration_no_team",
    provider: "pagerduty",
    severity: "low",
    title: "PagerDuty event orchestration has no team assigned",
    category: "Event orchestration ownership posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A PagerDuty event orchestration has no team assigned.",
    whatItChecks: "The team_present boolean on each pagerduty_event_orchestration record.",
    whyItMatters: "Orchestrations without team ownership may be harder to audit for accountability. This configuration posture may require review.",
    evidence: "Event orchestration record ID, team_present. No team member identities are stored.",
    remediation: "Assign a team to this event orchestration.",
    falsePositiveGuard: "Fires when team_present is explicitly false.",
  },
  {
    key: "pagerduty_business_service_no_team",
    provider: "pagerduty",
    severity: "low",
    title: "PagerDuty business service has no team assigned",
    category: "Business service ownership posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A PagerDuty business service has no owning team assigned.",
    whatItChecks: "The team_present boolean on each pagerduty_business_service record.",
    whyItMatters: "Business services without team ownership may lack clear accountability for incident response. This configuration posture may require review.",
    evidence: "Business service record ID, team_present. No team member identities are stored.",
    remediation: "Assign a team to this business service.",
    falsePositiveGuard: "Fires when team_present is explicitly false.",
  },
  {
    key: "pagerduty_business_service_no_contact",
    provider: "pagerduty",
    severity: "low",
    title: "PagerDuty business service has no point of contact configured",
    category: "Business service contact posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A PagerDuty business service has no point of contact assigned.",
    whatItChecks: "The point_of_contact_present boolean on each pagerduty_business_service record.",
    whyItMatters: "Without a point of contact, it may be unclear who to reach during an outage. This configuration posture may require review.",
    evidence: "Business service record ID, point_of_contact_present. Contact names and identities are never stored.",
    remediation: "Assign a point of contact to this business service.",
    falsePositiveGuard: "Fires when point_of_contact_present is explicitly false.",
  },
  {
    key: "pagerduty_response_play_no_responders",
    provider: "pagerduty",
    severity: "high",
    title: "PagerDuty response play has no responders configured",
    category: "Response play posture",
    confidence: "high",
    metadataOnly: true,
    description: "A PagerDuty response play has zero responders configured.",
    whatItChecks: "The responder_count field on each pagerduty_response_play record.",
    whyItMatters: "Without responders, the play cannot page anyone when executed during an incident. This configuration posture may require review.",
    evidence: "Response play record ID, responder_count. Responder identities are never stored.",
    remediation: "Add responders to this response play.",
    falsePositiveGuard: "Only fires when responder_count is exactly 0.",
  },
  {
    key: "pagerduty_response_play_no_subscribers",
    provider: "pagerduty",
    severity: "low",
    title: "PagerDuty response play has no subscribers configured",
    category: "Response play subscriber posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A PagerDuty response play has no subscribers configured.",
    whatItChecks: "The subscriber_count field on each pagerduty_response_play record.",
    whyItMatters: "Without subscribers, stakeholders will not be automatically notified when the play is executed. This configuration posture may require review.",
    evidence: "Response play record ID, subscriber_count. Subscriber identities are never stored.",
    remediation: "Add stakeholder subscribers to this response play.",
    falsePositiveGuard: "Fires when subscriber_count is exactly 0; some plays intentionally have no subscribers.",
  },
  {
    key: "pagerduty_response_play_not_runnable",
    provider: "pagerduty",
    severity: "medium",
    title: "PagerDuty response play runnability is not configured",
    category: "Response play runnability posture",
    confidence: "medium",
    metadataOnly: true,
    description: "A PagerDuty response play has an unknown runnability setting.",
    whatItChecks: "The runnability field on each pagerduty_response_play record.",
    whyItMatters: "Without a clear runnability configuration, it may be unclear who is allowed to trigger this play during an incident. This configuration posture may require review.",
    evidence: "Response play record ID, runnability. No responder identities are stored.",
    remediation: "Configure the runnability setting to 'owner', 'team', or 'any'.",
    falsePositiveGuard: "Fires when runnability is 'unknown'; some response plays may be intentionally restricted.",
  },
];

// ── Deferred / planned coverage (clearly NOT active) ─────────────────────────

export const DEFERRED_RULES: DeferredRuleMeta[] = [
  {
    provider: "supabase",
    title: "Public storage bucket",
    reason: "Listing storage buckets and their public/private status requires the project's service-role/anon key, which ConfigTrace deliberately does not store or use. The Management API exposes no safe bucket list.",
  },
  {
    provider: "supabase",
    title: "Auth redirect URL too broad",
    reason: "The connector stores only the count of additional redirect URLs (never the raw URLs/patterns), so wildcard/localhost cannot be evaluated.",
  },
  {
    provider: "firebase",
    title: "Firestore / Storage public read vs write split",
    reason: "firebase_rules_public and firebase_storage_rules_public already detect public access and raise severity to critical for public write; separate per-operation read/write keys would double-flag the identical ruleset state.",
  },
  {
    provider: "firebase",
    title: "Public HTTPS Cloud Function",
    reason: "The function metadata record carries the trigger type (HTTP) but no ingress-settings or unauthenticated-invoker field, so public reachability cannot be reliably inferred without unsafe IAM-policy reads.",
  },
  {
    provider: "cloudflare",
    title: "Unproxied DNS for sensitive hostnames",
    reason:
      "Many DNS-only records are intentional (MX, TXT, mail, verification, third-party CNAMEs); flagging them needs an expected-proxy baseline.",
  },
  {
    provider: "aws",
    title: "Public web ports (80/443)",
    reason:
      "Public 80/443 is normal for web servers; without reachability/attachment context, flagging it would be noise.",
  },
  {
    provider: "aws",
    title: "Default security group public ingress",
    reason: "Requires joining a rule to its parent group's name, which the per-rule record does not carry.",
  },
  {
    provider: "stripe",
    title: "Restricted key scope expansion / live-mode webhook",
    reason:
      "The connector does not (and cannot safely) enumerate other API keys' scopes, and webhook records have no live/test mode field.",
  },
  {
    provider: "stripe",
    title: "Separate insecure-webhook-URL rule",
    reason:
      "stripe_webhook_http already fires on an enabled plain-HTTP webhook endpoint; a separate insecure-URL key would double-flag the identical state.",
  },
  {
    provider: "stripe",
    title: "Standalone Tax-settings rule",
    reason:
      "Tax posture is reviewed per active payment link via stripe_payment_link_tax_disabled; the account-singleton Stripe Tax settings surface is not fetched, so no separate key is added.",
  },
  {
    provider: "github",
    title: "Repository public visibility",
    reason: "There is no expected-private signal, so flagging public repos would be wrong.",
  },
  {
    provider: "github",
    title: "Broad Actions permissions",
    reason: "allowed_actions='all' is GitHub's common default and is too low-signal to call an exposure.",
  },
  {
    provider: "vercel",
    title: "Deploy hooks exposed (existence alone)",
    reason: "Every deploy hook is an unauthenticated trigger by design; mere existence is not a reliable exposure. Only hooks targeting the production branch are flagged (vercel_deploy_hook_production_branch).",
  },
  {
    provider: "vercel",
    title: "Project / deployment protection missing",
    reason: "The vercel_deployment_protection record already drives vercel_preview_unprotected when every protection is off; a separate 'protection missing' rule would double-flag the identical state.",
  },
  {
    provider: "shopify",
    title: "Raw 'any granted scope' rule",
    reason: "Scope presence is normal for legitimate apps. Only specific high-risk write scopes (shopify_app_broad_write_scopes, at >= 3) and customer-data scopes (shopify_app_customer_data_scope) are flagged; a per-scope presence rule with no expected-scope baseline would be noisy.",
  },
  {
    provider: "shopify",
    title: "Webhook disabled rule",
    reason: "The shopify_webhook_subscription record carries no enabled/disabled field; the connector cannot reliably tell whether delivery is paused.",
  },
  {
    provider: "shopify",
    title: "Separate insecure-webhook-URL rule",
    reason: "shopify_webhook_http already fires on a plain-HTTP webhook endpoint; a separate insecure-URL key would double-flag the identical state.",
  },
];

// ── Provider coverage summary ────────────────────────────────────────────────

export const PROVIDER_COVERAGE: ProviderCoverage[] = [
  { provider: "github", surfaces: ["Branch protection", "Webhooks", "Deploy keys", "Environment protection"] },
  { provider: "aws", surfaces: ["Security groups", "S3 public access", "IAM administrator policy", "Stale access keys"] },
  { provider: "cloudflare", surfaces: ["SSL/TLS", "HTTPS", "WAF", "HSTS", "Development mode", "Private-origin DNS"] },
  { provider: "supabase", surfaces: ["Row Level Security", "Public table policies", "Anonymous access", "JWT expiry", "Edge Functions"] },
  { provider: "firebase", surfaces: ["Firestore rules", "Realtime Database rules", "Storage rules", "Anonymous auth", "MFA"] },
  { provider: "stripe", surfaces: ["Webhook HTTPS", "Webhook posture", "Payment links", "Customer portal", "Account payments readiness"] },
  { provider: "vercel", surfaces: ["Preview protection", "Production branch", "Domains", "Environment variables", "Deploy hooks"] },
  { provider: "shopify", surfaces: ["Webhook HTTPS", "Webhook topic posture", "App scopes", "Primary domain SSL/verification", "Store policies"] },
  {
    provider: "azure",
    surfaces: [
      "Network security groups",
      "Storage accounts",
      "Key Vaults",
      "Identity / Role assignments",
      "App Service / Functions",
      "SQL Servers",
      "AKS Clusters",
    ],
  },
  {
    provider: "google_cloud",
    surfaces: [
      "IAM policy bindings",
      "VPC firewall rules",
      "Cloud Storage buckets",
      "Cloud SQL instances",
      "Cloud Run services",
      "GKE clusters",
      "Service account keys",
      "Secret Manager",
    ],
  },
  {
    provider: "twilio",
    surfaces: [
      "Incoming phone numbers",
      "Messaging services",
      "Verify services",
      "Account metadata",
      "API keys",
    ],
  },
  {
    provider: "sendgrid",
    surfaces: [
      "API key metadata",
      "Verified sender identities",
      "Domain authentication",
      "Mail settings",
      "Tracking settings",
      "Event webhook configuration",
      "Inbound parse configuration",
      "Suppression settings",
    ],
  },
  {
    provider: "auth0",
    surfaces: [
      "Tenant settings",
      "Applications / clients",
      "Connections",
      "APIs / resource servers",
      "Rules",
      "Actions",
      "MFA / Guardian factors",
      "Custom domains",
    ],
  },
  {
    provider: "datadog",
    surfaces: [
      "Monitor posture",
      "SLO posture",
      "Dashboard posture",
      "Webhook integrations",
      "Notification integrations",
      "API key metadata",
      "Application key metadata",
      "Role posture",
      "Team posture",
      "Cloud integrations",
    ],
  },
  {
    provider: "clerk",
    surfaces: [
      "Instance MFA posture",
      "Application MFA posture",
      "Application authentication posture",
      "Domain SSL/verification",
      "Redirect URL posture",
      "JWT template posture",
      "Webhook endpoint posture",
      "Email/SMS sender posture",
      "Authentication strategy posture",
      "Organization posture",
      "Session policy posture",
    ],
  },
  {
    provider: "pagerduty",
    surfaces: [
      "Service routing posture",
      "Service timeout posture",
      "Service integration posture",
      "Escalation policy posture",
      "Schedule posture",
      "Webhook transport posture",
      "Webhook subscription posture",
      "Event orchestration posture",
      "Business service ownership posture",
      "Response play posture",
    ],
  },
];
