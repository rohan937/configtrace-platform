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

// ── Matching predicates ───────────────────────────────────────────────────────
// Pure boolean helpers used across multiple playbooks.
// Keep these free of guidance text — they only test shape/value.

function _isHighOrCritical(rl: string): boolean {
  return rl === "high" || rl === "critical";
}

/**
 * True when the security-group field_path or risk_reason text indicates
 * an admin protocol port (SSH 22, RDP 3389, WinRM 5985/5986).
 */
function _sgHintAdminPort(fp: string, rr: string): boolean {
  return (
    fp === "has_public_ssh" ||
    fp === "has_public_rdp" ||
    rr.includes("ssh")       || rr.includes("rdp")     || rr.includes("winrm")  ||
    rr.includes("port 22")   || rr.includes("port 3389") ||
    rr.includes("5985")      || rr.includes("5986")
  );
}

/**
 * True when the security-group field_path or risk_reason text indicates
 * a database / cache / search port (Postgres, MySQL, MongoDB, Redis,
 * Elasticsearch, MS SQL, Oracle, Memcached).
 */
function _sgHintDatabasePort(fp: string, rr: string): boolean {
  return (
    fp === "has_public_database_port" ||
    rr.includes("database port")  ||
    rr.includes("postgres")  || rr.includes("mysql")      || rr.includes("mongo")    ||
    rr.includes("redis")     || rr.includes("elastic")    || rr.includes("mssql")    ||
    rr.includes("oracle")    || rr.includes("memcach")    ||
    rr.includes("port 5432") || rr.includes("port 3306")  || rr.includes("port 27017") ||
    rr.includes("port 6379") || rr.includes("port 9200")  || rr.includes("port 1433") ||
    rr.includes("port 1521") || rr.includes("port 11211")
  );
}

/**
 * True when the record_type (rt) is a bare Cloudflare DNS record type.
 * Cloudflare DNS records use the DNS type string ("a", "cname", "mx", …)
 * as provider_metadata.record_type — distinct from ConfigTrace's own
 * "cloudflare_dns_record" resource prefix.
 */
const _CF_DNS_TYPES = new Set([
  "a", "aaaa", "cname", "mx", "txt", "ns", "srv",
  "ptr", "spf", "caa", "ds", "tlsa",
]);
function _isCloudflareDnsRt(rt: string): boolean {
  return _CF_DNS_TYPES.has(rt);
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
// Playbook 1 — AWS (dispatcher)
// ─────────────────────────────────────────────────────────────────────────────

function _awsPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  return (
    _awsSgPlaybooks(rt, fp, ct, rl, rr, nv)        ??
    _awsCfPlaybooks(rt, fp, ct, rl, rr, nv)         ??
    _awsWafPlaybooks(rt, fp, ct, rl, rr, nv)        ??
    _awsRoute53Playbooks(rt, fp, ct, rl, rr, nv)    ??
    _awsIamPlaybooks(rt, fp, ct, rl, rr, nv)        ??
    _awsCloudTrailPlaybooks(rt, fp, ct, rl, rr, nv) ??
    null
  );
}

// ── 1a. Security Groups ───────────────────────────────────────────────────────

function _awsSgPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "aws_security_group_rule" && rt !== "aws_security_group") return null;

  // Admin ports (SSH/RDP/WinRM) exposed to the internet — high/critical
  if (_isHighOrCritical(rl) && _sgHintAdminPort(fp, rr)) {
    return _guidance({
      confidence: rl === "critical" ? "high" : "medium",
      title:   "Restrict public admin access",
      summary:
        "Remove or narrow the inbound rule permitting public internet access (0.0.0.0/0 or ::/0) on " +
        "administrative ports such as SSH (22), RDP (3389), or WinRM (5985/5986). " +
        "Replace with a trusted CIDR or use AWS Systems Manager Session Manager.",
      why_this_helps:
        "Security groups are the primary network perimeter for EC2 and related resources. " +
        "Exposing administrative protocols to 0.0.0.0/0 subjects the service to continuous " +
        "automated brute-force probes and credential-stuffing attacks from the entire internet. " +
        "Restricting source CIDRs to a corporate VPN, bastion host, or SSM Session Manager " +
        "removes the internet-facing attack surface entirely.",
      verify_first: [
        "Identify all EC2 instances, RDS instances, and other resources attached to this security group.",
        "Confirm the team has a viable alternative access path — SSM Session Manager, a VPN gateway, or a dedicated bastion host — before removing the rule.",
        "Check AWS CloudTrail to identify who added this rule and whether it was a temporary emergency-access change.",
        "Confirm whether this security group is shared across multiple resource types with differing requirements.",
        "Verify production vs staging context — the remediation urgency differs.",
      ],
      manual_steps: [
        "Open the AWS EC2 console → Security Groups.",
        "Locate the affected security group by name or group ID.",
        "Select Inbound rules → Edit inbound rules.",
        "Remove the rule allowing 0.0.0.0/0 or ::/0 on SSH (22), RDP (3389), or WinRM (5985/5986).",
        "Add a replacement rule restricted to your trusted CIDR — corporate VPN, office IP range, or bastion host IP.",
        "Alternatively, remove the rule entirely and use AWS Systems Manager Session Manager — no open inbound ports required.",
        "Save changes and verify admin access still works through the trusted path before ending your current session.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Confirm admin access still works via the alternate trusted path (SSM, VPN, or bastion).",
      ],
      caveats: [
        "Removing the only SSH/RDP rule without a confirmed alternate access path locks you out immediately.",
        "If this security group is shared with other resources, the rule change affects all of them.",
        "Security group rule changes take effect immediately.",
        "Emergency-access rules should be time-bounded and documented, not left permanently open.",
      ],
      docs_links: [
        { label: "AWS Security Groups",                 url: "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html" },
        { label: "AWS Systems Manager Session Manager", url: "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html" },
      ],
      provider_console_hint:
        "AWS Console → EC2 → Security Groups → [group name/ID] → Inbound rules → Edit inbound rules.",
    });
  }

  // Database / cache / search ports exposed to the internet — high/critical
  if (_isHighOrCritical(rl) && _sgHintDatabasePort(fp, rr)) {
    return _guidance({
      confidence: "high",
      title:   "Restrict public data-service access",
      summary:
        "Remove public ingress to database, cache, or search ports (Postgres 5432, MySQL 3306, " +
        "MongoDB 27017, Redis 6379, Elasticsearch 9200, MS SQL 1433, etc.) or restrict to " +
        "private subnets and trusted application tiers only.",
      why_this_helps:
        "Exposing database ports to 0.0.0.0/0 allows unauthenticated connection attempts from the entire " +
        "internet. Even with strong passwords, public data-service ports are a high-value target for " +
        "credential attacks and known-vulnerability exploits. Data services should communicate only through " +
        "private subnets or security-group-to-security-group rules with the application tier.",
      verify_first: [
        "Identify all resources attached to this security group and confirm which data services are exposed.",
        "Confirm which application servers or subnets legitimately need access.",
        "Check whether a managed service (RDS, ElastiCache) is using this group — managed services should not need public ingress.",
        "Verify no active migration or vendor access is in progress that requires temporary public connectivity.",
      ],
      manual_steps: [
        "Open the AWS EC2 console → Security Groups.",
        "Locate the affected security group.",
        "Select Inbound rules → Edit inbound rules.",
        "Remove the 0.0.0.0/0 or ::/0 rule for the database or cache port.",
        "Add a replacement rule sourcing from the private subnet CIDR or the application tier's security group ID.",
        "Prefer security-group-to-security-group rules (source: sg-xxxxxxxx) over CIDR rules for app-to-database traffic.",
        "Save changes and confirm application connectivity is intact.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Confirm application queries to the data service succeed after the rule change.",
      ],
      caveats: [
        "Removing the rule without first adding the correct private-access replacement will break production traffic.",
        "Security-group-to-security-group rules only work within the same VPC or peered VPCs.",
        "If the database is in a public subnet, consider moving it to a private subnet as a longer-term fix.",
      ],
      docs_links: [
        { label: "AWS Security Groups",         url: "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html" },
        { label: "RDS VPC and security groups", url: "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html" },
      ],
      provider_console_hint:
        "AWS Console → EC2 → Security Groups → [group name/ID] → Inbound rules → Edit inbound rules.",
    });
  }

  // Public inbound (web/general) — medium risk: confirm intent
  if (fp === "has_public_inbound" && nv === true) {
    return _guidance({
      confidence: "medium",
      title:   "Confirm public web exposure is intentional",
      summary:
        "Public HTTP/HTTPS access is often expected for web servers and load balancers, " +
        "but confirm this security group is attached only to intended internet-facing services " +
        "and not to internal, admin, worker, or database resources.",
      why_this_helps:
        "Public inbound rules on ports 80/443/8080/8443 are normal for load balancers and public web servers, " +
        "but become risky when the same security group is attached to internal services, admin APIs, or databases. " +
        "A shared or over-broad security group can inadvertently expose non-public resources.",
      verify_first: [
        "Confirm which resources are attached to this security group.",
        "Confirm only intended public-facing services (load balancers, web servers) use this group.",
        "Confirm a WAF or CDN (CloudFront, ALB with WAF) sits in front of the exposed endpoint.",
        "Confirm TLS termination and HTTP-to-HTTPS redirect behavior is correct.",
      ],
      manual_steps: [
        "Open the AWS EC2 console → Security Groups → [affected group].",
        "Review all attached ENIs, instances, and load balancers under 'Network interfaces'.",
        "If internal or admin resources share this group, create a separate private security group for them.",
        "Remove those resources from the public-facing group and assign the new private group.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Do not remove web ingress from public-facing services without confirming routing and end-user impact.",
        "Shared security groups are common but should be reviewed whenever public rules are added.",
      ],
      docs_links: [
        { label: "AWS Security Groups", url: "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html" },
      ],
      provider_console_hint:
        "AWS Console → EC2 → Security Groups → [group name/ID] → Network interfaces.",
    });
  }

  // Generic high/critical SG fallback — covers SG rule added / aggregate posture change
  if (_isHighOrCritical(rl)) {
    return _guidance({
      confidence: "medium",
      title:   "Restrict public admin access",
      summary:
        "Remove or narrow the inbound rule permitting public internet access (0.0.0.0/0 or ::/0) " +
        "to administrative or sensitive ports. Replace with a trusted CIDR or use SSM Session Manager.",
      why_this_helps:
        "Security groups are the primary network firewall for EC2 instances and related resources. " +
        "Leaving administrative or sensitive ports open to the entire internet exposes the service to " +
        "automated scanners, brute-force login attempts, and known-vulnerability exploits.",
      verify_first: [
        "Identify all resources currently attached to this security group.",
        "Confirm an alternative admin access path exists before removing the rule.",
        "Check AWS CloudTrail for the IAM principal that made this change.",
        "Confirm production vs staging context.",
      ],
      manual_steps: [
        "Open the AWS EC2 console → Security Groups.",
        "Locate the affected security group.",
        "Select Inbound rules → Edit inbound rules.",
        "Remove or restrict the public inbound rule to a trusted CIDR.",
        "Save and verify admin access still works through the permitted path.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Removing the only admin ingress rule without a verified alternate path locks you out immediately.",
        "Changes to security group rules take effect immediately.",
      ],
      docs_links: [
        { label: "AWS Security Groups",                 url: "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html" },
        { label: "AWS Systems Manager Session Manager", url: "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html" },
      ],
      provider_console_hint:
        "AWS Console → EC2 → Security Groups → [group name/ID] → Inbound rules → Edit inbound rules.",
    });
  }

  return null;
}

// ── 1b. CloudFront ────────────────────────────────────────────────────────────

function _awsCfPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "aws_cloudfront_distribution") return null;
  // medium risk passes here (e.g. logging_enabled → false); low/unknown already filtered at top

  // Distribution disabled — critical/high
  if (fp === "enabled" && nv === false) {
    return _guidance({
      confidence: rl === "critical" ? "high" : "medium",
      title:   "Re-enable CloudFront distribution",
      summary: "Re-enable the CloudFront distribution if it was disabled accidentally. CDN delivery for all associated domains has stopped.",
      why_this_helps:
        "Disabling a CloudFront distribution immediately stops delivery for all associated domain aliases. " +
        "End users receive errors until the distribution is re-enabled and the change propagates.",
      verify_first: [
        "Confirm whether the distribution was disabled intentionally (decommission, migration, cost reduction).",
        "Confirm the associated domain aliases are still expected to serve traffic.",
        "Check CloudTrail for who disabled the distribution and when.",
      ],
      manual_steps: [
        "Open the AWS CloudFront console → Distributions.",
        "Locate the affected distribution.",
        "Select the distribution → click 'Enable'.",
        "Wait for the distribution status to return to 'Deployed' (typically 3–5 minutes).",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Verify the domain aliases are reachable and serving expected content.",
      ],
      caveats: [
        "Distribution enablement changes propagate globally over a few minutes.",
        "If the distribution was disabled intentionally (cost, maintenance, migration), confirm that context before re-enabling.",
      ],
      docs_links: [
        { label: "CloudFront distributions", url: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-working-with.html" },
      ],
      provider_console_hint:
        "AWS Console → CloudFront → Distributions → [ID] → Enable.",
    });
  }

  // Viewer protocol policy weakened (allow-all) — critical/high
  if (fp === "default_cache_behavior_summary") {
    return _guidance({
      confidence: "high",
      title:   "Restore CloudFront HTTPS enforcement",
      summary:
        "Restore 'Redirect HTTP to HTTPS' or 'HTTPS Only' as the viewer protocol policy " +
        "for the affected distribution behavior.",
      why_this_helps:
        "Changing the viewer protocol policy to 'allow-all' permits users to access the distribution " +
        "over unencrypted HTTP. This exposes authentication tokens, session cookies, and user data in " +
        "transit to network interception. Modern web applications should enforce HTTPS-only delivery at the CDN layer.",
      verify_first: [
        "Confirm whether this distribution serves production traffic or a public-facing endpoint.",
        "Check whether any downstream integration depends on plain HTTP delivery.",
        "Review CloudTrail for who changed this setting and when.",
        "Confirm this was not part of a planned CDN reconfiguration or A/B test.",
      ],
      manual_steps: [
        "Open the AWS CloudFront console → Distributions → [affected distribution].",
        "Select Behaviors → Default (*) → Edit.",
        "Under 'Viewer protocol policy', select 'Redirect HTTP to HTTPS' or 'HTTPS only'.",
        "Save changes and wait for the distribution to redeploy.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Test HTTPS access to the distribution domain.",
        "Verify that HTTP requests redirect correctly to HTTPS.",
      ],
      caveats: [
        "Enforcing HTTPS-only will break any client or integration that sends plain HTTP requests to this distribution.",
        "Confirm compatibility before changing high-traffic distributions.",
        "Changes propagate globally over a few minutes.",
      ],
      docs_links: [
        { label: "CloudFront viewer protocol policies", url: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesViewerProtocolPolicy" },
      ],
      provider_console_hint:
        "AWS Console → CloudFront → Distributions → [ID] → Behaviors → Default → Edit → Viewer protocol policy.",
    });
  }

  // TLS minimum protocol version weakened — high
  if (fp === "viewer_certificate_summary") {
    return _guidance({
      confidence: "high",
      title:   "Restore CloudFront minimum TLS version",
      summary:
        "Restore the minimum TLS protocol version to TLSv1.2_2021 or TLSv1.2_2019 " +
        "to remove support for outdated, vulnerable TLS versions.",
      why_this_helps:
        "TLS 1.0 and TLS 1.1 are deprecated and have known vulnerabilities (BEAST, POODLE). " +
        "A weak minimum TLS version allows clients to negotiate insecure cipher suites, " +
        "potentially exposing encrypted traffic to downgrade attacks.",
      verify_first: [
        "Confirm whether any legitimate client or API consumer requires an older TLS version.",
        "Check whether this is a public-facing or internal-only distribution.",
        "Confirm the ACM or IAM certificate attached to the distribution supports the intended TLS policy.",
      ],
      manual_steps: [
        "Open the AWS CloudFront console → Distributions → [affected distribution].",
        "Navigate to General → Settings → Edit.",
        "Under 'Custom SSL certificate', review 'Security policy' and select TLSv1.2_2021 or higher.",
        "Save changes and wait for deployment.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Test HTTPS access and verify TLS negotiation uses the expected protocol version.",
      ],
      caveats: [
        "Restricting the TLS minimum version may break older browsers or API clients that do not support TLS 1.2.",
        "Confirm compatibility with your user base before tightening.",
      ],
      docs_links: [
        { label: "CloudFront supported protocols", url: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html" },
      ],
      provider_console_hint:
        "AWS Console → CloudFront → Distributions → [ID] → General → Settings → Security policy.",
    });
  }

  // WAF Web ACL removed / detached — high
  if (fp === "web_acl_id") {
    return _guidance({
      confidence: "high",
      title:   "Reattach CloudFront WAF Web ACL",
      summary:
        "Reattach the intended WAF Web ACL to the distribution to restore edge-layer protection " +
        "against common web attacks, bots, and rate-limit abuse.",
      why_this_helps:
        "A CloudFront distribution without an attached WAF Web ACL receives all traffic without managed " +
        "rule filtering, rate-limiting, or bot protection. Removing the WAF association removes " +
        "AWS-managed rule groups that protect against OWASP Top 10, known bad IPs, and automated bot attacks.",
      verify_first: [
        "Confirm the Web ACL was intentionally removed (cost reduction, rule conflict) or was a misconfiguration.",
        "Identify the original Web ACL from CloudTrail or the previous ConfigTrace snapshot.",
        "Confirm the Web ACL still exists — CloudFront WAF ACLs must be in us-east-1.",
      ],
      manual_steps: [
        "Open the AWS CloudFront console → Distributions → [affected distribution].",
        "Navigate to General → Settings → Edit.",
        "Under 'AWS WAF web ACL', select the intended Web ACL from the dropdown.",
        "Save changes and wait for deployment.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Confirm the WAF Web ACL appears under WAF & Shield → Web ACLs → Associated AWS resources.",
      ],
      caveats: [
        "Reattaching a WAF Web ACL with strict rules may block legitimate traffic — monitor CloudWatch WAF metrics after reattachment.",
        "CloudFront WAF ACLs must be in us-east-1 (global scope) — regional ACLs are not compatible.",
      ],
      docs_links: [
        { label: "CloudFront WAF integration",      url: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html" },
        { label: "AWS WAFv2 managed rule groups",   url: "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html" },
      ],
      provider_console_hint:
        "AWS Console → CloudFront → Distributions → [ID] → General → Settings → AWS WAF web ACL.",
    });
  }

  // Origin changed — high/critical
  if (fp === "origins_summary") {
    return _guidance({
      confidence: rl === "critical" ? "high" : "medium",
      title:   "Verify CloudFront origin configuration change",
      summary:
        "Confirm the origin configuration change was intentional and that traffic is not being " +
        "routed to an unexpected or uncontrolled destination.",
      why_this_helps:
        "CloudFront origin changes redirect all CDN cache misses to the new origin. An unexpected origin " +
        "change may route production traffic to a staging environment, an incorrect server, or in adversarial " +
        "cases, an attacker-controlled endpoint.",
      verify_first: [
        "Confirm the new origin domain or S3 bucket is under your team's control.",
        "Check CloudTrail to identify who changed the origin configuration.",
        "Confirm this was part of a planned migration or deployment.",
        "Verify the origin is responding correctly with expected content.",
      ],
      manual_steps: [
        "Open the AWS CloudFront console → Distributions → [affected distribution].",
        "Navigate to Origins → review and edit the affected origin.",
        "Restore the intended origin domain or S3 bucket if changed unexpectedly.",
        "Save changes and wait for deployment.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Verify the distribution is serving expected content from the correct origin.",
      ],
      caveats: [
        "Changing the origin back may briefly serve stale cached content — consider a cache invalidation if needed.",
      ],
      docs_links: [
        { label: "CloudFront origins", url: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/working-with-distributions.html" },
      ],
      provider_console_hint:
        "AWS Console → CloudFront → Distributions → [ID] → Origins.",
    });
  }

  // Logging disabled — medium
  if (fp === "logging_enabled" && nv === false) {
    return _guidance({
      confidence: "medium",
      title:   "Re-enable CloudFront access logging",
      summary:
        "Re-enable access logging to restore forensic visibility into CDN request patterns, " +
        "error rates, and traffic anomalies.",
      why_this_helps:
        "CloudFront access logs record every request to the distribution including source IPs, user agents, " +
        "cache hit/miss status, and response codes. Disabling logging removes this visibility, making it " +
        "harder to investigate security incidents, track traffic patterns, or debug cache behavior.",
      verify_first: [
        "Confirm logging was not disabled for a specific reason (cost reduction, S3 bucket cleanup).",
        "Confirm the S3 log destination bucket still exists and has appropriate permissions.",
        "Confirm the team's logging retention and compliance requirements.",
      ],
      manual_steps: [
        "Open the AWS CloudFront console → Distributions → [affected distribution].",
        "Navigate to General → Settings → Edit.",
        "Under 'Standard logging', set to 'On' and specify the S3 bucket and optional prefix.",
        "Save changes and wait for deployment.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "CloudFront access logging incurs S3 storage costs — confirm log retention policy and lifecycle rules.",
        "There is typically a 15–30 minute delay before logs appear in the S3 bucket.",
      ],
      docs_links: [
        { label: "CloudFront access logs", url: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html" },
      ],
      provider_console_hint:
        "AWS Console → CloudFront → Distributions → [ID] → General → Settings → Standard logging.",
    });
  }

  // Generic CloudFront high/critical fallback
  if (_isHighOrCritical(rl)) {
    return _guidance({
      confidence: "medium",
      title:   "Restore CloudFront HTTPS enforcement and WAF coverage",
      summary:
        "Re-enable HTTPS-only viewer protocol policy, restore the WAF Web ACL association, " +
        "and re-enable access logging if they were disabled or weakened.",
      why_this_helps:
        "CloudFront is the edge entry point for your application. Weakening the viewer protocol policy " +
        "exposes users to downgrade attacks. Detaching a WAF Web ACL removes rate-limiting and bot protection. " +
        "Disabling access logs removes forensic visibility for security incidents.",
      verify_first: [
        "Confirm the change was not part of a planned migration or A/B test.",
        "Identify all origins and behaviors the distribution serves.",
        "Review CloudTrail for who made the change.",
      ],
      manual_steps: [
        "Open the AWS CloudFront console → Distributions → [affected distribution].",
        "Under Behaviors, set Viewer Protocol Policy to 'Redirect HTTP to HTTPS' or 'HTTPS Only'.",
        "Under General → Settings, confirm a WAF Web ACL is associated and logging is enabled.",
        "Save and deploy the distribution changes.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Enforcing HTTPS-only will break any clients or integrations using plain HTTP.",
        "Reattaching a WAF Web ACL may affect high-traffic paths — monitor after change.",
        "Distribution changes propagate globally over a few minutes.",
      ],
      docs_links: [
        { label: "CloudFront viewer protocol policies", url: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesViewerProtocolPolicy" },
        { label: "CloudFront WAF integration",          url: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html" },
      ],
      provider_console_hint:
        "AWS Console → CloudFront → Distributions → [ID] → Behaviors + General tab.",
    });
  }

  return null;
}

// ── 1c. WAFv2 ─────────────────────────────────────────────────────────────────

function _awsWafPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "aws_wafv2_web_acl" && rt !== "aws_wafv2_web_acl_association") return null;
  if (!_isHighOrCritical(rl) && ct !== "removed") return null;

  // ACL association removed — resource unprotected
  if (rt === "aws_wafv2_web_acl_association" && ct === "removed") {
    return _guidance({
      confidence: "high",
      title:   "Restore WAF protection for disassociated resource",
      summary:
        "Re-associate the WAF Web ACL with the affected resource (CloudFront distribution, " +
        "API Gateway, or ALB) to restore edge-layer protection.",
      why_this_helps:
        "Disassociating a WAF Web ACL means the resource now receives all traffic without managed rule " +
        "filtering, rate-limiting, or bot challenges. The disassociation removes all WAF protection from " +
        "the resource — not just one rule — so every request bypasses WAF entirely.",
      verify_first: [
        "Confirm which resource (CloudFront, ALB, API Gateway) lost its WAF association.",
        "Confirm the Web ACL still exists in the correct scope and region.",
        "Check CloudTrail for who removed the association and whether it was intentional.",
      ],
      manual_steps: [
        "Open the AWS WAF & Shield console → Web ACLs.",
        "Locate the affected Web ACL.",
        "Select Associated AWS resources → Add AWS resources.",
        "Select the affected CloudFront distribution, ALB, or API Gateway.",
        "Save changes.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "CloudFront WAF ACLs must be in us-east-1 (global scope) — regional ACLs cannot be associated with CloudFront.",
        "Re-association may take a few minutes to propagate.",
      ],
      docs_links: [
        { label: "AWS WAFv2 resource associations", url: "https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-associating-aws-resource.html" },
      ],
      provider_console_hint:
        "AWS Console → WAF & Shield → Web ACLs → [ACL name] → Associated AWS resources → Add AWS resources.",
    });
  }

  // Default action changed to Allow
  if (fp === "default_action") {
    return _guidance({
      confidence: rl === "critical" ? "high" : "medium",
      title:   "Review WAF default action change to Allow",
      summary:
        "Restore the WAF Web ACL default action to Block or review the rules to ensure " +
        "unmatched requests are handled correctly.",
      why_this_helps:
        "The WAF default action applies to all requests that do not match any explicit rule. " +
        "Changing it from 'block' or 'count' to 'allow' means requests not covered by existing rules " +
        "pass through unfiltered. This is especially risky if managed rule groups are also removed.",
      verify_first: [
        "Confirm whether the default action change was intentional or a misconfiguration.",
        "Review existing WAF rules to confirm they provide adequate coverage for all associated resources.",
        "Check CloudTrail for who made the change.",
        "Confirm this ACL protects production resources.",
      ],
      manual_steps: [
        "Open the AWS WAF & Shield console → Web ACLs → [affected ACL].",
        "Select 'Edit' → review Default action.",
        "Change Default action back to 'Block' or 'Count' as appropriate.",
        "Save changes.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Changing default action to Block may reject legitimate traffic if rule coverage is incomplete.",
        "Use 'Count' mode during testing to observe traffic patterns before switching to Block.",
      ],
      docs_links: [
        { label: "AWS WAFv2 default actions", url: "https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-default-action.html" },
      ],
      provider_console_hint:
        "AWS Console → WAF & Shield → Web ACLs → [ACL name] → Edit → Default action.",
    });
  }

  // Rule count reduced
  if (fp === "rule_count") {
    return _guidance({
      confidence: rl === "critical" ? "high" : "medium",
      title:   "Review reduced WAF rule coverage",
      summary:
        "Restore removed WAF rules or managed rule groups to ensure the Web ACL still provides " +
        "adequate protection for the associated resources.",
      why_this_helps:
        "WAF rules are the primary blocking mechanism against common web attacks. Reducing rule count — " +
        "especially to zero — may mean requests previously blocked now pass through to the origin, " +
        "including SQL injection, XSS, bad bots, and known malicious IPs.",
      verify_first: [
        "Confirm the rule removal was part of a planned tuning effort or false-positive remediation.",
        "Identify which rules were removed and what attack patterns they covered.",
        "Check whether managed rule groups were also removed.",
      ],
      manual_steps: [
        "Open the AWS WAF & Shield console → Web ACLs → [affected ACL] → Rules.",
        "Compare against your expected rule baseline.",
        "Add back removed managed rule groups (e.g. AWSManagedRulesCommonRuleSet, AWSManagedRulesKnownBadInputsRuleSet).",
        "Add back custom rate-based or IP-set rules as appropriate.",
        "Consider using 'Count' mode first to validate rule impact before switching to 'Block'.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Re-adding managed rules may block legitimate traffic if removals were originally due to false positives.",
        "Test in Count mode before enabling Block mode for newly restored rules.",
      ],
      docs_links: [
        { label: "AWS WAFv2 managed rule groups", url: "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html" },
      ],
      provider_console_hint:
        "AWS Console → WAF & Shield → Web ACLs → [ACL name] → Rules.",
    });
  }

  // Managed rule group count reduced
  if (fp === "managed_rule_group_count") {
    return _guidance({
      confidence: "high",
      title:   "Restore WAFv2 managed rule groups",
      summary:
        "Re-add removed managed rule groups to restore coverage against OWASP Top 10, " +
        "bot traffic, and known bad inputs.",
      why_this_helps:
        "AWS managed rule groups provide continuously-updated protection against common attack patterns " +
        "without requiring custom rule maintenance. Removing managed rule groups reduces protection against " +
        "OWASP Top 10 vulnerabilities (SQLi, XSS, RCE) and known bad actors.",
      verify_first: [
        "Confirm the managed rule group removal was not due to a false positive affecting production traffic.",
        "Identify which specific rule groups were removed (AWSManagedRulesCommonRuleSet, BotControlRuleSet, etc.).",
        "Check whether custom rules were added to compensate for the removed groups.",
      ],
      manual_steps: [
        "Open AWS WAF & Shield → Web ACLs → [affected ACL] → Rules → Add rules → Add managed rule groups.",
        "Re-add removed managed rule groups.",
        "Set override action to 'Count' initially to validate rule behavior without blocking.",
        "Monitor CloudWatch WAF metrics for blocked/counted requests.",
        "Switch to 'None' (use rule default action) once you confirm no false positives.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Re-enabling managed rules may reintroduce false positives if the original removal unblocked a legitimate use case.",
        "Count mode does not block traffic — ensure you switch to block mode once validated.",
      ],
      docs_links: [
        { label: "AWS WAFv2 managed rule groups", url: "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html" },
      ],
      provider_console_hint:
        "AWS Console → WAF & Shield → Web ACLs → [ACL name] → Rules → Add rules → Add managed rule groups.",
    });
  }

  // Rate-based rule count reduced
  if (fp === "rate_based_rule_count") {
    return _guidance({
      confidence: "medium",
      title:   "Restore WAF rate-based rules",
      summary:
        "Re-add the rate-based rule(s) that were removed to restore request-rate limiting " +
        "against high-volume attacks and credential-stuffing attempts.",
      why_this_helps:
        "Rate-based WAF rules automatically block IPs that exceed a configured request threshold in a " +
        "rolling time window. They are a primary defence against volumetric attacks, credential stuffing, " +
        "and scraping. Removing rate-based rules removes this automatic throttling layer.",
      verify_first: [
        "Confirm the rate-based rule removal was part of a tuning change.",
        "Identify which rate-based rules were removed and what thresholds they enforced.",
        "Confirm whether alternative rate-limiting is in place (e.g. ALB or API Gateway throttling).",
      ],
      manual_steps: [
        "Open AWS WAF & Shield → Web ACLs → [affected ACL] → Rules → Add rules → Add my own rules and rule groups.",
        "Select 'Rule builder' and set rule type to 'Rate-based rule'.",
        "Set an appropriate rate limit threshold for your expected traffic volume.",
        "Set the action to Block.",
        "Save changes.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Rate thresholds that are too low may block legitimate traffic during traffic spikes.",
        "Calibrate rate limits based on your normal request volume baselines.",
      ],
      docs_links: [
        { label: "AWS WAFv2 rate-based rules", url: "https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html" },
      ],
      provider_console_hint:
        "AWS Console → WAF & Shield → Web ACLs → [ACL name] → Rules → Add rules.",
    });
  }

  // WAF logging disabled
  if (fp === "logging_enabled" && nv === false) {
    return _guidance({
      confidence: "medium",
      title:   "Re-enable WAF logging",
      summary:
        "Re-enable WAF logging to restore visibility into which requests are being " +
        "blocked, challenged, or counted by your Web ACL rules.",
      why_this_helps:
        "WAF logs record every request evaluation including rule matches, actions taken, and request " +
        "metadata. Without logging, security teams lose visibility into attack patterns, false positives, " +
        "and traffic anomalies. WAF logs are also required for forensic investigation of security incidents.",
      verify_first: [
        "Confirm the log destination (CloudWatch Logs, S3, or Kinesis Firehose) still exists.",
        "Confirm the logging change was not made due to cost or compliance concerns.",
      ],
      manual_steps: [
        "Open AWS WAF & Shield → Web ACLs → [affected ACL] → Logging and metrics.",
        "Enable logging and select the log destination (CloudWatch Logs group or S3 bucket).",
        "Optionally configure log filter fields to reduce volume.",
        "Save changes.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "WAF logging incurs cost depending on log volume and destination — confirm log retention policy.",
        "Full logging can generate high log volume for busy distributions.",
      ],
      docs_links: [
        { label: "AWS WAFv2 logging", url: "https://docs.aws.amazon.com/waf/latest/developerguide/logging.html" },
      ],
      provider_console_hint:
        "AWS Console → WAF & Shield → Web ACLs → [ACL name] → Logging and metrics.",
    });
  }

  // Generic WAF high/critical fallback
  return _guidance({
    confidence: ct === "removed" ? "high" : "medium",
    title:   "Restore WAFv2 Web ACL rules and associations",
    summary:
      "Re-enable or restore the WAFv2 Web ACL, its managed rule groups, and any associations " +
      "with CloudFront distributions, API Gateways, or Application Load Balancers.",
    why_this_helps:
      "WAFv2 Web ACLs protect web applications from common exploits such as SQL injection, cross-site " +
      "scripting, and automated bot attacks. Removing or weakening a Web ACL eliminates protection across " +
      "all associated resources simultaneously.",
    verify_first: [
      "Confirm the rule group removal or ACL change was intentional.",
      "Identify all resources the ACL was protecting.",
      "Check whether a replacement or updated ACL is being deployed in parallel.",
      "Review CloudTrail for the timeline of changes.",
    ],
    manual_steps: [
      "Open the AWS WAF & Shield console → Web ACLs.",
      "Select the affected Web ACL.",
      "Review Rules — add back any removed managed rule groups.",
      "Go to Associated AWS resources — add back any removed CloudFront, API Gateway, or ALB associations.",
    ],
    validation_steps: STANDARD_VALIDATION,
    caveats: [
      "Re-adding overly broad managed rule groups may block legitimate traffic. Test in Count mode first.",
      "Associating an ACL with a CloudFront distribution takes a few minutes to propagate.",
    ],
    docs_links: [
      { label: "AWS WAFv2 managed rule groups", url: "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html" },
    ],
    provider_console_hint:
      "AWS Console → WAF & Shield → Web ACLs → [ACL name] → Rules + Associated AWS resources.",
  });
}

// ── 1d. Route53 DNS records ───────────────────────────────────────────────────

function _awsRoute53Playbooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "aws_route53_record") return null;
  if (!_isHighOrCritical(rl)) return null;

  // DMARC policy weakened — critical/high
  if (fp === "dmarc_policy") {
    return _guidance({
      confidence: "high",
      title:   "Restore DMARC email authentication policy",
      summary:
        "Restore the DMARC policy to 'quarantine' or 'reject' to re-enable email " +
        "authentication enforcement and prevent domain spoofing.",
      why_this_helps:
        "DMARC controls what mail receivers do with emails that fail SPF or DKIM alignment. " +
        "Changing the policy to 'none' means spoofed or fraudulent emails claiming to be from your domain " +
        "are delivered to recipients instead of being quarantined or rejected, enabling phishing attacks.",
      verify_first: [
        "Confirm whether the DMARC policy change was part of a planned email migration or deliverability investigation.",
        "Check whether SPF and DKIM are correctly aligned for all sending sources before tightening DMARC.",
        "Confirm which email sending providers (ESPs) are authorised senders for this domain.",
        "Review DMARC aggregate reports (rua destination) to understand current SPF/DKIM pass rates.",
      ],
      manual_steps: [
        "Open the AWS Route53 console → Hosted Zones → [affected zone].",
        "Locate the _dmarc TXT record and click Edit.",
        "Set the policy to p=quarantine or p=reject.",
        "If transitioning from none: start with p=quarantine and monitor aggregate reports before moving to p=reject.",
        "Save and publish the updated record.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Verify the DMARC record is published correctly using a DMARC lookup tool.",
        "Monitor aggregate reports for SPF/DKIM pass rates before tightening further.",
      ],
      caveats: [
        "Setting p=reject before all legitimate sending sources pass SPF/DKIM will cause legitimate email to be rejected.",
        "Third-party senders (ESPs, SaaS tools) must be included in SPF and have DKIM configured before tightening DMARC.",
        "Gradual rollout (none → quarantine → reject) is safer than an immediate jump to p=reject.",
      ],
      docs_links: [
        { label: "Route53 record editing",   url: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-editing.html" },
        { label: "Route53 DNS record types", url: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html" },
      ],
      provider_console_hint:
        "AWS Console → Route53 → Hosted Zones → [zone] → _dmarc TXT record → Edit.",
    });
  }

  // DNS record removed — MX, apex A, NS, wildcard, or sensitive hostname
  if (ct === "removed") {
    const isMx    = rr.includes("mx record") || rr.includes("email delivery");
    const isApex  = rr.includes("apex dns record") || rr.includes("domain may become unreachable");
    const isNs    = rr.includes("ns record") || rr.includes("nameserver");

    const title   = isMx   ? "Restore removed MX record"
                  : isApex ? "Restore removed apex DNS record"
                  : isNs   ? "Verify NS record change"
                  :          "Verify DNS record removal";

    const summary = isMx
      ? "Re-create the MX record to restore email delivery to this domain."
      : isApex
        ? "Restore the apex A/ALIAS record to prevent the root domain from becoming unreachable."
        : "Confirm the DNS record removal was intentional and restore it if production routing was affected.";

    return _guidance({
      confidence: rl === "critical" ? "high" : "medium",
      title,
      summary,
      why_this_helps: isMx
        ? "MX records direct email for the domain to the correct mail servers. Removing an MX record causes all inbound email to the domain to fail silently — delivery failures may not be immediately obvious and can persist until the record is restored."
        : isApex
          ? "The apex A record maps the root domain to its IP address. Removing it makes the root domain completely unreachable to end users. Depending on TTL, the outage may begin within minutes."
          : "DNS record removals can redirect or break routing for the affected hostname. Changes in Route53 take effect within the TTL window and may be cached by downstream resolvers.",
      verify_first: [
        "Confirm the record removal was intentional — check Route53 change history and AWS CloudTrail.",
        "Identify the previous record value (IP address, hostname, MX priority).",
        "Confirm the TTL and whether DNS propagation has already occurred.",
        "Verify whether the record is still needed for current infrastructure.",
      ],
      manual_steps: [
        "Open the AWS Route53 console → Hosted Zones → [affected zone].",
        "Click 'Create record' and select the correct type.",
        "Enter the previous record value — IP address, hostname, or alias target.",
        "Set an appropriate TTL (300s for rapid propagation, 3600s for stable records).",
        "Save and confirm the record appears in the hosted zone.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Verify DNS resolution for the affected hostname using a DNS lookup tool (dig, nslookup).",
        "Confirm email delivery (if MX was removed) or application reachability (if A/ALIAS was removed).",
      ],
      caveats: [
        "DNS propagation depends on TTL — lower TTLs speed recovery but may already be cached at a higher level.",
        "If the record was removed as part of a cutover or migration, restoring it may interfere with that process.",
      ],
      docs_links: [
        { label: "Route53 record editing",   url: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-editing.html" },
        { label: "Route53 DNS record types", url: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html" },
      ],
      provider_console_hint:
        "AWS Console → Route53 → Hosted Zones → [zone] → Create record.",
    });
  }

  // DNS value changed — apex, wildcard, NS, or sensitive hostname
  if (fp === "value_hash" || fp === "alias_target_dns_name") {
    return _guidance({
      confidence: rl === "critical" ? "high" : "medium",
      title:   "Verify DNS record destination change",
      summary:
        "Confirm the DNS record destination change was intentional and restore the previous " +
        "value if production routing was affected.",
      why_this_helps:
        "DNS value changes redirect traffic for the affected hostname to a new destination. For apex, " +
        "wildcard, or production-critical records, an unexpected change can reroute all user traffic, " +
        "break application APIs, or redirect to an unintended endpoint.",
      verify_first: [
        "Confirm the new record value (IP address, hostname, or alias target) is expected and under your control.",
        "Check Route53 change history and CloudTrail to identify who made the change and when.",
        "Confirm whether this was part of a planned deployment, migration, or failover.",
        "Verify the new target is reachable and serving expected content.",
      ],
      manual_steps: [
        "Open the AWS Route53 console → Hosted Zones → [affected zone].",
        "Locate and edit the affected DNS record.",
        "Restore the previous value if the change was unintentional.",
        "Confirm TTL is appropriate for the intended stability of this record.",
        "Save changes.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Verify DNS resolution for the affected hostname using a DNS lookup tool.",
        "Confirm the application or service resolves to the expected destination.",
      ],
      caveats: [
        "DNS propagation time depends on the record TTL — lower TTL means faster global propagation.",
        "Route53 changes take effect almost immediately, but resolver caching delays global propagation.",
      ],
      docs_links: [
        { label: "Route53 record editing", url: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-editing.html" },
      ],
      provider_console_hint:
        "AWS Console → Route53 → Hosted Zones → [zone] → [record name] → Edit.",
    });
  }

  return null;
}

// ── 1e. IAM access keys ───────────────────────────────────────────────────────

function _awsIamPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "aws_iam_access_key") return null;
  // medium and above passes here

  return _guidance({
    confidence: "medium",
    title:   "Review IAM access key change",
    summary:
      "Verify the IAM access key change was expected, confirm the key belongs to the " +
      "intended user, and rotate or disable it if the change was unexpected.",
    why_this_helps:
      "IAM access keys are long-lived programmatic AWS credentials. Unexpected key creation or " +
      "reactivation can indicate a compromised account, a service account provisioned without oversight, " +
      "or an overly broad IAM policy. Stale or unused keys are a persistent exposure risk — they remain " +
      "valid until explicitly disabled or deleted.",
    verify_first: [
      "Confirm the key owner (IAM user) and the intended purpose of this key.",
      "Check AWS CloudTrail for when and by whom the key was created or activated.",
      "Verify the key is associated with a service or automation that actually needs programmatic AWS access.",
      "Confirm the key's associated IAM policies follow the principle of least privilege.",
    ],
    manual_steps: [
      "Open the AWS IAM console → Users → [affected user] → Security credentials.",
      "Review the access key status and last-used date.",
      "If the key is unexpected: disable it immediately, then delete after confirming no service dependency.",
      "If the key is stale (unused for 90+ days): disable it and monitor for any broken services.",
      "Review attached IAM policies and remove permissions that are not required.",
      "Enable MFA for console access for the associated IAM user if not already enabled.",
    ],
    validation_steps: [
      ...STANDARD_VALIDATION,
      "Confirm dependent services and CI/CD pipelines are still functioning if a key was rotated or disabled.",
    ],
    caveats: [
      "Disabling an active key immediately breaks any service or CI/CD pipeline using it — confirm ownership before acting.",
      "AWS IAM credential reports can help identify all active keys and their last-used dates.",
      "Long-lived access keys should be replaced with IAM roles for EC2 instances, Lambda, and ECS tasks where possible.",
    ],
    docs_links: [
      { label: "AWS IAM access keys best practices", url: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html" },
      { label: "AWS IAM credential report",          url: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html" },
    ],
    provider_console_hint:
      "AWS Console → IAM → Users → [username] → Security credentials → Access keys.",
  });
}

// ── 1f. CloudTrail trails ─────────────────────────────────────────────────────

function _awsCloudTrailPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "aws_cloudtrail_trail") return null;
  if (!_isHighOrCritical(rl) && ct !== "removed") return null;

  // Trail deleted
  if (ct === "removed") {
    return _guidance({
      confidence: "high",
      title:   "Verify CloudTrail trail removal",
      summary:
        "Confirm the CloudTrail trail was intentionally deleted and, if so, ensure an " +
        "alternative trail covers the same scope and regions.",
      why_this_helps:
        "CloudTrail is the primary audit and compliance logging service for AWS. Removing a trail stops " +
        "delivery of management event logs used for security investigations, compliance reporting, and " +
        "detecting unauthorized API activity. A missing multi-region or organization trail leaves entire " +
        "regions or accounts without audit coverage.",
      verify_first: [
        "Confirm whether the trail deletion was intentional (decommission, replacement trail).",
        "Check whether a replacement trail was created with equivalent scope.",
        "Verify the CloudTrail S3 log bucket is still accessible and retaining logs.",
        "Identify whether this was a multi-region or organization trail covering multiple accounts.",
      ],
      manual_steps: [
        "Open the AWS CloudTrail console → Trails.",
        "If the deletion was unintentional: click 'Create trail' with the same configuration.",
        "Enable logging for management events at minimum.",
        "For multi-region coverage: enable 'Apply trail to all regions'.",
        "Point logs to the original or an equivalent S3 bucket with proper bucket policy.",
        "Enable log file validation for tamper detection.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "CloudTrail charges per event recorded — confirm log volume expectations before restoring.",
        "A new trail cannot retroactively recover events missed during the coverage gap.",
      ],
      docs_links: [
        { label: "AWS CloudTrail trail management", url: "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html" },
      ],
      provider_console_hint:
        "AWS Console → CloudTrail → Trails → Create trail.",
    });
  }

  // Logging stopped
  if (fp === "is_logging" && nv === false) {
    return _guidance({
      confidence: "high",
      title:   "Re-enable CloudTrail logging",
      summary:
        "Re-enable logging on the CloudTrail trail to restore audit event delivery " +
        "to the S3 bucket and any connected analysis services.",
      why_this_helps:
        "When CloudTrail logging is stopped, all management API events — IAM changes, security group " +
        "modifications, S3 access, and configuration changes — are no longer recorded. This creates a " +
        "visibility gap that can mask unauthorized activity, hinder incident response, and cause compliance violations.",
      verify_first: [
        "Confirm the logging stoppage was not intentional (trail reconfiguration in progress).",
        "Check the CloudTrail console for error indicators — logging may have stopped due to S3 delivery errors.",
        "Verify the S3 log bucket exists and has the correct bucket policy for CloudTrail.",
        "Confirm no active incidents occurred during the logging gap that require investigation.",
      ],
      manual_steps: [
        "Open the AWS CloudTrail console → Trails → [affected trail].",
        "Click 'Start logging' if logging is currently stopped.",
        "If logging stopped due to S3 delivery errors: fix the S3 bucket policy to allow CloudTrail writes.",
        "Confirm the trail now shows 'Logging: On'.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Confirm new events appear in the S3 log bucket within a few minutes.",
      ],
      caveats: [
        "Events that occurred while logging was stopped cannot be retroactively recovered.",
        "Check the S3 bucket policy before re-enabling — an incorrect policy will cause logging to stop again.",
      ],
      docs_links: [
        { label: "CloudTrail starting and stopping logging", url: "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-turning-on-off.html" },
      ],
      provider_console_hint:
        "AWS Console → CloudTrail → Trails → [trail name] → Start logging.",
    });
  }

  // Log file validation disabled
  if (fp === "log_file_validation_enabled" && nv === false) {
    return _guidance({
      confidence: "medium",
      title:   "Re-enable CloudTrail log file validation",
      summary:
        "Re-enable log file validation to restore the ability to detect tampering or " +
        "deletion of CloudTrail log files after delivery.",
      why_this_helps:
        "CloudTrail log file validation creates a digest file for each hour of logs that verifies log " +
        "files have not been modified or deleted after delivery. Without validation, an attacker who gains " +
        "S3 bucket access could delete or modify logs to cover their tracks, and you would have no way to detect it.",
      verify_first: [
        "Confirm validation was not disabled for a specific reason.",
        "Check whether the S3 bucket has Object Lock or versioning as an alternative tamper-detection mechanism.",
      ],
      manual_steps: [
        "Open the AWS CloudTrail console → Trails → [affected trail] → Edit.",
        "Enable 'Log file validation'.",
        "Save the trail configuration.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Re-enabling validation creates new digest files going forward — it does not retroactively validate previous logs.",
      ],
      docs_links: [
        { label: "CloudTrail log file validation", url: "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html" },
      ],
      provider_console_hint:
        "AWS Console → CloudTrail → Trails → [trail name] → Edit → Log file validation.",
    });
  }

  // KMS encryption removed
  if (fp === "kms_key_id_present" && nv === false) {
    return _guidance({
      confidence: "medium",
      title:   "Restore CloudTrail KMS encryption",
      summary:
        "Re-enable KMS encryption for the CloudTrail trail to ensure log files are " +
        "encrypted at rest with a customer-managed key.",
      why_this_helps:
        "KMS encryption for CloudTrail ensures only principals with KMS key access can decrypt and read the " +
        "logs. Without KMS encryption, logs fall back to S3-managed encryption (SSE-S3), which does not " +
        "provide the same granular access control. For compliance frameworks (SOC 2, ISO 27001, PCI-DSS), " +
        "customer-managed KMS encryption for audit logs is often required.",
      verify_first: [
        "Confirm the KMS key was not removed due to key deletion or rotation policy.",
        "Verify the intended KMS key still exists and is enabled in the correct region.",
        "Confirm CloudTrail has the correct IAM permissions (kms:Decrypt, kms:GenerateDataKey) for the key.",
      ],
      manual_steps: [
        "Open the AWS CloudTrail console → Trails → [affected trail] → Edit.",
        "Under 'Log file SSE-KMS encryption', select Enabled.",
        "Choose the intended KMS key from the dropdown.",
        "Save the trail configuration.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Enabling KMS encryption requires the KMS key policy to grant the CloudTrail service principal encrypt/decrypt permissions.",
        "KMS encryption incurs additional API usage cost.",
      ],
      docs_links: [
        { label: "CloudTrail KMS encryption", url: "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html" },
      ],
      provider_console_hint:
        "AWS Console → CloudTrail → Trails → [trail name] → Edit → Log file SSE-KMS encryption.",
    });
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Playbook 2 — Cloudflare (dispatcher)
// ─────────────────────────────────────────────────────────────────────────────

function _cloudflarePlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  return (
    _cfDnsPlaybooks(rt, fp, ct, rl, rr, nv)     ??
    _cfRulesetPlaybooks(rt, fp, ct, rl, rr, nv) ??
    null
  );
}

// ── 2a. Cloudflare DNS records ────────────────────────────────────────────────

function _cfDnsPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (!_isCloudflareDnsRt(rt)) return null;
  if (!_isHighOrCritical(rl)) return null;

  const rrl = rr.toLowerCase();

  // NS record changed — authoritative delegation risk
  if (rt === "ns") {
    return _guidance({
      confidence: "high",
      title:   "Verify Cloudflare nameserver or NS record change",
      summary:
        "Confirm the NS record change was intentional. An unexpected NS change can redirect " +
        "DNS resolution authority for the affected subdomain to a third-party nameserver.",
      why_this_helps:
        "NS records control which nameservers are authoritative for a domain or subdomain zone. " +
        "An attacker who can insert a malicious NS record can intercept or forge DNS responses for " +
        "that entire subtree — redirecting web, email, and API traffic. Even legitimate NS changes " +
        "can cause resolution failures if the target nameservers are not yet configured to respond.",
      verify_first: [
        "Confirm the new NS values match your intended authoritative nameservers.",
        "Check Cloudflare audit logs to identify who made the change and when.",
        "Verify the target nameservers are under your control and correctly configured for the zone.",
        "Confirm whether this is a subdomain delegation (expected) or a root-zone NS override (high risk).",
      ],
      manual_steps: [
        "Log into the Cloudflare dashboard → select the affected zone → DNS → Records.",
        "Locate the NS record that changed and verify its current value.",
        "If the change was unintentional: edit the record to restore the previous nameserver values.",
        "If the record should not exist at all: delete it.",
        "Save changes and verify DNS propagation using a DNS lookup tool.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Verify NS record values using: dig NS <hostname> @8.8.8.8",
        "Confirm the zone resolves correctly from multiple geographic locations.",
      ],
      caveats: [
        "NS record changes propagate based on the parent zone TTL, not the record's own TTL.",
        "Removing a valid NS delegation will break resolution for any hostnames in the delegated subzone.",
      ],
      docs_links: [
        { label: "Cloudflare DNS records",     url: "https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/" },
        { label: "Cloudflare audit logs",      url: "https://developers.cloudflare.com/fundamentals/account-and-billing/account-security/review-audit-logs/" },
      ],
      provider_console_hint:
        "Cloudflare Dashboard → [zone] → DNS → Records → locate the NS record.",
    });
  }

  // Email authentication records changed/removed (SPF, DKIM, DMARC TXT records)
  if (
    rrl.includes("spf")  || rrl.includes("dkim") || rrl.includes("dmarc") ||
    rrl.includes("email authentication") || rrl.includes("sender policy")
  ) {
    const isRemoved = ct === "removed";
    return _guidance({
      confidence: "high",
      title:   isRemoved
        ? "Restore email authentication DNS record"
        : "Verify email authentication DNS record change",
      summary:
        isRemoved
          ? "Restore the removed SPF, DKIM, or DMARC TXT record to re-enable email authentication " +
            "for this domain and prevent spoofed email from passing authentication checks."
          : "Confirm the SPF, DKIM, or DMARC record change was intentional and that email authentication " +
            "is still correctly configured for all authorised sending sources.",
      why_this_helps:
        "SPF, DKIM, and DMARC are the three email authentication standards that together prevent domain " +
        "spoofing and phishing from your domain. Removing or weakening any of these records means mail " +
        "receivers can no longer reliably verify whether email from your domain is legitimate. This enables " +
        "attackers to send convincing phishing emails appearing to be from your domain.",
      verify_first: [
        "Identify which record type was affected (SPF TXT, DKIM TXT at _domainkey subdomain, or _dmarc TXT).",
        "Confirm whether the change was part of an ESP migration or email infrastructure update.",
        "Verify all authorised sending sources (ESPs, SaaS tools) are included in the current SPF record.",
        "Check DMARC aggregate reports (if available) for SPF/DKIM pass rates before making changes.",
      ],
      manual_steps: [
        "Log into the Cloudflare dashboard → select the affected zone → DNS → Records.",
        isRemoved
          ? "Click 'Add record' and re-create the SPF, DKIM, or DMARC TXT record with the correct value."
          : "Locate the affected TXT record and edit it to restore the correct value.",
        "For SPF: ensure the record includes all authorised sending IPs and ESP include directives.",
        "For DMARC: set p=quarantine or p=reject if the policy was weakened to p=none.",
        "Save changes and allow DNS propagation (TTL-dependent).",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Verify email authentication records using MXToolbox or similar (SPF, DKIM, DMARC lookups).",
        "Send a test email and check the authentication results in the received headers.",
      ],
      caveats: [
        "SPF lookups are limited to 10 DNS lookups — exceeding this causes SPF to fail for all recipients.",
        "DKIM records must match the selector used by the signing ESP — confirm the correct selector subdomain.",
        "Tightening DMARC policy before SPF/DKIM are fully aligned will cause legitimate email to be rejected.",
      ],
      docs_links: [
        { label: "Cloudflare email security DNS records", url: "https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/" },
        { label: "Cloudflare DMARC management",           url: "https://developers.cloudflare.com/dmarc-management/" },
      ],
      provider_console_hint:
        "Cloudflare Dashboard → [zone] → DNS → Records → locate the SPF/DKIM/DMARC TXT record.",
    });
  }

  // MX record removed — inbound email delivery failure
  if (rt === "mx" && ct === "removed") {
    return _guidance({
      confidence: "high",
      title:   "Restore Cloudflare MX record",
      summary:
        "Re-create the removed MX record to restore inbound email delivery for this domain.",
      why_this_helps:
        "MX records direct inbound email for a domain to the correct mail server. Without an MX record, " +
        "sending mail servers have no target to deliver to and will return delivery failures to the sender. " +
        "Depending on the sender's retry window, email loss begins within minutes of the MX record being removed.",
      verify_first: [
        "Confirm the MX record removal was not part of a planned email provider migration.",
        "Identify the previous MX value (mail server hostname) and priority from a recent DNS snapshot or your email provider's documentation.",
        "Verify the mail server the MX record points to is still operational.",
        "Check whether a replacement MX record was supposed to be created as part of this change.",
      ],
      manual_steps: [
        "Log into the Cloudflare dashboard → select the affected zone → DNS → Records.",
        "Click 'Add record' and select type 'MX'.",
        "Enter the mail server hostname (e.g. mail.example.com or your provider's MX target).",
        "Set the priority value (lower numbers = higher priority; 10 is common for a single provider).",
        "Save the record and verify it appears in the DNS records list.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Verify MX resolution using: dig MX <domain> @8.8.8.8",
        "Send a test inbound email to a mailbox on the domain and confirm delivery.",
      ],
      caveats: [
        "MX record propagation depends on the TTL — recovery may be delayed if a high TTL is cached by upstream resolvers.",
        "If multiple MX records existed (primary and backup), restore all of them — not just the highest-priority one.",
      ],
      docs_links: [
        { label: "Cloudflare MX records",  url: "https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/" },
        { label: "Cloudflare DNS records", url: "https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/" },
      ],
      provider_console_hint:
        "Cloudflare Dashboard → [zone] → DNS → Records → Add record → MX.",
    });
  }

  // Wildcard DNS change — broad traffic redirection risk
  if (rrl.includes("wildcard")) {
    return _guidance({
      confidence: "high",
      title:   "Verify Cloudflare wildcard DNS change",
      summary:
        "Confirm the wildcard DNS record change was intentional. A wildcard record change affects " +
        "routing for all subdomains not covered by a more specific record.",
      why_this_helps:
        "A wildcard DNS record (*.example.com) matches any subdomain not explicitly defined in the zone. " +
        "Changing a wildcard record redirects traffic for potentially hundreds of subdomains at once to a " +
        "new destination. An unexpected wildcard change can misdirect user traffic, break application " +
        "subdomains, or — if an attacker controls the target — serve malicious content across your domain.",
      verify_first: [
        "Confirm the new wildcard record value is a destination under your control.",
        "Check Cloudflare audit logs to identify who made the change and when.",
        "Identify which specific subdomains rely on the wildcard record for routing.",
        "Confirm whether more-specific records exist for critical subdomains (app., api., mail.) that override the wildcard.",
      ],
      manual_steps: [
        "Log into the Cloudflare dashboard → select the affected zone → DNS → Records.",
        "Locate the wildcard record (*) and verify its current value.",
        "If the change was unintentional: edit the record to restore the previous destination.",
        "Verify that critical subdomains have explicit records and are not solely reliant on the wildcard.",
        "Save changes.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Test a sample of subdomains using DNS lookup tools to confirm they resolve to expected destinations.",
      ],
      caveats: [
        "Wildcard records are overridden by more-specific hostname records — changes may only affect subdomains with no explicit record.",
        "Cloudflare proxies wildcard records only when the wildcard is proxied; unproxied wildcard records expose the origin IP.",
      ],
      docs_links: [
        { label: "Cloudflare wildcard DNS records", url: "https://developers.cloudflare.com/dns/manage-dns-records/reference/wildcard-dns-records/" },
      ],
      provider_console_hint:
        "Cloudflare Dashboard → [zone] → DNS → Records → locate the * (wildcard) record.",
    });
  }

  // Proxy status disabled — Cloudflare protection removed from record
  if (fp === "proxied" && nv === false) {
    return _guidance({
      confidence: "medium",
      title:   "Review Cloudflare proxy status change",
      summary:
        "Confirm that disabling the Cloudflare proxy on this DNS record was intentional. " +
        "Unproxied records bypass Cloudflare's WAF, DDoS mitigation, and hide the origin IP.",
      why_this_helps:
        "When a Cloudflare DNS record is proxied (orange cloud), traffic passes through Cloudflare's " +
        "network, applying WAF rules, DDoS protection, caching, and rate limiting. Disabling the proxy " +
        "(grey cloud) routes traffic directly to the origin server, bypassing all Cloudflare security " +
        "controls and exposing the origin IP address to the public — which can enable direct attacks " +
        "targeting the origin that circumvent Cloudflare's protections entirely.",
      verify_first: [
        "Confirm the proxy was disabled intentionally (e.g. for a non-HTTP service, VPN, or SSH record).",
        "Verify the origin server has its own firewall rules restricting direct access to known IPs if unproxied.",
        "Check whether WAF or rate limiting rules were relying on this record being proxied.",
        "Confirm the origin IP is not otherwise exposed in other DNS records or TLS certificates.",
      ],
      manual_steps: [
        "Log into the Cloudflare dashboard → select the affected zone → DNS → Records.",
        "Locate the affected record and click Edit.",
        "Toggle the proxy status to 'Proxied' (orange cloud icon).",
        "Save the record.",
        "Verify traffic is now routing through Cloudflare by checking the response headers for cf-ray.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Confirm the response includes a cf-ray header indicating Cloudflare is proxying the request.",
        "Test the affected service still functions correctly after re-enabling the proxy.",
      ],
      caveats: [
        "Some record types (MX, NS, TXT) cannot be proxied — proxy status applies to A, AAAA, and CNAME records serving HTTP/HTTPS traffic.",
        "Non-HTTP services (SMTP, SSH, VPN) typically cannot be proxied and should remain grey-cloud.",
        "Re-enabling the proxy changes the visible IP to Cloudflare's anycast IPs — ensure origin firewall rules allow Cloudflare's IP ranges.",
      ],
      docs_links: [
        { label: "Cloudflare proxy vs DNS-only",    url: "https://developers.cloudflare.com/dns/manage-dns-records/reference/proxied-dns-records/" },
        { label: "Cloudflare IP ranges",            url: "https://www.cloudflare.com/ips/" },
      ],
      provider_console_hint:
        "Cloudflare Dashboard → [zone] → DNS → Records → [record] → Edit → toggle proxy status.",
    });
  }

  // Generic Cloudflare DNS high/critical fallback
  return _guidance({
    confidence: "medium",
    title:   "Verify Cloudflare DNS routing change",
    summary:
      "Confirm the DNS record change was intentional and that affected hostnames are routing " +
      "to the correct destination.",
    why_this_helps:
      "DNS changes take effect within the record's TTL window and can redirect or break routing for " +
      "any service or application depending on the affected hostname. High-risk DNS changes include " +
      "value changes to production hostnames, removal of critical records, and changes to records " +
      "that affect broad groups of subdomains.",
    verify_first: [
      "Confirm the new record value is a destination under your control.",
      "Check Cloudflare audit logs to identify who made the change.",
      "Identify all services and applications that depend on this DNS record.",
      "Confirm the change was part of a planned deployment or migration.",
    ],
    manual_steps: [
      "Log into the Cloudflare dashboard → select the affected zone → DNS → Records.",
      "Locate the changed record and verify its current value.",
      "If the change was unintentional: edit the record to restore the previous value.",
      "Save changes and allow DNS propagation.",
    ],
    validation_steps: [
      ...STANDARD_VALIDATION,
      "Verify DNS resolution for the affected hostname using a DNS lookup tool.",
    ],
    caveats: [
      "DNS changes propagate globally within the record TTL — a low TTL means faster recovery if a change needs to be reverted.",
      "Cloudflare changes are near-instant at the Cloudflare edge, but upstream resolver caches may hold the old value until TTL expires.",
    ],
    docs_links: [
      { label: "Cloudflare DNS records",  url: "https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/" },
      { label: "Cloudflare audit logs",   url: "https://developers.cloudflare.com/fundamentals/account-and-billing/account-security/review-audit-logs/" },
    ],
    provider_console_hint:
      "Cloudflare Dashboard → [zone] → DNS → Records.",
  });
}

// ── 2b. Cloudflare WAF rulesets ───────────────────────────────────────────────

function _cfRulesetPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "cloudflare_ruleset") return null;
  if (!_isHighOrCritical(rl) && ct !== "removed") return null;

  // Ruleset removed entirely
  if (ct === "removed") {
    return _guidance({
      confidence: "high",
      title:   "Restore removed Cloudflare WAF ruleset",
      summary:
        "Re-create or re-enable the Cloudflare WAF ruleset that was removed to restore " +
        "application-layer protection for the affected zone.",
      why_this_helps:
        "Cloudflare WAF rulesets provide protection against SQL injection, cross-site scripting, " +
        "credential stuffing, and bot attacks at the network edge — before requests reach your origin. " +
        "Removing a ruleset eliminates this entire protection layer, and the zone will process all " +
        "matching traffic without WAF evaluation until the ruleset is restored.",
      verify_first: [
        "Confirm the ruleset removal was intentional (e.g. zone migration, ruleset replacement).",
        "Check Cloudflare audit logs to identify who removed the ruleset and when.",
        "Verify whether a replacement ruleset or equivalent protection is already in place.",
        "Identify which WAF phase this ruleset covered (http_request_firewall_managed, http_request_firewall_custom, etc.).",
      ],
      manual_steps: [
        "Log into the Cloudflare dashboard → select the affected zone.",
        "Navigate to Security → WAF → Managed rules.",
        "Re-deploy the Cloudflare Managed Ruleset or OWASP Core Ruleset that was removed.",
        "Alternatively: navigate to Security → WAF → Custom rules to restore any removed custom rulesets.",
        "Enable the ruleset and confirm the rule count is as expected.",
        "Monitor Security → Overview for blocked/challenged requests.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Re-enabling the Cloudflare Managed Ruleset may block legitimate traffic if rules were previously bypassed for a reason — monitor in Log mode initially.",
        "Cloudflare Managed Ruleset updates happen automatically — confirm the ruleset version is appropriate.",
      ],
      docs_links: [
        { label: "Cloudflare WAF managed rules",  url: "https://developers.cloudflare.com/waf/managed-rules/" },
        { label: "Cloudflare ruleset engine",     url: "https://developers.cloudflare.com/ruleset-engine/" },
      ],
      provider_console_hint:
        "Cloudflare Dashboard → [zone] → Security → WAF → Managed rules.",
    });
  }

  // skip_count increased — bypass rules added
  if (fp === "skip_count") {
    return _guidance({
      confidence: "medium",
      title:   "Review increased Cloudflare WAF skip/bypass rules",
      summary:
        "Review the newly added WAF skip or bypass rules to confirm they are scoped narrowly " +
        "and are not bypassing protection more broadly than intended.",
      why_this_helps:
        "WAF skip rules instruct Cloudflare to skip further rule evaluation for matching requests. " +
        "A broadly-scoped skip rule (e.g. skipping all managed rules for a wide URI pattern or large " +
        "IP range) can neutralise large portions of WAF coverage for a subset of traffic. Attackers " +
        "who discover or can trigger these skip conditions can bypass WAF protection entirely for " +
        "affected requests.",
      verify_first: [
        "Review the specific skip rule(s) that were added — identify the match expression (URI, IP, header).",
        "Confirm whether the skip condition is scoped to a specific path, IP address, or ASN — not a broad wildcard.",
        "Check whether the skip was added to resolve a WAF false positive — if so, verify a narrower exception couldn't achieve the same result.",
        "Review Cloudflare audit logs to confirm who added the skip rule.",
      ],
      manual_steps: [
        "Log into the Cloudflare dashboard → select the affected zone → Security → WAF → Custom rules.",
        "Locate the skip/bypass rule(s) that were added.",
        "Review the match expression — confirm it matches only the intended traffic.",
        "If too broad: edit the rule to add a more specific IP, URI path, or header condition.",
        "If the skip is no longer needed: delete the rule.",
        "Save changes.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Narrowing a skip rule may re-expose previously bypassed requests to WAF rules — confirm no false positives occur.",
        "Skip rules in the Managed Ruleset phase can bypass both Cloudflare's and OWASP's rules simultaneously.",
      ],
      docs_links: [
        { label: "Cloudflare WAF exceptions",    url: "https://developers.cloudflare.com/waf/managed-rules/waf-exceptions/" },
        { label: "Cloudflare ruleset engine",    url: "https://developers.cloudflare.com/ruleset-engine/" },
      ],
      provider_console_hint:
        "Cloudflare Dashboard → [zone] → Security → WAF → Custom rules → review skip/bypass rules.",
    });
  }

  // block_count or enabled_rule_count reduced — coverage weakened
  if (fp === "block_count" || fp === "enabled_rule_count") {
    return _guidance({
      confidence: "medium",
      title:   "Review reduced Cloudflare WAF coverage",
      summary:
        "Re-enable disabled WAF rules or restore block actions to recover coverage against " +
        "the attack patterns previously addressed by the removed rules.",
      why_this_helps:
        "Reducing the number of active WAF rules or changing rule actions from Block to Log/Challenge " +
        "weakens the effective protection of the WAF ruleset. Each disabled rule represents a category " +
        "of attacks — such as SQLi, XSS, or known CVE payloads — that will pass through unblocked. " +
        "Even temporary rule disabling during an incident or deployment can create a window of exposure.",
      verify_first: [
        "Identify which specific rules were disabled or had their action changed.",
        "Confirm whether the rule change was made to resolve a false positive affecting production traffic.",
        "Verify whether the affected rule categories are covered by any other WAF rules or custom rules.",
        "Check Cloudflare Security → Analytics for traffic patterns before and after the change.",
      ],
      manual_steps: [
        "Log into the Cloudflare dashboard → select the affected zone → Security → WAF.",
        "Navigate to Managed rules → review individual rule overrides.",
        "Re-enable any rules that were set to Disabled.",
        "For rules changed from Block to Log or Challenge: change the action back to Block.",
        "If a false positive was the reason for the change: create a narrower WAF exception for the specific URI or IP instead.",
        "Save changes and monitor Security → Overview.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Restoring Block actions on rules that had false positives will re-block the affected traffic — have a narrow exception ready.",
        "Cloudflare managed rules are updated by Cloudflare — the rule IDs may have changed since they were last reviewed.",
      ],
      docs_links: [
        { label: "Cloudflare WAF managed rules",     url: "https://developers.cloudflare.com/waf/managed-rules/" },
        { label: "Cloudflare WAF rule overrides",    url: "https://developers.cloudflare.com/waf/managed-rules/override-managed-rules/" },
      ],
      provider_console_hint:
        "Cloudflare Dashboard → [zone] → Security → WAF → Managed rules → rule overrides.",
    });
  }

  // Generic Cloudflare ruleset high/critical fallback
  return _guidance({
    confidence: ct === "removed" ? "high" : "medium",
    title:   "Re-enable WAF ruleset and restore rule coverage",
    summary:
      "Restore disabled WAF rules, re-enable the ruleset, or remove unintended skip/bypass " +
      "rules that reduced protection coverage.",
    why_this_helps:
      "Cloudflare WAF rulesets are the primary application-layer defence for your zone. Disabling " +
      "managed rules, removing block actions, or increasing skip/bypass counts means malicious requests " +
      "(SQL injection, XSS, credential stuffing, bot attacks) may pass through unfiltered. Even a " +
      "temporary ruleset disable during a deployment can leave the zone unprotected if not restored.",
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
