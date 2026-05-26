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
// Playbook 3 — Firebase (dispatcher)
// ─────────────────────────────────────────────────────────────────────────────

function _firebasePlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  return (
    _fbRulesetPlaybooks(rt, fp, ct, rl, rr, nv)      ??
    _fbAuthPlaybooks(rt, fp, ct, rl, rr, nv)         ??
    _fbAppCheckPlaybooks(rt, fp, ct, rl, rr, nv)     ??
    _fbRemoteConfigPlaybooks(rt, fp, ct, rl, rr, nv) ??
    _fbFunctionPlaybooks(rt, fp, ct, rl, rr, nv)     ??
    _fbStorageBucketPlaybooks(rt, fp, ct, rl, rr, nv)??
    null
  );
}

// ── 3a. Firestore + Storage security rules ────────────────────────────────────

function _fbRulesetPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  const isRuleset =
    rt === "firebase_firestore_ruleset" ||
    rt === "firebase_storage_ruleset";
  if (!isRuleset) return null;

  const surface = rt.includes("storage") ? "Storage" : "Firestore";

  // Public write detected
  if (fp === "public_write_detected" && nv === true) {
    return _guidance({
      confidence: "high",
      title:   `Restrict public ${surface} writes`,
      summary:
        `Update ${surface} security rules so writes require authentication ` +
        `and the intended authorization checks.`,
      why_this_helps:
        `Firebase security rules are the sole data-access control layer for ${surface} when ` +
        `accessed from client SDKs. A rule that permits \`allow write: if true;\` or ` +
        `\`allow write: if request.auth == null;\` on any path exposes your ` +
        `${surface === "Storage" ? "storage bucket to unauthenticated uploads, overwrites, and deletions" : "database to unauthenticated create, update, and delete operations"} ` +
        `from the public internet. ` +
        `${surface === "Storage" ? "This can result in storage abuse, malware hosting, or data destruction." : "This can result in data injection, spam, or overwriting production documents."}`,
      verify_first: [
        `Confirm this is the production Firebase project, not a staging or development environment.`,
        `Identify which ${surface === "Storage" ? "bucket paths" : "Firestore collection paths"} currently allow public writes.`,
        `Confirm whether any app feature legitimately requires unauthenticated writes — if so, scope the rule to a specific path only.`,
        `Confirm whether server-side services rely on the Admin SDK — Admin SDK traffic bypasses security rules entirely.`,
        `Test rule changes in a staging project or the Firebase Rules Playground before publishing to production.`,
      ],
      manual_steps: [
        `Open the Firebase Console → select the affected project.`,
        `Navigate to ${surface === "Storage" ? "Storage" : "Firestore Database"} → Rules tab.`,
        `Locate rules that allow writes without an auth check (e.g. \`allow write: if true;\`).`,
        `Replace with an authenticated condition, for example: \`allow write: if request.auth != null;\``,
        `For user-specific paths, add ownership checks: \`if request.auth.uid == resource.data.owner_id;\``,
        `Use the Firebase Rules Playground to test the updated rules against expected read/write patterns.`,
        `Publish the rules only after confirming legitimate client flows still work.`,
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        `Test expected authenticated write flows in the app to confirm they still succeed.`,
        `Test unauthenticated write attempts to confirm they are rejected.`,
      ],
      caveats: [
        `Tightening rules without reviewing all app code paths can break legitimate client writes.`,
        `Rules changes take effect immediately — have a rollback plan ready.`,
        `Admin SDK traffic (server-side) bypasses security rules regardless of the published rules — verify client vs server access paths separately.`,
        `If App Check is not yet enforced, authenticated rules alone provide weaker protection than authenticated + App Check together.`,
      ],
      docs_links: [
        { label: `Firebase ${surface} security rules`,  url: `https://firebase.google.com/docs/rules` },
        { label: "Firebase Rules Playground",           url: "https://firebase.google.com/docs/rules/simulator" },
      ],
      provider_console_hint:
        `Firebase Console → [project] → ${surface === "Storage" ? "Storage" : "Firestore Database"} → Rules.`,
    });
  }

  // Public read detected
  if (fp === "public_read_detected" && nv === true) {
    return _guidance({
      confidence: rl === "critical" ? "high" : "medium",
      title:   `Review public ${surface} read access`,
      summary:
        `Confirm public read access is intentional and restrict any sensitive ` +
        `${surface === "Storage" ? "file paths" : "collection paths"} to authenticated or authorized users.`,
      why_this_helps:
        `Public read rules allow any internet client to read ` +
        `${surface === "Storage" ? "files from your storage bucket" : "documents from your Firestore collections"} ` +
        `without signing in. Some public reads are intentional — for example, serving public content or ` +
        `assets — but public reads on paths containing user data, internal content, or tenant-specific ` +
        `records may expose data unintentionally.`,
      verify_first: [
        `Identify which ${surface === "Storage" ? "bucket paths" : "Firestore collection paths"} currently allow public reads.`,
        `Confirm whether the affected paths contain any user data, internal records, or sensitive content.`,
        `Confirm whether anonymous/unauthenticated clients are expected to read from these paths.`,
        `Confirm whether the rules differ between your staging and production projects.`,
      ],
      manual_steps: [
        `Open the Firebase Console → select the affected project.`,
        `Navigate to ${surface === "Storage" ? "Storage" : "Firestore Database"} → Rules tab.`,
        `Identify paths with \`allow read: if true;\` or similar unauthenticated conditions.`,
        `Keep public reads only on paths serving intentionally public content.`,
        `Add \`request.auth != null\` or role-based conditions for paths containing non-public data.`,
        `Test anonymous and authenticated access in the Firebase Rules Playground.`,
        `Publish the updated rules.`,
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        `Test anonymous read access is blocked on sensitive paths after the rule update.`,
        `Test authenticated read access still works for expected user flows.`,
      ],
      caveats: [
        `Removing public reads can break unauthenticated pages or app flows that rely on publicly readable data.`,
        `If the ${surface === "Storage" ? "bucket" : "collection"} intentionally serves public content, a narrow path-specific rule is safer than a broad allow-all.`,
      ],
      docs_links: [
        { label: `Firebase ${surface} security rules`, url: `https://firebase.google.com/docs/rules` },
        { label: "Firebase Rules Playground",          url: "https://firebase.google.com/docs/rules/simulator" },
      ],
      provider_console_hint:
        `Firebase Console → [project] → ${surface === "Storage" ? "Storage" : "Firestore Database"} → Rules.`,
    });
  }

  // Rules deployment changed (hash changed) — medium
  if (fp === "rules_hash" || fp === "ruleset_name_hash") {
    return _guidance({
      confidence: "medium",
      title:   `Review ${surface} security rules deployment`,
      summary:
        `Confirm the updated ${surface} security rules deployment is intentional ` +
        `and that access control for sensitive paths is unchanged or improved.`,
      why_this_helps:
        `A change to the active ${surface} ruleset hash means a new rules deployment was published. ` +
        `Even if the change was intentional, rules deployments can inadvertently loosen access control ` +
        `or introduce logic errors that affect read/write permissions across your app.`,
      verify_first: [
        `Confirm who published the updated rules and when — check Firebase Console history or audit logs.`,
        `Review the diff between the previous and current rules deployments.`,
        `Confirm the updated rules correctly restrict sensitive paths.`,
      ],
      manual_steps: [
        `Open the Firebase Console → select the affected project.`,
        `Navigate to ${surface === "Storage" ? "Storage" : "Firestore Database"} → Rules tab.`,
        `Review the current published rules for any unintended public access conditions.`,
        `Use the Rules Playground to test expected read/write patterns.`,
        `Roll back to the previous ruleset if the change was accidental.`,
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        `ConfigTrace stores a hash of the ruleset, not the raw source — use the Firebase Console to inspect the actual rules.`,
      ],
      docs_links: [
        { label: `Firebase ${surface} security rules`, url: `https://firebase.google.com/docs/rules` },
      ],
      provider_console_hint:
        `Firebase Console → [project] → ${surface === "Storage" ? "Storage" : "Firestore Database"} → Rules.`,
    });
  }

  return null;
}

// ── 3b. Firebase Auth ─────────────────────────────────────────────────────────

function _fbAuthPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {

  // Anonymous auth enabled
  if (
    rt === "firebase_auth_config" &&
    fp === "anonymous_enabled" && (nv === true || nv === "true")
  ) {
    return _guidance({
      confidence: "high",
      title:   "Review anonymous authentication",
      summary:
        "Confirm anonymous sign-in is intentional and verify that Firestore/Storage rules " +
        "restrict what anonymous users can access.",
      why_this_helps:
        "Anonymous auth lets any internet user sign in without credentials, obtaining a valid Firebase " +
        "auth token. This is safe when intentionally scoped — for example, for a guest onboarding flow — " +
        "but it increases the importance of tight Firestore and Storage rules: anonymous users with a " +
        "valid token can pass \`request.auth != null\` checks, which may expose more data than intended.",
      verify_first: [
        "Confirm whether the product intentionally supports anonymous or guest users.",
        "Review Firestore and Storage rules to confirm anonymous users cannot access sensitive paths.",
        "Confirm anonymous accounts are upgraded or linked to permanent accounts when needed.",
        "Confirm this is the production project, not a development environment where anonymous auth is used for testing.",
      ],
      manual_steps: [
        "Open the Firebase Console → [project] → Authentication → Sign-in method.",
        "Review the Anonymous provider status.",
        "If anonymous sign-in is not required: disable it by toggling the provider off.",
        "If anonymous sign-in is required: review Firestore/Storage rules to confirm anonymous users are appropriately restricted.",
        "Consider enabling Firebase App Check to limit anonymous auth to legitimate app clients only.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "If disabled: test that guest/anonymous sign-in flows fail as expected.",
        "If kept enabled: verify that anonymous users cannot read or write sensitive data paths.",
      ],
      caveats: [
        "Disabling anonymous auth can break guest-session or onboarding flows that rely on it.",
        "Anonymous auth does not bypass security rules — but rules that only check request.auth != null will allow anonymous users.",
      ],
      docs_links: [
        { label: "Firebase Anonymous Authentication", url: "https://firebase.google.com/docs/auth/web/anonymous-auth" },
        { label: "Firebase Auth sign-in methods",     url: "https://firebase.google.com/docs/auth" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → Authentication → Sign-in method → Anonymous.",
    });
  }

  // MFA disabled
  if (
    rt === "firebase_auth_config" &&
    (fp === "mfa_enabled" || fp === "mfa_state") &&
    (nv === false || nv === "false" || String(nv).toUpperCase() === "DISABLED")
  ) {
    return _guidance({
      confidence: "high",
      title:   "Verify Firebase MFA was intentionally disabled",
      summary:
        "Confirm multi-factor authentication was intentionally disabled and that alternative " +
        "account security controls are in place for sensitive user accounts.",
      why_this_helps:
        "Multi-factor authentication is a primary defence against account takeover via stolen or " +
        "phished credentials. Disabling MFA at the project level removes the ability for users to " +
        "enroll in TOTP or SMS second factors, reducing the barrier for credential-based attacks on " +
        "your Firebase user accounts.",
      verify_first: [
        "Confirm who disabled MFA and the reason — check the Firebase Console change history.",
        "Confirm whether any users currently have MFA enrolled and whether disabling it affects them.",
        "Confirm whether MFA is required for admin or high-privilege user accounts.",
        "Confirm this is the production project, not a development environment.",
      ],
      manual_steps: [
        "Open the Firebase Console → [project] → Authentication → Sign-in method.",
        "Scroll to Multi-factor Authentication.",
        "Re-enable MFA if the change was unintentional.",
        "If keeping MFA disabled: confirm alternative account security controls are in place (strong password policies, rate limiting).",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Re-enabling MFA does not automatically enroll existing users — it only allows them to enroll.",
        "MFA availability depends on the Firebase pricing plan — confirm the project is on Blaze if TOTP MFA is required.",
      ],
      docs_links: [
        { label: "Firebase Multi-factor Authentication", url: "https://firebase.google.com/docs/auth/web/multi-factor-auth" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → Authentication → Sign-in method → Multi-factor Authentication.",
    });
  }

  // Authorized domain added (non-default, non-localhost — high risk)
  if (
    rt === "firebase_authorized_domain" &&
    ct === "added" && _isHighOrCritical(rl)
  ) {
    return _guidance({
      confidence: "high",
      title:   "Review Firebase Auth authorized domains",
      summary:
        "Confirm the newly added authorized domain belongs to your application and " +
        "was not added unintentionally.",
      why_this_helps:
        "Firebase Authentication uses the authorized domain list to control which origins are " +
        "permitted to initiate OAuth redirect flows. An unexpected domain on this list could allow " +
        "a third-party origin to complete OAuth sign-in redirects on behalf of your app — a form " +
        "of open-redirect or OAuth flow hijacking risk.",
      verify_first: [
        "Confirm the new domain belongs to your application (production, staging, or a known preview environment).",
        "Confirm who added the domain and when — check the Firebase Console change history.",
        "Verify the domain is not a temporary, external, or suspicious origin.",
        "Confirm that OAuth redirect flows (Sign in with Google, etc.) are only used from expected origins.",
      ],
      manual_steps: [
        "Open the Firebase Console → [project] → Authentication → Settings → Authorized domains.",
        "Review the full domain list.",
        "Remove any domain that is not an expected application host.",
        "If the domain was added for a new environment: confirm it is correctly scoped.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Confirm sign-in OAuth redirect flows work from expected domains after any removals.",
      ],
      caveats: [
        "Removing a domain that is actively used for sign-in will break OAuth redirect flows for that environment.",
        "Default Firebase domains (*.firebaseapp.com, *.web.app) and localhost are normal and expected.",
      ],
      docs_links: [
        { label: "Firebase Auth authorized domains", url: "https://firebase.google.com/docs/auth/web/google-signin#before_you_begin" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → Authentication → Settings → Authorized domains.",
    });
  }

  // Authorized domain removed — medium
  if (rt === "firebase_authorized_domain" && ct === "removed" && rl === "medium") {
    return _guidance({
      confidence: "medium",
      title:   "Verify Firebase Auth authorized domain removal",
      summary:
        "Confirm the removed authorized domain was intentional and that sign-in flows " +
        "for legitimate environments are not affected.",
      why_this_helps:
        "Removing a domain from the Firebase Auth authorized list blocks OAuth redirect flows " +
        "from that origin — any sign-in attempts (Google, GitHub, etc.) from the removed domain " +
        "will fail with an unauthorized domain error.",
      verify_first: [
        "Confirm the removed domain is no longer an active environment.",
        "Check whether any users or deployments still use this domain for authentication.",
        "Confirm the removal was part of a planned decommission or domain change.",
      ],
      manual_steps: [
        "Open the Firebase Console → [project] → Authentication → Settings → Authorized domains.",
        "If the removal was unintentional: re-add the domain.",
        "Test sign-in flows from all active environments.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Restoring the domain takes effect immediately — test sign-in flows after re-adding.",
      ],
      docs_links: [
        { label: "Firebase Auth authorized domains", url: "https://firebase.google.com/docs/auth/web/google-signin#before_you_begin" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → Authentication → Settings → Authorized domains.",
    });
  }

  return null;
}

// ── 3c. Firebase App Check ────────────────────────────────────────────────────

function _fbAppCheckPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "firebase_app_check_config") return null;

  // Record removed entirely
  if (ct === "removed") {
    return _guidance({
      confidence: "high",
      title:   "Verify Firebase App Check configuration removal",
      summary:
        "Confirm the App Check configuration record was not unexpectedly removed and " +
        "that enforcement is still active for protected services.",
      why_this_helps:
        "Loss of the App Check configuration record may indicate that App Check is no longer " +
        "enabled or that the connector lost access to the App Check API. If enforcement was " +
        "previously active, services may now accept requests from unattested clients.",
      verify_first: [
        "Open the Firebase Console → App Check and confirm whether enforcement is still visible.",
        "Confirm whether a recent project change affected App Check API access.",
        "Verify this is the production project.",
      ],
      manual_steps: [
        "Open the Firebase Console → [project] → App Check.",
        "Confirm enforcement is still active for the expected services.",
        "Run a ConfigTrace sync to re-baseline App Check state.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "App Check enforcement can only be managed through the Firebase Console — ConfigTrace is read-only.",
      ],
      docs_links: [
        { label: "Firebase App Check", url: "https://firebase.google.com/docs/app-check" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → App Check.",
    });
  }

  // enforced_service_count decreased — fewer services protected
  if (fp === "enforced_service_count" && _isHighOrCritical(rl)) {
    return _guidance({
      confidence: "high",
      title:   "Restore Firebase App Check enforcement",
      summary:
        "Re-enable App Check enforcement for the services that were unenforced to prevent " +
        "unauthorized or unattested clients from calling those Firebase APIs.",
      why_this_helps:
        "Firebase App Check enforcement requires clients to pass a device-attestation check " +
        "(Play Integrity, App Attest, reCAPTCHA) before accessing Firebase services. When enforcement " +
        "is removed from a service, any client — including scripts, bots, or unauthorized apps — can " +
        "call that service's APIs without attestation, bypassing this abuse-prevention layer.",
      verify_first: [
        "Identify which specific services lost enforcement (Firestore, Storage, Functions, etc.).",
        "Confirm whether the change was part of a planned rollout pause or rollback.",
        "Verify all active app versions have App Check providers correctly registered before re-enforcing.",
        "Confirm debug tokens are registered for development/CI environments to avoid breaking those flows.",
      ],
      manual_steps: [
        "Open the Firebase Console → [project] → App Check.",
        "Review the enforcement status for each service — identify services showing 'Unenforced'.",
        "Click 'Enforce' on each service that should be protected.",
        "Monitor App Check metrics for client errors after enforcement is re-enabled.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Confirm the enforced_service_count returns to the expected value after a sync.",
        "Test supported app versions to confirm they pass App Check attestation.",
      ],
      caveats: [
        "Enabling enforcement too early can block legitimate clients that do not yet have App Check providers registered.",
        "Debug tokens must be registered for development and CI environments to continue working after enforcement is enabled.",
        "Older app versions without App Check support will be blocked once enforcement is active.",
      ],
      docs_links: [
        { label: "Firebase App Check",              url: "https://firebase.google.com/docs/app-check" },
        { label: "App Check enforcement guidance",  url: "https://firebase.google.com/docs/app-check/manage-enforcement" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → App Check → [service] → Enforce.",
    });
  }

  // unenforced_service_count increased — more services now unprotected
  if (fp === "unenforced_service_count" && _isHighOrCritical(rl)) {
    return _guidance({
      confidence: "high",
      title:   "Restore Firebase App Check enforcement",
      summary:
        "Re-enable App Check enforcement for the services that moved to unenforced status " +
        "to prevent unauthorized clients from accessing those Firebase APIs.",
      why_this_helps:
        "An increase in unenforced services means additional Firebase APIs can now be called " +
        "without device attestation. This expands the attack surface for automated abuse, " +
        "credential stuffing, and unauthorized API access beyond what was previously allowed.",
      verify_first: [
        "Identify which services moved from enforced to unenforced.",
        "Confirm whether the change was intentional (rollout pause, debugging, or migration).",
        "Verify all active app versions have App Check providers registered before re-enforcing.",
      ],
      manual_steps: [
        "Open the Firebase Console → [project] → App Check.",
        "Identify services with 'Unenforced' status that should be protected.",
        "Click 'Enforce' to re-enable enforcement on those services.",
        "Monitor App Check metrics for any unexpected client failures.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Confirm unenforced_service_count returns to the expected lower value after a sync.",
      ],
      caveats: [
        "Enabling enforcement blocks clients without valid App Check tokens — ensure all production app versions are updated first.",
        "Debug tokens must be registered for non-production environments.",
      ],
      docs_links: [
        { label: "Firebase App Check",              url: "https://firebase.google.com/docs/app-check" },
        { label: "App Check enforcement guidance",  url: "https://firebase.google.com/docs/app-check/manage-enforcement" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → App Check.",
    });
  }

  // service_count changed — services added or removed from monitoring
  if (fp === "service_count") {
    return _guidance({
      confidence: "medium",
      title:   "Review Firebase App Check service count change",
      summary:
        "Confirm the change in App Check–monitored services was intentional and " +
        "that no service was removed from App Check coverage unintentionally.",
      why_this_helps:
        "The App Check service count tracks how many Firebase services are configured under " +
        "App Check monitoring. A decrease may indicate a service was removed from App Check, " +
        "which could mean it is now unmonitored and potentially accessible without attestation.",
      verify_first: [
        "Identify which service was added or removed from App Check coverage.",
        "Confirm whether the service is now enforced, unenforced, or removed entirely.",
        "Verify the change was part of a planned App Check rollout or service decommission.",
      ],
      manual_steps: [
        "Open the Firebase Console → [project] → App Check.",
        "Review the full list of services and their enforcement status.",
        "Re-add and enforce any service that was removed unintentionally.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "App Check service monitoring is separate from enforcement — a service can be monitored but unenforced.",
      ],
      docs_links: [
        { label: "Firebase App Check", url: "https://firebase.google.com/docs/app-check" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → App Check.",
    });
  }

  return null;
}

// ── 3d. Firebase Remote Config ────────────────────────────────────────────────

function _fbRemoteConfigPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "firebase_remote_config_template") return null;

  // Template removed entirely
  if (ct === "removed") {
    return _guidance({
      confidence: "high",
      title:   "Verify Firebase Remote Config template removal",
      summary:
        "Confirm the Remote Config template record was not unexpectedly removed and that " +
        "app clients are still receiving the expected configuration.",
      why_this_helps:
        "Remote Config controls feature flags, rollout targeting, and app behavior parameters " +
        "served to clients. Loss of the template record may indicate the template was deleted or " +
        "the connector lost access, which could cause clients to fall back to hardcoded defaults " +
        "or behave unexpectedly.",
      verify_first: [
        "Open the Firebase Console → Remote Config and verify the template still exists.",
        "Confirm whether a recent project change affected Remote Config API access.",
        "Check whether app clients are receiving configuration correctly.",
      ],
      manual_steps: [
        "Open the Firebase Console → [project] → Remote Config.",
        "Verify the template is present and published.",
        "Run a ConfigTrace sync to re-baseline Remote Config state.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "ConfigTrace stores Remote Config metadata (counts and hashes), not raw parameter values — use the Firebase Console to inspect the actual template.",
      ],
      docs_links: [
        { label: "Firebase Remote Config", url: "https://firebase.google.com/docs/remote-config" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → Remote Config.",
    });
  }

  // Parameter count decreased — parameters may have been removed
  if (fp === "parameter_count") {
    return _guidance({
      confidence: "medium",
      title:   "Review Remote Config parameter count change",
      summary:
        "Confirm parameter additions or removals were intentional and that app clients " +
        "handle missing parameters gracefully.",
      why_this_helps:
        "Remote Config can alter application behavior without a code deploy. Parameters that " +
        "are removed from the template will cause clients to fall back to their in-app default " +
        "values. If the in-app default was not set or differs from the expected server value, " +
        "this can silently change feature flag behavior across all clients.",
      verify_first: [
        "Confirm who made the template update — check the Firebase Console version history.",
        "Identify which parameters were added or removed.",
        "Confirm app clients have appropriate in-app defaults for any removed parameters.",
        "Confirm the change was part of a planned release or cleanup.",
      ],
      manual_steps: [
        "Open the Firebase Console → [project] → Remote Config.",
        "Review the current template and compare with the version history.",
        "Roll back to the previous version if the parameter removal was accidental.",
        "If intentional: confirm all app versions handle the missing parameter via in-app defaults.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Test affected client behavior to confirm feature flags behave as expected.",
      ],
      caveats: [
        "ConfigTrace stores parameter counts and key hashes, not raw values — use the Firebase Console to inspect exact parameter values.",
        "Rollbacks via the Firebase Console take effect immediately for all clients that fetch config.",
      ],
      docs_links: [
        { label: "Firebase Remote Config",             url: "https://firebase.google.com/docs/remote-config" },
        { label: "Remote Config template versioning",  url: "https://firebase.google.com/docs/remote-config/templates" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → Remote Config → Version history.",
    });
  }

  // Condition count decreased
  if (fp === "condition_count") {
    return _guidance({
      confidence: "medium",
      title:   "Review Remote Config condition count change",
      summary:
        "Confirm condition changes were intentional and that any affected targeting or " +
        "rollout logic behaves as expected.",
      why_this_helps:
        "Remote Config conditions define the targeting logic for parameter values — for example, " +
        "routing specific parameter values to specific app versions, user segments, or platforms. " +
        "Removing a condition may cause all clients to receive a single default value instead of " +
        "the previously targeted value, silently changing rollout behavior.",
      verify_first: [
        "Identify which conditions were added or removed.",
        "Confirm whether affected parameters now use only default values for all clients.",
        "Confirm the change was part of a planned rollout cleanup or A/B test conclusion.",
      ],
      manual_steps: [
        "Open the Firebase Console → [project] → Remote Config.",
        "Review the conditions list and compare with the version history.",
        "Roll back to the previous version if the condition removal was accidental.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "ConfigTrace stores condition counts and name hashes, not the condition expressions — use the Firebase Console to inspect the actual targeting logic.",
      ],
      docs_links: [
        { label: "Firebase Remote Config",            url: "https://firebase.google.com/docs/remote-config" },
        { label: "Remote Config template versioning", url: "https://firebase.google.com/docs/remote-config/templates" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → Remote Config → Conditions.",
    });
  }

  // Structural key/name hash changed
  if (fp === "parameter_keys_hash" || fp === "condition_names_hash") {
    const subject = fp === "parameter_keys_hash" ? "parameter keys" : "condition names";
    return _guidance({
      confidence: "medium",
      title:   "Review Remote Config rollout changes",
      summary:
        `Confirm ${subject} changes were intentional before they affect production clients.`,
      why_this_helps:
        `The set of Remote Config ${subject} changed, which means parameters or conditions were ` +
        `added, renamed, or removed. Remote Config can alter application behavior without a code ` +
        `deploy — unexpected changes may affect feature flags, rollout targeting, or client-side ` +
        `configuration across all users.`,
      verify_first: [
        "Confirm who made the template update and the reason for the change.",
        "Review the full template in the Firebase Console to identify what changed.",
        "Confirm the change was part of a planned release, experiment, or cleanup.",
      ],
      manual_steps: [
        "Open the Firebase Console → [project] → Remote Config.",
        "Review the current template and compare with the version history.",
        "Roll back to the previous version if the change was accidental.",
        "Test affected client behavior after confirming the template is correct.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "ConfigTrace stores hashes of parameter key names and condition names, not their values or expressions — use the Firebase Console to inspect exact content.",
      ],
      docs_links: [
        { label: "Firebase Remote Config",            url: "https://firebase.google.com/docs/remote-config" },
        { label: "Remote Config template versioning", url: "https://firebase.google.com/docs/remote-config/templates" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → Remote Config → Version history.",
    });
  }

  // Forced update or rollback
  if (fp === "update_type") {
    const rrl = rr.toLowerCase();
    const isForced = rrl.includes("forced") || rrl.includes("rollback");
    return _guidance({
      confidence: isForced ? "medium" : "low" as "medium" | "low",
      title:   "Review Remote Config rollout changes",
      summary:
        "Confirm the Remote Config update type was intentional and that clients are " +
        "receiving the expected configuration.",
      why_this_helps:
        "FORCED_UPDATE and ROLLBACK update types affect all clients that fetch Remote Config " +
        "immediately. A forced update can override client-side caching, while a rollback reverts " +
        "to a previous template version. Either can change app behavior across all users at once.",
      verify_first: [
        "Confirm the update type was intentional — check the Firebase Console version history.",
        "If a rollback: confirm the target version is correct and that it does not re-introduce previous issues.",
      ],
      manual_steps: [
        "Open the Firebase Console → [project] → Remote Config.",
        "Review the current template version and update history.",
        "If the update was accidental: roll back to the intended version.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Forced updates bypass client-side fetch throttling — all clients will see the new config on their next fetch cycle.",
      ],
      docs_links: [
        { label: "Firebase Remote Config", url: "https://firebase.google.com/docs/remote-config" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → Remote Config → Version history.",
    });
  }

  return null;
}

// ── 3e. Firebase Cloud Functions ──────────────────────────────────────────────

function _fbFunctionPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "firebase_function_metadata") return null;
  if (rl !== "medium" && !_isHighOrCritical(rl)) return null;

  if (fp === "runtime" || fp === "trigger_type" || fp === "env_var_key_count" || fp === "status") {
    const subject =
      fp === "runtime"          ? "runtime"
      : fp === "trigger_type"   ? "trigger type"
      : fp === "env_var_key_count" ? "environment variable key count"
      :                           "status";

    return _guidance({
      confidence: "medium",
      title:   "Review Firebase Function configuration drift",
      summary:
        `Confirm the Cloud Function ${subject} change was intentional and consistent with ` +
        `your deployment history.`,
      why_this_helps:
        "Cloud Function configuration drift can change execution behavior, trigger exposure, " +
        "or dependency on environment variables without a visible code change. An unexpected runtime " +
        "change may indicate an unplanned upgrade. An unexpected trigger type change may affect " +
        "how the function is invoked. Unexpected environment variable key count changes may " +
        "indicate secrets were added or removed outside of the normal deployment process.",
      verify_first: [
        "Confirm the function name and the deployment environment (production vs staging).",
        "Check recent deployment activity in your CI/CD pipeline or Google Cloud Console.",
        fp === "env_var_key_count"
          ? "Confirm environment variable key additions or removals were part of a planned deployment. (ConfigTrace does not read env var values — only the key count.)"
          : `Confirm the new ${subject} is expected for the current function version.`,
        "Confirm the change was not applied outside of your normal deployment pipeline.",
      ],
      manual_steps: [
        "Open the Google Cloud Console → Cloud Functions → [affected function].",
        "Review the function configuration and deployment history.",
        "Compare with your deployment pipeline configuration (e.g. firebase.json, Cloud Build config).",
        "Restore the intended configuration through your deployment pipeline if needed.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "ConfigTrace does not read environment variable values — only the count of configured keys.",
        "Configuration changes applied outside the deployment pipeline may not be reflected in version control.",
      ],
      docs_links: [
        { label: "Firebase Cloud Functions", url: "https://firebase.google.com/docs/functions" },
      ],
      provider_console_hint:
        "Firebase Console → [project] → Functions / Google Cloud Console → Cloud Functions.",
    });
  }

  return null;
}

// ── 3f. Firebase Storage buckets ──────────────────────────────────────────────

function _fbStorageBucketPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "firebase_storage_bucket") return null;
  if (!_isHighOrCritical(rl)) return null;

  // Uniform bucket-level access disabled — object ACLs now active
  if (fp === "uniform_bucket_level_access" && (nv === false || nv === "false")) {
    return _guidance({
      confidence: "high",
      title:   "Re-enable uniform bucket-level access",
      summary:
        "Re-enable uniform bucket-level access to prevent object-level ACLs from creating " +
        "unintended public access to individual storage objects.",
      why_this_helps:
        "Uniform bucket-level access ensures that all access to the bucket is controlled through " +
        "IAM policies only. When disabled, object-level ACLs become active — individual objects " +
        "can be made publicly accessible via ACLs, which may bypass Firebase Storage rules and " +
        "create unintended public exposure for files that were not intended to be public.",
      verify_first: [
        "Confirm who changed the uniform bucket-level access setting and why.",
        "Check whether any object-level ACLs were set while uniform access was disabled.",
        "Confirm whether any integration requires object-level ACLs (e.g. a legacy Google Cloud Storage workflow).",
        "Verify this is the production bucket, not a development or test bucket.",
      ],
      manual_steps: [
        "Open the Google Cloud Console → Cloud Storage → [affected bucket] → Permissions.",
        "Click 'Enable uniform bucket-level access'.",
        "Confirm no objects have public ACLs that should not be public.",
        "Save the configuration.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Confirm uniform bucket-level access shows as 'Enabled' in the Cloud Console.",
        "Test that Firebase Storage rules still work correctly after re-enabling.",
      ],
      caveats: [
        "Re-enabling uniform bucket-level access may remove existing object-level ACLs — review ACLs before making the change.",
        "Firebase Storage security rules are not affected by this setting — they operate independently.",
      ],
      docs_links: [
        { label: "Cloud Storage uniform bucket-level access", url: "https://cloud.google.com/storage/docs/uniform-bucket-level-access" },
      ],
      provider_console_hint:
        "Google Cloud Console → Cloud Storage → [bucket] → Permissions → Uniform access.",
    });
  }

  // Public access prevention changed away from enforced
  if (fp === "public_access_prevention") {
    return _guidance({
      confidence: "high",
      title:   "Verify Cloud Storage public access prevention change",
      summary:
        "Confirm that changing the public access prevention setting was intentional and " +
        "that the bucket does not now allow unintended public object access.",
      why_this_helps:
        "When public access prevention is set to 'enforced', it blocks all public access to the " +
        "bucket regardless of IAM policies or ACLs. Changing this to 'inherited' or 'unspecified' " +
        "re-enables the possibility of public access through IAM or ACL grants, which may expose " +
        "files that should not be publicly accessible.",
      verify_first: [
        "Confirm the public access prevention change was intentional.",
        "Review current IAM bindings and object ACLs to check for any allUsers or allAuthenticatedUsers grants.",
        "Confirm whether this bucket stores sensitive data or user uploads.",
      ],
      manual_steps: [
        "Open the Google Cloud Console → Cloud Storage → [affected bucket] → Permissions.",
        "Review public access prevention status.",
        "If the change was unintentional: restore 'Enforced' public access prevention.",
        "Review IAM bindings for allUsers grants and remove any that are not intentional.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Setting public access prevention to enforced will block intentional public access via allUsers — confirm no public serving use case exists first.",
      ],
      docs_links: [
        { label: "Cloud Storage public access prevention", url: "https://cloud.google.com/storage/docs/public-access-prevention" },
      ],
      provider_console_hint:
        "Google Cloud Console → Cloud Storage → [bucket] → Permissions → Public access prevention.",
    });
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Playbook 4 — Supabase (dispatcher)
// ─────────────────────────────────────────────────────────────────────────────

function _supabasePlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  return (
    _sbRlsPlaybooks(rt, fp, ct, rl, rr, nv)        ??
    _sbAuthPlaybooks(rt, fp, ct, rl, rr, nv)       ??
    _sbStoragePlaybooks(rt, fp, ct, rl, rr, nv)    ??
    _sbEdgeFnPlaybooks(rt, fp, ct, rl, rr, nv)     ??
    _sbNetworkPlaybooks(rt, fp, ct, rl, rr, nv)    ??
    _sbApiConfigPlaybooks(rt, fp, ct, rl, rr, nv)  ??
    null
  );
}

// ── 4a. Supabase RLS ──────────────────────────────────────────────────────────

function _sbRlsPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "supabase_rls_status") return null;

  // RLS disabled on a previously-enabled table — critical
  if (fp === "rls_enabled" && (nv === false || nv === "false")) {
    return _guidance({
      confidence: "high",
      title:   "Re-enable Supabase Row Level Security carefully",
      summary:
        "Re-enable RLS for the affected table after confirming correct policies exist " +
        "for all expected roles — do not re-enable without policies in place.",
      why_this_helps:
        "Row Level Security (RLS) is Supabase's primary data isolation mechanism. When RLS is " +
        "disabled on a table accessible via the public PostgREST API, any client with the anon key " +
        "(embedded in every client app) can read and write all rows regardless of their identity. " +
        "The anon key is not a secret — it is designed to be public, meaning a disabled RLS table " +
        "is effectively readable and writable by anyone who has your Supabase project URL.",
      verify_first: [
        "Confirm who disabled RLS and why — check the Supabase dashboard or audit log.",
        "Confirm whether the table is accessed from client code (subject to anon key exposure) or only from server-side code using the service role key.",
        "Confirm that at least one RLS policy exists per operation type (SELECT, INSERT, UPDATE, DELETE) for the roles that should access the table — re-enabling RLS without any policies blocks all client access.",
        "Confirm this is the production project, not a development or staging environment.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Authentication → Policies.",
        "Select the affected table and review existing policies.",
        "If policies are missing: create policies for each operation (SELECT, INSERT, UPDATE, DELETE) appropriate to the anon and authenticated roles.",
        "Once policies are confirmed correct: enable RLS by toggling the RLS switch on the table.",
        "Test that expected anon and authenticated queries still succeed.",
        "Test that cross-user queries are correctly rejected.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Test that anon/authenticated client queries behave as expected after RLS is re-enabled.",
        "Confirm unauthenticated clients cannot read rows they should not access.",
      ],
      caveats: [
        "Re-enabling RLS without any policies will block all PostgREST client access to the table — ensure at least one correct policy exists first.",
        "Service role keys bypass RLS by design — server-side code using the service role key is unaffected.",
        "Policies with incorrect USING expressions may inadvertently block legitimate access or expose more data than intended.",
      ],
      docs_links: [
        { label: "Supabase Row Level Security",  url: "https://supabase.com/docs/guides/database/postgres/row-level-security" },
        { label: "Supabase Auth and policies",   url: "https://supabase.com/docs/guides/auth" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Authentication → Policies → [table] → Enable RLS.",
    });
  }

  // RLS forced flag removed — table owner can now bypass RLS
  if (fp === "rls_forced" && (nv === false || nv === "false") && _isHighOrCritical(rl)) {
    return _guidance({
      confidence: "medium",
      title:   "Review removal of Supabase RLS forced flag",
      summary:
        "Confirm the RLS 'forced' flag removal was intentional — table owners can now " +
        "bypass Row Level Security on this table.",
      why_this_helps:
        "The RLS forced flag (FORCE ROW LEVEL SECURITY) extends RLS enforcement to table " +
        "owners. Without it, the table owner role can bypass all RLS policies. If service-role " +
        "connections share ownership of this table, removing forced RLS may allow broader " +
        "access than intended for certain query patterns.",
      verify_first: [
        "Confirm who removed the forced RLS flag and the reason.",
        "Identify which database roles own this table and whether they should be subject to RLS.",
        "Confirm whether the service role or admin connections need unrestricted access to this table.",
      ],
      manual_steps: [
        "Open the Supabase SQL editor.",
        "To re-enable: run ALTER TABLE [schema].[table] FORCE ROW LEVEL SECURITY;",
        "Test that table owner queries are correctly subject to RLS policies.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Forcing RLS on a table owner can break admin/maintenance queries that rely on owner-level unrestricted access.",
        "Test all query patterns (application and admin) after re-enabling forced RLS.",
      ],
      docs_links: [
        { label: "Supabase Row Level Security",  url: "https://supabase.com/docs/guides/database/postgres/row-level-security" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → SQL editor → ALTER TABLE … FORCE ROW LEVEL SECURITY.",
    });
  }

  // New table added without RLS — medium
  if (ct === "added" && fp === "rls_enabled" && (nv === false || nv === "false")) {
    return _guidance({
      confidence: "medium",
      title:   "Review new table without Row Level Security",
      summary:
        "Confirm the new table does not require RLS protection or enable RLS and add " +
        "appropriate policies before exposing the table to client queries.",
      why_this_helps:
        "A newly created table without RLS is accessible to any client with the anon key if " +
        "the table is in the PostgREST-exposed schema. Until RLS is enabled and policies are " +
        "defined, any authenticated client can read and modify all rows in the table.",
      verify_first: [
        "Confirm whether the table will be accessed from client-side code.",
        "Confirm the table's intended access model (who can read, write, update, delete).",
        "Confirm this is the production project.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Authentication → Policies.",
        "Select the new table and define policies for the required operation types.",
        "Enable RLS once policies are in place.",
        "Test expected client access patterns.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Enable RLS after policies are in place — enabling without policies blocks all client access.",
        "Tables only used by server-side code via service role may not require RLS, but confirm this is intentional.",
      ],
      docs_links: [
        { label: "Supabase Row Level Security",  url: "https://supabase.com/docs/guides/database/postgres/row-level-security" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Authentication → Policies → [table].",
    });
  }

  return null;
}

// ── 4b. Supabase Auth config ──────────────────────────────────────────────────

function _sbAuthPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "supabase_auth_config") return null;

  // Anonymous auth enabled — critical
  if (fp === "anonymous_enabled" && (nv === true || nv === "true")) {
    return _guidance({
      confidence: "high",
      title:   "Review Supabase anonymous authentication",
      summary:
        "Confirm anonymous sign-in is required and that RLS policies correctly restrict " +
        "what anonymous users can access.",
      why_this_helps:
        "Enabling anonymous authentication allows any internet user to obtain a valid Supabase " +
        "auth token without credentials. Anonymous users pass request.auth checks in RLS policies, " +
        "which may expose more data than intended if policies do not explicitly restrict the anon " +
        "role. Supabase anonymous users also consume MAU quota.",
      verify_first: [
        "Confirm the product intentionally supports anonymous or guest users.",
        "Review RLS policies on sensitive tables to confirm anonymous users are correctly restricted.",
        "Confirm anonymous accounts are upgraded or linked to permanent accounts when needed.",
        "Confirm this is the production project, not a development environment.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Authentication → Providers.",
        "Review Anonymous sign-ins status.",
        "If not required: disable anonymous sign-ins.",
        "If required: review RLS policies for all client-accessible tables to confirm anonymous users have only intended access.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Test anonymous sign-in behavior after any changes.",
        "Confirm anonymous users cannot access data they should not.",
      ],
      caveats: [
        "Disabling anonymous auth can break guest-session or onboarding flows that rely on it.",
        "Anonymous users with a valid token pass request.auth != null checks — policies must explicitly restrict the anon role if needed.",
      ],
      docs_links: [
        { label: "Supabase Anonymous Sign-ins", url: "https://supabase.com/docs/guides/auth/auth-anonymous" },
        { label: "Supabase Row Level Security",  url: "https://supabase.com/docs/guides/database/postgres/row-level-security" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Authentication → Providers → Anonymous.",
    });
  }

  // MFA disabled — high
  if (fp === "mfa_totp_enabled" && (nv === false || nv === "false") && _isHighOrCritical(rl)) {
    return _guidance({
      confidence: "high",
      title:   "Verify Supabase MFA was intentionally disabled",
      summary:
        "Confirm TOTP multi-factor authentication was intentionally disabled and that " +
        "alternative account security controls are in place.",
      why_this_helps:
        "TOTP MFA is a primary defence against account takeover via stolen or phished credentials. " +
        "Disabling MFA at the project level prevents users from enrolling in TOTP second factors, " +
        "reducing security for all user accounts — particularly admin and privileged users.",
      verify_first: [
        "Confirm who disabled MFA and the reason.",
        "Confirm whether any users currently have MFA enrolled and how this affects them.",
        "Confirm whether MFA is required for admin or high-privilege accounts.",
        "Confirm this is the production project.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Authentication → Sign In / MFA.",
        "Re-enable TOTP MFA if the change was unintentional.",
        "If disabling was intentional: confirm alternative account security controls are in place.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Re-enabling MFA does not automatically enroll existing users — it only allows new enrollments.",
      ],
      docs_links: [
        { label: "Supabase MFA", url: "https://supabase.com/docs/guides/auth/auth-mfa" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Authentication → Sign In → MFA.",
    });
  }

  // Leaked password protection disabled — high
  if (fp === "leaked_password_protection_enabled" && (nv === false || nv === "false")) {
    return _guidance({
      confidence: "high",
      title:   "Restore Supabase leaked password protection",
      summary:
        "Re-enable leaked password protection so users cannot set passwords that appear " +
        "in known data breach databases.",
      why_this_helps:
        "Supabase's leaked password protection checks new passwords against the Have I Been Pwned " +
        "database. When disabled, users may set passwords that are already present in breach " +
        "datasets and are actively used in credential-stuffing attacks, increasing the risk of " +
        "account compromise.",
      verify_first: [
        "Confirm the setting was intentionally disabled or changed accidentally.",
        "Confirm whether the change affects sign-up, password reset, or both flows.",
        "Confirm this is the production project.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Authentication → Security.",
        "Re-enable 'Prevent use of leaked passwords'.",
        "Save the setting.",
        "Test sign-up and password reset flows to confirm they still work correctly.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "This protection only applies to new password sets — existing accounts with weak passwords are not affected retroactively.",
      ],
      docs_links: [
        { label: "Supabase Auth security",        url: "https://supabase.com/docs/guides/auth/password-security" },
        { label: "Supabase going-to-prod guide",  url: "https://supabase.com/docs/guides/platform/going-into-prod" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Authentication → Security → Leaked password protection.",
    });
  }

  // Refresh token rotation disabled — medium
  if (fp === "refresh_token_rotation_enabled" && (nv === false || nv === "false")) {
    return _guidance({
      confidence: "high",
      title:   "Restore Supabase refresh token rotation",
      summary:
        "Re-enable refresh token rotation so stolen refresh tokens cannot be silently " +
        "reused without detection.",
      why_this_helps:
        "Refresh token rotation issues a new token pair on each use and invalidates the previous " +
        "refresh token. Without rotation, a stolen refresh token remains valid indefinitely — an " +
        "attacker who obtains a refresh token can maintain a persistent session even after the " +
        "legitimate user changes their password or signs out.",
      verify_first: [
        "Confirm the rotation was intentionally disabled or changed accidentally.",
        "Confirm whether any app code or integration relies on reusing the same refresh token across sessions.",
        "Confirm this is the production project.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Authentication → Sessions.",
        "Enable 'Refresh Token Rotation'.",
        "Save the setting.",
        "Test sign-in and session refresh flows to confirm they work correctly.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Test that session refresh works correctly after rotation is re-enabled.",
      ],
      caveats: [
        "Enabling token rotation invalidates existing long-lived refresh tokens — users with active sessions may need to re-authenticate.",
        "Confirm app clients handle 401/refresh-token-invalid errors gracefully.",
      ],
      docs_links: [
        { label: "Supabase Auth sessions",  url: "https://supabase.com/docs/guides/auth/sessions" },
        { label: "Supabase going-to-prod",  url: "https://supabase.com/docs/guides/platform/going-into-prod" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Authentication → Sessions → Refresh token rotation.",
    });
  }

  // CAPTCHA disabled — medium
  if (fp === "captcha_enabled" && (nv === false || nv === "false")) {
    return _guidance({
      confidence: "medium",
      title:   "Restore Supabase Auth CAPTCHA protection",
      summary:
        "Re-enable CAPTCHA on Auth endpoints to restore bot protection for sign-in " +
        "and sign-up flows.",
      why_this_helps:
        "CAPTCHA protection blocks automated scripts from submitting sign-in and sign-up requests " +
        "at scale. Without it, Auth endpoints may become more susceptible to credential stuffing, " +
        "brute-force attacks, and automated account creation.",
      verify_first: [
        "Confirm the setting was intentionally disabled or changed accidentally.",
        "Confirm whether the app's sign-in/sign-up UI is configured to send CAPTCHA tokens — re-enabling without client-side integration will block legitimate users.",
        "Confirm the CAPTCHA provider (hCaptcha or Turnstile) is correctly configured.",
        "Confirm this is the production project.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Authentication → Security.",
        "Re-enable CAPTCHA and select the provider (hCaptcha or Cloudflare Turnstile).",
        "Ensure the app's sign-in/sign-up forms send the CAPTCHA token in the request.",
        "Test sign-in and sign-up flows end-to-end.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Re-enabling CAPTCHA without updating client-side forms to submit CAPTCHA tokens will block all sign-in/sign-up attempts.",
        "CAPTCHA can affect UX and conversion — confirm the user experience is acceptable.",
      ],
      docs_links: [
        { label: "Supabase Auth CAPTCHA",  url: "https://supabase.com/docs/guides/auth/auth-captcha" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Authentication → Security → Enable CAPTCHA.",
    });
  }

  // Reauthentication for password update disabled — medium
  if (fp === "require_reauthentication_for_password_update" && (nv === false || nv === "false")) {
    return _guidance({
      confidence: "medium",
      title:   "Restore Supabase Auth reauthentication requirement",
      summary:
        "Re-enable the reauthentication requirement before users can change their password.",
      why_this_helps:
        "Requiring reauthentication before a password update means an attacker who hijacks " +
        "an active session cannot silently change the user's password to lock them out. Without " +
        "this requirement, an XSS or session hijack that obtains a live session token is " +
        "sufficient to take full control of the account.",
      verify_first: [
        "Confirm whether the change was intentional or accidental.",
        "Confirm whether app flows prompt users to reauthenticate before password changes.",
        "Confirm this is the production project.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Authentication → Security.",
        "Re-enable 'Require reauthentication before password update'.",
        "Test the password change flow to confirm users are prompted to reauthenticate.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Enabling this may require app changes if the UI does not currently prompt for reauthentication.",
      ],
      docs_links: [
        { label: "Supabase Auth security",  url: "https://supabase.com/docs/guides/auth/password-security" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Authentication → Security.",
    });
  }

  // JWT expiry increased — medium
  if (fp === "jwt_exp" && _isHighOrCritical(rl)) {
    return _guidance({
      confidence: "medium",
      title:   "Review longer Supabase JWT lifetime",
      summary:
        "Confirm the longer JWT access token lifetime is intentional and consistent " +
        "with your session security policy.",
      why_this_helps:
        "A longer JWT expiry means access tokens remain valid for a longer window after issuance. " +
        "If a JWT is obtained by an attacker — through XSS, a compromised client, or a network " +
        "intercept — a longer expiry gives the attacker more time to use the token before it expires. " +
        "Shorter access token lifetimes reduce this window, particularly when combined with refresh " +
        "token rotation.",
      verify_first: [
        "Confirm the new JWT expiry value and the previous value.",
        "Confirm the change was part of a planned auth configuration update.",
        "Confirm refresh token rotation is still enabled to reduce the risk of long-lived access.",
        "Confirm user experience requirements — a very short expiry may increase session-refresh churn.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Authentication → Sessions.",
        "Review the JWT Expiry setting.",
        "Restore the intended expiry if the change was accidental.",
        "Test sign-in and session refresh behavior after any changes.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Reducing JWT expiry too aggressively can cause frequent session refreshes and 401 errors in client apps.",
        "JWT expiry affects access tokens only — refresh token lifetime is controlled separately.",
      ],
      docs_links: [
        { label: "Supabase Auth sessions",  url: "https://supabase.com/docs/guides/auth/sessions" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Authentication → Sessions → JWT Expiry.",
    });
  }

  // Additional redirect URLs count increased — medium
  if (fp === "additional_redirect_urls_count" && _isHighOrCritical(rl)) {
    return _guidance({
      confidence: "medium",
      title:   "Review Supabase Auth redirect URLs",
      summary:
        "Confirm newly added redirect URLs belong to expected application domains and " +
        "remove any unexpected or untrusted redirect targets.",
      why_this_helps:
        "Supabase Auth redirect URLs control where users can be redirected after sign-in, " +
        "sign-out, email confirmation, and OAuth callbacks. An unexpected URL in this list " +
        "could enable open-redirect behavior — where an attacker crafts a sign-in link that " +
        "redirects users to a malicious domain after authenticating.",
      verify_first: [
        "Confirm which URLs were added and whether they belong to your application.",
        "Confirm the new URLs are expected app environments (production, staging, preview deploy).",
        "Confirm no temporary, test, or suspicious domains were added.",
        "Confirm this is the production project.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Authentication → URL Configuration.",
        "Review the Site URL and Additional Redirect URLs.",
        "Remove any URL that is not an expected application host.",
        "Restore any legitimate URLs that were accidentally removed.",
        "Test login, logout, and OAuth callback flows after changes.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Test sign-in and OAuth callback flows to confirm redirects work correctly.",
      ],
      caveats: [
        "Removing a URL that is actively used for auth redirects will break sign-in for that environment.",
        "ConfigTrace stores the count of redirect URLs, not the raw URLs — use the Supabase dashboard to inspect them.",
      ],
      docs_links: [
        { label: "Supabase Auth URL Configuration",  url: "https://supabase.com/docs/guides/auth/redirect-urls" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Authentication → URL Configuration.",
    });
  }

  return null;
}

// ── 4c. Supabase Storage ──────────────────────────────────────────────────────

function _sbStoragePlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "supabase_storage_config") return null;

  // File size limit removed or significantly increased
  if (fp === "file_size_limit" && (nv === null || nv === undefined || _isHighOrCritical(rl))) {
    return _guidance({
      confidence: nv === null || nv === undefined ? "high" : "medium",
      title:   "Review Supabase Storage file size limit",
      summary:
        nv === null || nv === undefined
          ? "Restore the storage file size limit to prevent users from uploading arbitrarily large files."
          : "Confirm the increased storage file size limit is intentional.",
      why_this_helps:
        "The global storage file size limit is the last-resort defence against excessive upload sizes " +
        "when bucket-level policies do not enforce size restrictions. Removing it or increasing it " +
        "significantly allows users to upload very large files, which can exhaust storage quota, " +
        "increase costs, and may be used for storage-abuse attacks.",
      verify_first: [
        "Confirm whether the change was intentional (e.g. supporting large media uploads for a new feature).",
        "Confirm whether bucket-level policies enforce size limits for specific buckets.",
        "Confirm this is the production project.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Storage → Settings.",
        "Review the global file size limit.",
        "Restore an appropriate limit if the change was accidental or overly permissive.",
        "Consider setting bucket-level size limits via Storage policies for fine-grained control.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "The global limit applies across all buckets — more specific per-bucket limits should be set via Storage policies.",
        "Reducing the limit does not affect files already uploaded.",
      ],
      docs_links: [
        { label: "Supabase Storage",  url: "https://supabase.com/docs/guides/storage" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Storage → Settings → File size limit.",
    });
  }

  // Allowed MIME types restriction removed
  if (fp === "allowed_mime_types" && (nv === null || nv === undefined || (Array.isArray(nv) && nv.length === 0))) {
    return _guidance({
      confidence: "medium",
      title:   "Review Supabase Storage MIME type restriction removal",
      summary:
        "Restore the MIME type allow-list to prevent users from uploading file types " +
        "that are not expected by the application.",
      why_this_helps:
        "The global MIME type allow-list restricts which file types can be uploaded to Supabase " +
        "Storage. Removing it allows any file type to be uploaded, including executables, scripts, " +
        "or archive formats that may be used in file-upload abuse or stored-content attacks.",
      verify_first: [
        "Confirm whether the MIME type restriction removal was intentional.",
        "Confirm which file types the application legitimately needs to accept.",
        "Confirm bucket-level policies still enforce file type restrictions if needed.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Storage → Settings.",
        "Review allowed MIME types and restore an appropriate list.",
        "Consider setting bucket-level MIME restrictions via Storage policies for per-bucket control.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Application-level file type validation should complement, not replace, storage-level MIME restrictions.",
      ],
      docs_links: [
        { label: "Supabase Storage",  url: "https://supabase.com/docs/guides/storage" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Storage → Settings → Allowed MIME types.",
    });
  }

  return null;
}

// ── 4d. Supabase Edge Functions ───────────────────────────────────────────────

function _sbEdgeFnPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "supabase_edge_function") return null;

  // JWT verification disabled — high
  if (fp === "verify_jwt" && (nv === false || nv === "false") && _isHighOrCritical(rl)) {
    return _guidance({
      confidence: "high",
      title:   "Restore Supabase Edge Function JWT verification",
      summary:
        "Re-enable JWT verification for this Edge Function to require callers to present " +
        "a valid Supabase JWT before the function executes.",
      why_this_helps:
        "JWT verification is the primary access control mechanism for Supabase Edge Functions. " +
        "When disabled, the function can be called by any HTTP client without authentication — " +
        "including unauthenticated requests from the public internet. This may be intentional for " +
        "public webhook endpoints, but for functions that process user data or perform sensitive " +
        "operations, disabling JWT verification removes the authentication requirement entirely.",
      verify_first: [
        "Confirm whether this function is intended to be publicly callable (e.g. a webhook receiver).",
        "Confirm whether the function performs any privileged operations or accesses user data.",
        "Confirm this is the production environment, not a development or testing function.",
        "Confirm whether the function implements its own auth logic instead of relying on JWT verification.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Edge Functions → [function name].",
        "Review the function settings and re-enable JWT verification if the function should require auth.",
        "If the function is a public webhook: confirm it implements request signature verification instead.",
        "Test the function with and without a valid JWT to confirm access control behaves as expected.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Test that unauthenticated requests are rejected when JWT verification is re-enabled.",
        "Test that authenticated requests with a valid Supabase JWT succeed.",
      ],
      caveats: [
        "Re-enabling JWT verification will block any service currently calling this function without a JWT.",
        "Public webhook endpoints (Stripe, GitHub, etc.) typically cannot send Supabase JWTs — for these, disable JWT verification and add request-signature verification instead.",
      ],
      docs_links: [
        { label: "Supabase Edge Functions",  url: "https://supabase.com/docs/guides/functions" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Edge Functions → [function] → Settings.",
    });
  }

  return null;
}

// ── 4e. Supabase network restrictions ────────────────────────────────────────

function _sbNetworkPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "supabase_network_restriction") return null;
  if (!_isHighOrCritical(rl) && ct !== "removed") return null;

  // Unrestricted access enabled or wildcard CIDR added
  const isUnrestricted =
    (fp === "is_unrestricted" && (nv === true || nv === "true")) ||
    (ct === "added" && (nv === true || nv === "true"));

  if (isUnrestricted) {
    return _guidance({
      confidence: "high",
      title:   "Restore Supabase database network restrictions",
      summary:
        "Re-enable network restrictions to limit direct database access to known IP " +
        "addresses or CIDR ranges.",
      why_this_helps:
        "Supabase network restrictions control which IP addresses can establish direct PostgreSQL " +
        "connections to the database (port 5432). When restrictions are removed, the database " +
        "connection port may be reachable from any IP address on the internet. While the database " +
        "still requires credentials, direct exposure increases the attack surface for credential " +
        "brute-force, connection exhaustion, and PostgreSQL protocol-level attacks.",
      verify_first: [
        "Confirm who removed the network restrictions and why.",
        "Identify which CIDR ranges or IP addresses should be allowed for direct DB access.",
        "Confirm whether any current services rely on direct database access from dynamic IPs (e.g. serverless functions).",
        "Confirm this is the production project.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Settings → Database → Network Restrictions.",
        "Add back the intended CIDR allow-list entries (static IPs, NAT gateway ranges, office CIDRs).",
        "Remove the wildcard/unrestricted entry if one was added.",
        "Save the network restrictions.",
        "Test that expected services can still connect to the database.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Confirm direct database connection attempts from unallowed IPs are rejected.",
        "Confirm services with whitelisted IPs can still connect.",
      ],
      caveats: [
        "Network restrictions apply to direct PostgreSQL connections only — connections via the Supabase API (PostgREST) and Edge Functions are unaffected.",
        "Dynamic-IP services (serverless, CI/CD) may need to use the connection pooler or a static IP egress solution.",
      ],
      docs_links: [
        { label: "Supabase network restrictions",  url: "https://supabase.com/docs/guides/platform/network-restrictions" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Settings → Database → Network Restrictions.",
    });
  }

  // Network restriction CIDR removed
  if (ct === "removed" && _isHighOrCritical(rl)) {
    return _guidance({
      confidence: "medium",
      title:   "Verify Supabase network restriction removal",
      summary:
        "Confirm the removed CIDR allow-list entry was intentional and that the database " +
        "is not now reachable from unexpected IP ranges.",
      why_this_helps:
        "Removing a CIDR from the network restrictions allow-list may mean a previously allowed " +
        "IP range can no longer connect, or — if all entries are removed — the database becomes " +
        "unrestricted. Verify that the removal was intentional and that no active services lost " +
        "direct database access.",
      verify_first: [
        "Identify which CIDR was removed from the allow-list.",
        "Confirm whether any service currently connects from IPs in that range.",
        "Confirm this was a planned decommission or IP range change.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Settings → Database → Network Restrictions.",
        "Review the current allow-list.",
        "Re-add the removed CIDR if it is still needed.",
        "Test that affected services can connect.",
      ],
      validation_steps: STANDARD_VALIDATION,
      caveats: [
        "Removing all CIDRs may leave the database unrestricted — confirm at least one entry covers expected connection sources.",
      ],
      docs_links: [
        { label: "Supabase network restrictions",  url: "https://supabase.com/docs/guides/platform/network-restrictions" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Settings → Database → Network Restrictions.",
    });
  }

  return null;
}

// ── 4f. Supabase PostgREST / API config ───────────────────────────────────────

function _sbApiConfigPlaybooks(
  rt: string, fp: string, ct: string,
  rl: string, rr: string, nv: unknown,
): RemediationGuidance | null {
  if (rt !== "supabase_api_config") return null;
  if (!_isHighOrCritical(rl)) return null;

  // Exposed schema changed — high risk
  if (fp === "db_schema") {
    return _guidance({
      confidence: "high",
      title:   "Verify Supabase PostgREST exposed schema change",
      summary:
        "Confirm the PostgREST exposed schema change was intentional and does not expose " +
        "unintended tables or data to the public API.",
      why_this_helps:
        "The PostgREST db_schema setting controls which database schemas are exposed through the " +
        "Supabase REST API. Changing this can add previously unexposed tables to the public API " +
        "surface, or remove tables from the API unexpectedly. Any table in the exposed schema that " +
        "lacks RLS protection may be accessible to anon or authenticated clients.",
      verify_first: [
        "Confirm the new schema value is expected and was changed intentionally.",
        "Identify all tables in the new schema and confirm their RLS status.",
        "Confirm no sensitive or internal tables are now newly exposed to the API.",
        "Confirm existing API consumers are not broken by the change.",
      ],
      manual_steps: [
        "Open the Supabase dashboard → [project] → Settings → API.",
        "Review the Exposed Schema setting.",
        "Restore the previous schema if the change was unintentional.",
        "If intentional: review all tables in the newly exposed schema and confirm RLS is enabled where required.",
      ],
      validation_steps: [
        ...STANDARD_VALIDATION,
        "Test API access for tables in the affected schema.",
        "Confirm RLS enforcement on newly exposed tables.",
      ],
      caveats: [
        "Tables in the exposed schema without RLS are accessible to any client with the anon key.",
        "Schema changes take effect after a Supabase configuration reload.",
      ],
      docs_links: [
        { label: "Supabase API settings",         url: "https://supabase.com/docs/guides/api" },
        { label: "Supabase Row Level Security",   url: "https://supabase.com/docs/guides/database/postgres/row-level-security" },
      ],
      provider_console_hint:
        "Supabase Dashboard → [project] → Settings → API → Exposed Schema.",
    });
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
