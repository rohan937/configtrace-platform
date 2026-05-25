/**
 * Timeline helpers — human-readable titles, descriptions, provider/category
 * labels for the security event feed on the Timeline page.
 *
 * Keeps all display-logic out of components and makes it unit-testable.
 */

import type { ChangeListItem } from "@/types";
import { getProviderMeta } from "@/lib/providers";
import { formatValue } from "@/lib/utils";

// ── Internal helpers ──────────────────────────────────────────────────────────

/** Lowercase known acronyms for field label formatting. */
const ACRONYMS = new Set([
  "rls", "mfa", "jwt", "api", "iam", "kms", "sts", "ssm", "rdp", "ssh",
  "vpc", "cdn", "url", "arn", "cidr", "acl", "cors", "waf", "s3", "ec2",
  "ecr", "ecs", "eks", "sns", "sqs", "kv", "ip", "id", "tls", "ssl",
]);

/**
 * Convert a snake_case field path to a readable label.
 * Uppercases known acronyms; title-cases everything else.
 * e.g. "last_used_service" → "Last Used Service"
 *      "rls_enabled"       → "RLS Enabled"
 *      "mfa_totp_enabled"  → "MFA TOTP Enabled"
 */
export function formatFieldLabel(fieldPath: string): string {
  return fieldPath
    .split("_")
    .map((w) =>
      ACRONYMS.has(w.toLowerCase())
        ? w.toUpperCase()
        : w.charAt(0).toUpperCase() + w.slice(1),
    )
    .join(" ");
}

/** Truncate a formatted value to keep descriptions compact. */
function shortVal(v: unknown): string {
  const s = formatValue(v);
  return s.length > 40 ? s.slice(0, 40) + "…" : s;
}

// ── Provider detection ────────────────────────────────────────────────────────

/**
 * Infer provider id from the record_type prefix in provider_metadata.
 * Cloudflare DNS record types ("A", "CNAME", etc.) have no underscore,
 * so anything unrecognised falls back to "cloudflare".
 */
export function getTimelineProvider(change: ChangeListItem): string {
  const rt = (
    (change.provider_metadata?.record_type as string | undefined) ?? ""
  ).toLowerCase();
  if (rt.startsWith("aws_"))      return "aws";
  if (rt.startsWith("github_"))   return "github";
  if (rt.startsWith("vercel_"))   return "vercel";
  if (rt.startsWith("stripe_"))   return "stripe";
  if (rt.startsWith("firebase_")) return "firebase";
  if (rt.startsWith("supabase_")) return "supabase";
  return "cloudflare";
}

// ── Category mapping ──────────────────────────────────────────────────────────

/**
 * Return a short category string for the metadata line, e.g. "IAM",
 * "Network", "Auth", "Storage".  Returns null when no specific category
 * applies (the provider label alone is sufficient).
 */
export function getTimelineCategory(change: ChangeListItem): string | null {
  const rt = (
    (change.provider_metadata?.record_type as string | undefined) ?? ""
  ).toLowerCase();

  // AWS
  if (rt.startsWith("aws_iam_"))                                    return "IAM";
  if (rt.startsWith("aws_s3_"))                                     return "Storage";
  if (rt === "aws_security_group" || rt === "aws_security_group_rule") return "Network";
  if (rt.startsWith("aws_vpc") || rt.startsWith("aws_subnet") ||
      rt.startsWith("aws_route") || rt === "aws_internet_gateway" ||
      rt.startsWith("aws_network_acl"))                             return "Network";
  if (rt.startsWith("aws_elbv2") || rt.startsWith("aws_elb_"))     return "Load Balancing";
  if (rt.startsWith("aws_lambda"))                                  return "Compute";
  if (rt.startsWith("aws_apigateway"))                              return "API Gateway";
  if (rt.startsWith("aws_rds"))                                     return "Database";
  if (rt.startsWith("aws_cloudtrail") || rt.startsWith("aws_guardduty") ||
      rt.startsWith("aws_securityhub"))                             return "Security";
  if (rt.startsWith("aws_kms"))                                     return "Encryption";
  if (rt.startsWith("aws_secretsmanager") || rt.startsWith("aws_ssm")) return "Secrets";
  if (rt.startsWith("aws_backup"))                                  return "Backup";
  if (rt.startsWith("aws_organizations"))                           return "Organizations";
  if (rt.startsWith("aws_cloudwatch"))                              return "Monitoring";
  if (rt.startsWith("aws_ecs") || rt.startsWith("aws_eks") ||
      rt.startsWith("aws_ecr"))                                     return "Containers";
  if (rt.startsWith("aws_eventbridge") || rt.startsWith("aws_sqs") ||
      rt.startsWith("aws_sns"))                                     return "Messaging";
  if (rt.startsWith("aws_wafv2"))                                   return "WAF";
  if (rt.startsWith("aws_cloudfront"))                              return "CDN";
  if (rt.startsWith("aws_route53"))                                 return "DNS";
  if (rt === "aws_account_identity" || rt === "aws_region" ||
      rt === "aws_service_inventory")                               return "Account";

  // GitHub
  if (rt === "github_actions_secret" || rt === "github_deploy_key") return "CI/CD";
  if (rt === "github_branch_protection")                            return "Branch Policy";
  if (rt === "github_repo_settings")                                return "Repo Settings";
  if (rt === "github_webhook")                                      return "Webhooks";

  // Vercel
  if (rt === "vercel_env_var")                                      return "Config";
  if (rt === "vercel_domain")                                       return "Domains";

  // Stripe
  if (rt.startsWith("stripe_payment"))                              return "Payments";
  if (rt === "stripe_webhook_endpoint")                             return "Webhooks";

  // Firebase
  if (rt.startsWith("firebase_auth"))                               return "Auth";
  if (rt.startsWith("firebase_firestore"))                          return "Database";
  if (rt.startsWith("firebase_storage"))                            return "Storage";
  if (rt.startsWith("firebase_hosting"))                            return "Hosting";
  if (rt.startsWith("firebase_function"))                           return "Functions";

  // Supabase
  if (rt.startsWith("supabase_auth") || rt === "supabase_oauth_provider") return "Auth";
  if (rt.startsWith("supabase_database") || rt === "supabase_rls_status" ||
      rt === "supabase_api_config")                                 return "Database";
  if (rt.startsWith("supabase_storage"))                            return "Storage";
  if (rt === "supabase_edge_function")                              return "Functions";
  if (rt === "supabase_network_restriction")                        return "Network";

  // Cloudflare DNS record types ("A", "CNAME", "MX", …)
  if (rt && !rt.includes("_"))                                      return "DNS";

  return null;
}

// ── Event title ───────────────────────────────────────────────────────────────

/**
 * Return a concise human-readable title for a change event.
 * Format: "{Provider} {surface} {verb}" — e.g. "AWS IAM access key changed".
 */
export function getTimelineEventTitle(change: ChangeListItem): string {
  const rt = (
    (change.provider_metadata?.record_type as string | undefined) ?? ""
  ).toLowerCase();
  const ct = change.change_type;

  // ── AWS ──────────────────────────────────────────────────────────────
  if (rt === "aws_iam_account_summary")   return "AWS IAM account posture changed";
  if (rt === "aws_iam_user")              return ct === "added" ? "AWS IAM user created" : ct === "removed" ? "AWS IAM user removed" : "AWS IAM user settings changed";
  if (rt === "aws_iam_access_key")        return "AWS IAM access key changed";
  if (rt === "aws_iam_role")              return ct === "added" ? "AWS IAM role created" : ct === "removed" ? "AWS IAM role deleted" : "AWS IAM role changed";
  if (rt === "aws_iam_policy")            return ct === "added" ? "AWS IAM policy created" : ct === "removed" ? "AWS IAM policy deleted" : "AWS IAM policy changed";
  if (rt === "aws_iam_policy_attachment") return ct === "added" ? "AWS IAM policy attached" : ct === "removed" ? "AWS IAM policy detached" : "AWS IAM policy attachment changed";
  if (rt === "aws_iam_inline_policy")     return ct === "added" ? "AWS IAM inline policy added" : ct === "removed" ? "AWS IAM inline policy removed" : "AWS IAM inline policy changed";
  if (rt === "aws_iam_group")             return ct === "added" ? "AWS IAM group created" : ct === "removed" ? "AWS IAM group deleted" : "AWS IAM group changed";
  if (rt === "aws_iam_identity_provider") return ct === "added" ? "AWS IAM identity provider added" : ct === "removed" ? "AWS IAM identity provider removed" : "AWS IAM identity provider changed";
  if (rt === "aws_account_identity")      return "AWS account identity changed";
  if (rt === "aws_region")                return ct === "added" ? "AWS region added to monitoring" : ct === "removed" ? "AWS region removed from monitoring" : "AWS region changed";
  if (rt === "aws_service_inventory")     return "AWS service inventory updated";
  if (rt === "aws_s3_bucket")             return ct === "added" ? "AWS S3 bucket detected" : ct === "removed" ? "AWS S3 bucket removed" : "AWS S3 bucket configuration changed";
  if (rt === "aws_security_group")        return ct === "added" ? "AWS security group added" : ct === "removed" ? "AWS security group removed" : "AWS security group changed";
  if (rt === "aws_security_group_rule")   return ct === "added" ? "AWS security group rule added" : ct === "removed" ? "AWS security group rule removed" : "AWS security group rule changed";
  if (rt === "aws_vpc")                   return ct === "added" ? "AWS VPC added" : ct === "removed" ? "AWS VPC removed" : "AWS VPC changed";
  if (rt === "aws_subnet")                return ct === "added" ? "AWS subnet added" : ct === "removed" ? "AWS subnet removed" : "AWS subnet changed";
  if (rt === "aws_route_table")           return "AWS route table changed";
  if (rt === "aws_internet_gateway")      return ct === "added" ? "AWS internet gateway added" : ct === "removed" ? "AWS internet gateway removed" : "AWS internet gateway changed";
  if (rt === "aws_network_acl")           return "AWS network ACL changed";
  if (rt === "aws_lambda_function")       return ct === "added" ? "AWS Lambda function added" : ct === "removed" ? "AWS Lambda function removed" : "AWS Lambda function changed";
  if (rt === "aws_lambda_alias")          return ct === "added" ? "AWS Lambda alias added" : ct === "removed" ? "AWS Lambda alias removed" : "AWS Lambda alias changed";
  if (rt === "aws_lambda_function_url")   return ct === "added" ? "AWS Lambda function URL added" : ct === "removed" ? "AWS Lambda function URL removed" : "AWS Lambda function URL changed";
  if (rt === "aws_lambda_event_source_mapping") return "AWS Lambda event source mapping changed";
  if (rt === "aws_rds_db_instance")       return ct === "added" ? "AWS RDS instance added" : ct === "removed" ? "AWS RDS instance removed" : "AWS RDS instance changed";
  if (rt === "aws_rds_db_cluster")        return ct === "added" ? "AWS RDS cluster added" : ct === "removed" ? "AWS RDS cluster removed" : "AWS RDS cluster changed";
  if (rt.startsWith("aws_rds_"))          return "AWS RDS configuration changed";
  if (rt === "aws_kms_key")               return ct === "added" ? "AWS KMS key created" : ct === "removed" ? "AWS KMS key removed" : "AWS KMS key changed";
  if (rt === "aws_kms_alias")             return ct === "added" ? "AWS KMS alias created" : ct === "removed" ? "AWS KMS alias removed" : "AWS KMS alias changed";
  if (rt === "aws_secretsmanager_secret") return ct === "added" ? "AWS secret added" : ct === "removed" ? "AWS secret removed" : "AWS secret changed";
  if (rt === "aws_ssm_parameter")         return ct === "added" ? "AWS SSM parameter added" : ct === "removed" ? "AWS SSM parameter removed" : "AWS SSM parameter changed";
  if (rt === "aws_cloudtrail_trail")      return ct === "added" ? "AWS CloudTrail trail added" : ct === "removed" ? "AWS CloudTrail trail removed" : "AWS CloudTrail trail changed";
  if (rt === "aws_cloudtrail_event_data_store") return "AWS CloudTrail event data store changed";
  if (rt === "aws_guardduty_detector")    return ct === "added" ? "AWS GuardDuty detector added" : ct === "removed" ? "AWS GuardDuty detector removed" : "AWS GuardDuty detector changed";
  if (rt.startsWith("aws_guardduty_"))    return "AWS GuardDuty configuration changed";
  if (rt === "aws_securityhub_account")   return "AWS Security Hub account changed";
  if (rt.startsWith("aws_securityhub_"))  return "AWS Security Hub configuration changed";
  if (rt.startsWith("aws_ecs_"))          return ct === "added" ? `AWS ECS ${rt.replace("aws_ecs_", "")} added` : ct === "removed" ? `AWS ECS ${rt.replace("aws_ecs_", "")} removed` : `AWS ECS ${rt.replace("aws_ecs_", "")} changed`;
  if (rt.startsWith("aws_eks_"))          return ct === "added" ? `AWS EKS ${rt.replace("aws_eks_", "")} added` : ct === "removed" ? `AWS EKS ${rt.replace("aws_eks_", "")} removed` : `AWS EKS ${rt.replace("aws_eks_", "")} changed`;
  if (rt.startsWith("aws_ecr_"))          return "AWS ECR configuration changed";
  if (rt.startsWith("aws_elbv2_"))        return "AWS load balancer configuration changed";
  if (rt === "aws_elb_classic_load_balancer") return "AWS Classic load balancer changed";
  if (rt.startsWith("aws_apigateway"))    return "AWS API Gateway configuration changed";
  if (rt === "aws_cloudfront_distribution") return ct === "added" ? "AWS CloudFront distribution added" : ct === "removed" ? "AWS CloudFront distribution removed" : "AWS CloudFront distribution changed";
  if (rt === "aws_wafv2_web_acl")         return ct === "added" ? "AWS WAF Web ACL added" : ct === "removed" ? "AWS WAF Web ACL removed" : "AWS WAF Web ACL changed";
  if (rt.startsWith("aws_wafv2_"))        return "AWS WAF configuration changed";
  if (rt.startsWith("aws_eventbridge_"))  return "AWS EventBridge configuration changed";
  if (rt.startsWith("aws_sqs_"))          return ct === "added" ? "AWS SQS queue added" : ct === "removed" ? "AWS SQS queue removed" : "AWS SQS queue changed";
  if (rt.startsWith("aws_sns_"))          return "AWS SNS configuration changed";
  if (rt.startsWith("aws_backup_"))       return "AWS Backup configuration changed";
  if (rt.startsWith("aws_organizations_")) return "AWS Organizations configuration changed";
  if (rt.startsWith("aws_cloudwatch_"))   return "AWS CloudWatch configuration changed";
  if (rt.startsWith("aws_route53_"))      return "AWS Route 53 configuration changed";

  // ── GitHub ────────────────────────────────────────────────────────────
  if (rt === "github_repo_settings")      return "GitHub repository settings changed";
  if (rt === "github_branch_protection")  return ct === "added" ? "GitHub branch protection added" : ct === "removed" ? "GitHub branch protection removed" : "GitHub branch protection changed";
  if (rt === "github_actions_secret")     return ct === "added" ? "GitHub Actions secret added" : ct === "removed" ? "GitHub Actions secret removed" : "GitHub Actions secret rotated";
  if (rt === "github_webhook")            return ct === "added" ? "GitHub webhook added" : ct === "removed" ? "GitHub webhook removed" : "GitHub webhook changed";
  if (rt === "github_deploy_key")         return ct === "added" ? "GitHub deploy key added" : ct === "removed" ? "GitHub deploy key removed" : "GitHub deploy key changed";

  // ── Vercel ────────────────────────────────────────────────────────────
  if (rt === "vercel_project")            return "Vercel project settings changed";
  if (rt === "vercel_env_var")            return ct === "added" ? "Vercel environment variable added" : ct === "removed" ? "Vercel environment variable removed" : "Vercel environment variable changed";
  if (rt === "vercel_domain")             return ct === "added" ? "Vercel domain added" : ct === "removed" ? "Vercel domain removed" : "Vercel domain changed";

  // ── Stripe ────────────────────────────────────────────────────────────
  if (rt === "stripe_account_settings")   return "Stripe account settings changed";
  if (rt === "stripe_webhook_endpoint")   return ct === "added" ? "Stripe webhook endpoint added" : ct === "removed" ? "Stripe webhook endpoint removed" : "Stripe webhook endpoint changed";
  if (rt.startsWith("stripe_payment_"))   return "Stripe payment configuration changed";

  // ── Firebase ──────────────────────────────────────────────────────────
  if (rt === "firebase_project")          return ct === "added" ? "Firebase project connected" : "Firebase project settings changed";
  if (rt === "firebase_auth_config")      return "Firebase Auth settings changed";
  if (rt === "firebase_auth_provider")    return ct === "added" ? "Firebase Auth provider enabled" : ct === "removed" ? "Firebase Auth provider disabled" : "Firebase Auth provider changed";
  if (rt === "firebase_authorized_domain") return ct === "added" ? "Firebase authorized domain added" : ct === "removed" ? "Firebase authorized domain removed" : "Firebase authorized domain changed";
  if (rt === "firebase_firestore_ruleset") return ct === "added" ? "Firestore security ruleset deployed" : "Firestore security ruleset changed";
  if (rt === "firebase_storage_bucket")   return ct === "added" ? "Firebase Storage bucket added" : ct === "removed" ? "Firebase Storage bucket removed" : "Firebase Storage bucket changed";
  if (rt === "firebase_storage_ruleset")  return ct === "added" ? "Firebase Storage rules deployed" : "Firebase Storage rules changed";
  if (rt === "firebase_hosting_site")     return ct === "added" ? "Firebase Hosting site added" : ct === "removed" ? "Firebase Hosting site removed" : "Firebase Hosting site changed";
  if (rt === "firebase_hosting_domain")   return ct === "added" ? "Firebase Hosting domain added" : ct === "removed" ? "Firebase Hosting domain removed" : "Firebase Hosting domain changed";
  if (rt === "firebase_function_metadata") return ct === "added" ? "Firebase Cloud Function deployed" : ct === "removed" ? "Firebase Cloud Function deleted" : "Firebase Cloud Function changed";

  // ── Supabase ──────────────────────────────────────────────────────────
  if (rt === "supabase_project")          return ct === "added" ? "Supabase project connected" : "Supabase project settings changed";
  if (rt === "supabase_auth_config")      return "Supabase Auth settings changed";
  if (rt === "supabase_oauth_provider")   return ct === "added" ? "Supabase OAuth provider enabled" : ct === "removed" ? "Supabase OAuth provider disabled" : "Supabase OAuth provider changed";
  if (rt === "supabase_rls_status")       return "Supabase table RLS status changed";
  if (rt === "supabase_network_restriction") return ct === "added" ? "Supabase network restriction added" : ct === "removed" ? "Supabase network restriction removed" : "Supabase network restriction changed";
  if (rt === "supabase_edge_function")    return ct === "added" ? "Supabase Edge Function deployed" : ct === "removed" ? "Supabase Edge Function removed" : "Supabase Edge Function changed";
  if (rt === "supabase_database_config")  return "Supabase database config changed";
  if (rt === "supabase_storage_config")   return "Supabase Storage config changed";
  if (rt === "supabase_api_config")       return "Supabase API config changed";
  if (rt === "supabase_custom_domain")    return ct === "added" ? "Supabase custom domain configured" : ct === "removed" ? "Supabase custom domain removed" : "Supabase custom domain changed";

  // ── Cloudflare DNS ────────────────────────────────────────────────────
  // record_type for Cloudflare DNS is e.g. "A", "CNAME", "MX" — no underscore
  if (rt && !rt.includes("_")) {
    const dnsType = rt.toUpperCase();
    return ct === "added"
      ? `Cloudflare ${dnsType} record added`
      : ct === "removed"
        ? `Cloudflare ${dnsType} record removed`
        : `Cloudflare ${dnsType} record changed`;
  }

  // ── Generic fallback ──────────────────────────────────────────────────
  if (rt) {
    const provider = getTimelineProvider(change);
    const provLabel = getProviderMeta(provider).shortLabel;
    // Strip the known provider prefix from the record_type
    const knownPrefixes = ["aws_", "github_", "vercel_", "stripe_", "firebase_", "supabase_"];
    let rest = rt;
    for (const pfx of knownPrefixes) {
      if (rt.startsWith(pfx)) { rest = rt.slice(pfx.length); break; }
    }
    const readableType = rest.split("_").join(" ");
    const ctLabel = ct === "added" ? "added" : ct === "removed" ? "removed" : "changed";
    return `${provLabel} ${readableType} ${ctLabel}`;
  }

  // Final fallback
  return ct === "added" ? "Configuration added" : ct === "removed" ? "Configuration removed" : "Configuration changed";
}

// ── Event description ─────────────────────────────────────────────────────────

/**
 * Return a concise human-readable description for a change event.
 * Returns null when the title alone is sufficient.
 *
 * Priority:
 * 1. risk_reason (for high/critical — usually the best contextual note)
 * 2. "Field changed from X to Y." for modified + readable scalar values
 * 3. null
 */
export function getTimelineEventDescription(change: ChangeListItem): string | null {
  const fp = change.field_path;
  const pv = change.prev_value;
  const nv = change.new_value;

  // For high/critical, risk_reason is almost always the most useful line
  const rl = (change.risk_level ?? "").toLowerCase();
  if ((rl === "critical" || rl === "high") && change.risk_reason) {
    return change.risk_reason;
  }

  // For modified changes with a field path and readable scalar values, show the diff
  if (change.change_type === "modified" && fp) {
    const pvStr = shortVal(pv);
    const nvStr = shortVal(nv);
    if (pvStr !== "—" && nvStr !== "—" && pvStr !== nvStr) {
      return `${formatFieldLabel(fp)} changed from ${pvStr} to ${nvStr}.`;
    }
    if (nvStr !== "—") {
      return `${formatFieldLabel(fp)} changed to ${nvStr}.`;
    }
    // Fall back to field name only
    return `${formatFieldLabel(fp)} changed.`;
  }

  // For medium changes with a risk_reason, still surface it
  if (rl === "medium" && change.risk_reason) {
    return change.risk_reason;
  }

  return null;
}

// ── Bundled helper ────────────────────────────────────────────────────────────

export interface TimelineEventData {
  title: string;
  description: string | null;
  provider: string;
  providerLabel: string;
  category: string | null;
}

/** One-stop helper that bundles all display data for a timeline row. */
export function getTimelineEventData(change: ChangeListItem): TimelineEventData {
  const provider = getTimelineProvider(change);
  return {
    title:         getTimelineEventTitle(change),
    description:   getTimelineEventDescription(change),
    provider,
    providerLabel: getProviderMeta(provider).shortLabel,
    category:      getTimelineCategory(change),
  };
}

// ── Risk count summary ────────────────────────────────────────────────────────

export interface RiskCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  total: number;
}

/** Tally risk levels across a set of loaded changes. */
export function computeRiskCounts(changes: ChangeListItem[]): RiskCounts {
  const counts: RiskCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: changes.length };
  for (const c of changes) {
    const k = (c.risk_level ?? "unknown").toLowerCase() as keyof Omit<RiskCounts, "total">;
    if (k in counts) counts[k]++;
    else counts.unknown++;
  }
  return counts;
}
