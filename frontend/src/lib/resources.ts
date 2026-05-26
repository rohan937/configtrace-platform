/**
 * Resource-specific helpers: provider inference, category labels,
 * and human-readable type strings.
 *
 * Keeps display logic out of components and centralises the
 * resource-type → provider mapping so it is consistent across
 * ResourceList, the resource detail page, and any future surfaces.
 */

import type { ProviderId, ProviderMeta } from "@/lib/providers";
import { getProviderMeta } from "@/lib/providers";

// ── Provider inference ────────────────────────────────────────────────────────

/**
 * Infer the provider for a resource from its `provider_resource_type` string.
 *
 * Prefix rules (same convention as the backend connectors):
 *   aws_*        → aws
 *   firebase_*   → firebase
 *   supabase_*   → supabase
 *   stripe_*     → stripe
 *   github_*     → github
 *   vercel_*     → vercel
 *   cloudflare_* → cloudflare
 *
 * Fallback: cloudflare — handles bare DNS record type names ("A", "CNAME", …)
 * stored by the Cloudflare connector.
 */
export function getResourceProvider(resourceType: string): ProviderId {
  const t = resourceType.toLowerCase();
  if (t.startsWith("aws_"))        return "aws";
  if (t.startsWith("firebase_"))   return "firebase";
  if (t.startsWith("supabase_"))   return "supabase";
  if (t.startsWith("stripe_"))     return "stripe";
  if (t.startsWith("github_"))     return "github";
  if (t.startsWith("vercel_"))     return "vercel";
  if (t.startsWith("cloudflare_")) return "cloudflare";
  if (t.startsWith("shopify_"))   return "shopify";
  return "cloudflare";
}

/** Convenience: ProviderMeta for a resource type. */
export function getResourceProviderMeta(resourceType: string): ProviderMeta {
  return getProviderMeta(getResourceProvider(resourceType));
}

// ── Category labels ───────────────────────────────────────────────────────────

/**
 * Short category label for a resource type, shown as a secondary chip.
 * Returns null when no meaningful category applies (e.g. a root "account" resource).
 *
 * Examples:
 *   aws_iam_user           → "IAM"
 *   aws_security_group     → "Network"
 *   firebase_auth_config   → "Auth"
 *   firebase_firestore_ruleset → "Database"
 *   supabase_database_table → "Database"
 *   github_branch_protection → "Security"
 *   cloudflare_dns_record  → "DNS"
 */
export function getResourceCategory(resourceType: string): string | null {
  const t = resourceType.toLowerCase();

  // ── AWS ───────────────────────────────────────────────────────────────────
  if (t.startsWith("aws_iam"))         return "IAM";
  if (t.startsWith("aws_s3"))          return "Storage";
  if (t === "aws_security_group")      return "Network";
  if (t.startsWith("aws_vpc"))         return "Network";
  if (t.startsWith("aws_rds"))         return "Database";
  if (t.startsWith("aws_lambda"))      return "Compute";
  if (t.startsWith("aws_ec2"))         return "Compute";
  if (t.startsWith("aws_eks"))         return "Compute";
  if (t.startsWith("aws_ecs"))         return "Compute";
  if (t.startsWith("aws_ecr"))         return "Containers";
  if (t.startsWith("aws_kms"))         return "Security";
  if (t.startsWith("aws_secrets"))     return "Secrets";
  if (t.startsWith("aws_cloudtrail"))  return "Audit";
  if (t.startsWith("aws_guardduty"))   return "Security";
  if (t.startsWith("aws_config"))      return "Audit";
  if (t.startsWith("aws_route53"))     return "DNS";
  if (t.startsWith("aws_sns"))         return "Messaging";
  if (t.startsWith("aws_sqs"))         return "Messaging";
  if (t.startsWith("aws_api_gateway")) return "API";
  if (t.startsWith("aws_cloudwatch"))  return "Monitoring";
  if (t.startsWith("aws_cloudfront")) return "CDN";
  if (t.startsWith("aws_wafv2"))      return "Security";
  if (t.startsWith("aws_elb") || t.startsWith("aws_elbv2")) return "Network";

  // ── Firebase — more specific checks first ─────────────────────────────────
  if (t === "firebase_remote_config_template") return "App Config";
  if (t === "firebase_app_check_config")       return "App Security";
  if (t.includes("firestore"))         return "Database";
  if (t.includes("auth"))              return "Auth";
  if (t.includes("storage"))           return "Storage";
  if (t.includes("hosting"))           return "Hosting";
  if (t.includes("function"))          return "Functions";

  // ── Supabase ──────────────────────────────────────────────────────────────
  if (t.includes("database"))          return "Database";
  if (t.includes("pooler"))            return "Database";
  if (t.includes("edge_function"))     return "Functions";
  if (t.includes("network"))           return "Network";
  if (t.includes("custom_domain"))     return "Domains";

  // ── GitHub ────────────────────────────────────────────────────────────────
  if (t === "github_environment_protection") return "Deployment Security";
  if (t.includes("branch_protection")) return "Security";
  if (t.includes("secret"))            return "Secrets";
  if (t.includes("deploy_key"))        return "Security";
  if (t.includes("webhook"))           return "Webhooks";

  // ── Cloudflare ────────────────────────────────────────────────────────────
  if (t === "cloudflare_ruleset")      return "Security";
  if (t.includes("firewall"))          return "Security";
  if (t.includes("dns"))               return "DNS";
  if (t.includes("page_rule"))         return "Rules";
  if (t.includes("ssl"))               return "Security";
  if (t.includes("zone_setting"))      return "Settings";

  // ── Vercel ────────────────────────────────────────────────────────────────
  if (t === "vercel_deploy_hook_metadata") return "Deployment";
  if (t.includes("domain"))            return "Domains";
  if (t.includes("env"))               return "Config";

  // ── Stripe ────────────────────────────────────────────────────────────────
  if (t === "stripe_billing_portal_config")  return "Billing";
  if (t.includes("payment"))           return "Payments";
  // Note: webhook intentionally checked after GitHub to avoid false positives
  if (t.startsWith("stripe_webhook"))  return "Webhooks";

  // ── Shopify ───────────────────────────────────────────────────────────────
  if (t === "shopify_shop_metadata")          return "Settings";
  if (t === "shopify_webhook_subscription")   return "Webhooks";
  if (t === "shopify_store_policy")           return "Policies";
  if (t === "shopify_app_scope_summary")      return "Commerce Security";
  if (t.startsWith("shopify_"))               return "Commerce";

  return null;
}

// ── Type labels ───────────────────────────────────────────────────────────────

/** Explicit resource-type → short label map.
 *  The provider name is NOT repeated — the provider is shown separately. */
const TYPE_LABELS: Record<string, string> = {
  // ── Cloudflare ─────────────────────────────────────────────────────────
  cloudflare_dns_zone:           "DNS zone",
  cloudflare_dns_record:         "DNS record",
  cloudflare_firewall_rule:      "Firewall rule",
  cloudflare_page_rule:          "Page rule",
  cloudflare_ssl_setting:        "SSL setting",
  cloudflare_zone_setting:       "Zone setting",
  cloudflare_ruleset:            "WAF ruleset",

  // ── GitHub ────────────────────────────────────────────────────────────
  github_repo:                   "Repository",
  github_branch_protection:      "Branch protection",
  github_webhook:                "Webhook",
  github_secret:                 "Actions secret",
  github_deploy_key:             "Deploy key",
  github_environment_protection: "Environment protection",

  // ── Vercel ────────────────────────────────────────────────────────────
  vercel_project:                "Project",
  vercel_domain:                 "Domain",
  vercel_env_variable:           "Environment variable",
  vercel_deploy_hook_metadata:   "Deploy hook",

  // ── Stripe ────────────────────────────────────────────────────────────
  stripe_account:                "Account",
  stripe_webhook_endpoint:       "Webhook endpoint",
  stripe_payment_method:         "Payment method",
  stripe_payment_method_domain:  "Payment domain",
  stripe_product:                "Product",
  stripe_billing_portal_config:  "Billing portal config",

  // ── AWS ──────────────────────────────────────────────────────────────
  aws_account:                   "Account",
  aws_iam_user:                  "IAM user",
  aws_iam_role:                  "IAM role",
  aws_iam_policy:                "IAM policy",
  aws_iam_group:                 "IAM group",
  aws_iam_access_key:            "IAM access key",
  aws_s3_bucket:                 "S3 bucket",
  aws_security_group:            "Security group",
  aws_vpc:                       "VPC",
  aws_ec2_instance:              "EC2 instance",
  aws_lambda_function:           "Lambda function",
  aws_rds_instance:              "RDS instance",
  aws_rds_cluster:               "RDS cluster",
  aws_cloudtrail:                "CloudTrail",
  aws_cloudtrail_trail:          "CloudTrail trail",
  aws_cloudfront_distribution:   "CloudFront distribution",
  aws_wafv2_web_acl:             "WAFv2 Web ACL",
  aws_wafv2_web_acl_association: "WAFv2 ACL association",
  aws_guardduty_detector:        "GuardDuty detector",
  aws_kms_key:                   "KMS key",
  aws_secrets_manager_secret:    "Secrets Manager secret",
  aws_route53_record:            "Route53 DNS record",
  aws_route53_hosted_zone:       "Route53 hosted zone",
  aws_ecr_repository:            "ECR repository",
  aws_ecs_service:               "ECS service",
  aws_ecs_cluster:               "ECS cluster",
  aws_eks_cluster:               "EKS cluster",
  aws_sns_topic:                 "SNS topic",
  aws_sqs_queue:                 "SQS queue",
  aws_api_gateway_rest_api:      "API Gateway",
  aws_cloudwatch_alarm:          "CloudWatch alarm",
  aws_config_rule:               "Config rule",

  // ── Firebase ──────────────────────────────────────────────────────────
  firebase_project:              "Project",
  firebase_auth_config:          "Auth configuration",
  firebase_auth_provider:        "Auth provider",
  firebase_authorized_domain:    "Authorized domain",
  firebase_firestore_ruleset:    "Firestore ruleset",
  firebase_storage_bucket:       "Storage bucket",
  firebase_storage_ruleset:      "Storage ruleset",
  firebase_hosting_site:         "Hosting site",
  firebase_hosting_domain:       "Hosting domain",
  firebase_cloud_function:       "Cloud Function",
  firebase_remote_config_template: "Remote Config template",
  firebase_app_check_config:     "App Check config",

  // ── Supabase ──────────────────────────────────────────────────────────
  supabase_project:              "Project",
  supabase_auth_config:          "Auth configuration",
  supabase_auth_provider:        "Auth provider",
  supabase_database_table:       "Database table",
  supabase_database_policy:      "Database policy",
  supabase_storage_bucket:       "Storage bucket",
  supabase_edge_function:        "Edge Function",
  supabase_network_restriction:  "Network restriction",
  supabase_pooler_config:        "Database pooler",
  supabase_custom_domain:        "Custom domain",

  // ── Shopify ────────────────────────────────────────────────────────────
  shopify_shop_metadata:         "Shop settings",
  shopify_webhook_subscription:  "Webhook subscription",
  shopify_store_policy:          "Store policy",
  shopify_app_scope_summary:     "App scopes",
};

/**
 * Convert a `provider_resource_type` to a short, human-readable label.
 *
 * The provider name is NOT repeated in the output — it is expected to appear
 * separately in the section header or badge.
 *
 * Falls back to stripping the known provider prefix and title-casing the rest:
 *   e.g. "aws_new_service_type" → "New service type"
 */
export function formatResourceTypeLabel(resourceType: string): string {
  const key = resourceType.toLowerCase();
  if (TYPE_LABELS[key]) return TYPE_LABELS[key];

  const PREFIXES = [
    "aws_", "firebase_", "supabase_", "stripe_",
    "github_", "vercel_", "cloudflare_", "shopify_",
  ];
  let rest = key;
  for (const pfx of PREFIXES) {
    if (key.startsWith(pfx)) {
      rest = key.slice(pfx.length);
      break;
    }
  }
  return rest
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
