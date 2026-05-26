/**
 * Risk Assistant — M58.9.
 *
 * Deterministic, grounded question-answering for change investigation rooms.
 * Answers are assembled strictly from existing ConfigTrace data: change fields,
 * risk rules, remediation playbooks, fix plans, and preview data.
 *
 * Architecture:
 *   - Frontend-only. Zero external API calls. No LLM. No hallucination.
 *   - Answers are built from structured fields, not generated text.
 *   - Language rules (must remain in effect permanently):
 *       ✓ Use "may" / "could" when reachability or impact is unproven.
 *       ✗ Never say "breach", "confirmed exposure", or "resolved automatically".
 *       ✗ Never say "guaranteed" or overclaim impact.
 *       ✗ Commands are never included in responses (fix plan shown separately).
 *       ✗ Raw prev_value / new_value strings are never forwarded into answers.
 *       ✗ No sensitive values (tokens, keys, secrets) ever appear in output.
 *
 * Questions:
 *   why_risky           — Why is this change risky?
 *   what_changed        — What changed, in plain English?
 *   what_to_check       — What should I check first?
 *   could_be_expected   — Could this change be expected / intentional?
 *   safest_fix          — What is the safest remediation path?
 *   team_summary        — Concise summary to share with the team.
 *   next_steps          — What should I do next in ConfigTrace?
 *   non_security_summary — Simple explanation without security jargon.
 */

import type { ChangeDetail } from "@/types";
import type { RemediationResult, RemediationGuidance, FixPlanResult } from "@/lib/remediation";
import type { RemediationPreviewResult } from "@/lib/remediationPreview";

// ── Types ─────────────────────────────────────────────────────────────────────

export type AssistantQuestionId =
  | "why_risky"
  | "what_changed"
  | "what_to_check"
  | "could_be_expected"
  | "safest_fix"
  | "team_summary"
  | "next_steps"
  | "non_security_summary";

export interface AssistantQuestion {
  id: AssistantQuestionId;
  /** Button label shown in the chip row. */
  label: string;
}

export interface AssistantResponse {
  question_id: AssistantQuestionId;
  /** Short headline for the answer card. */
  title: string;
  /** Primary prose answer — 2–4 sentences. Uses "may/could" language. */
  answer: string;
  /** Supporting bullet points (3–5 items). */
  bullets: string[];
  /** How confident ConfigTrace is in this answer. */
  confidence: "high" | "medium" | "low";
  /**
   * Source facts shown as grounding chips beneath the answer.
   * e.g. ["Risk level: high", "Provider: AWS", "Remediation: Restrict public admin access"]
   */
  grounding: string[];
  /**
   * Honest caveats about what ConfigTrace cannot prove.
   * e.g. "ConfigTrace cannot confirm reachability from this rule alone."
   */
  limitations: string[];
  /** Optional CTA label for the action button. */
  recommended_action_label?: string;
  /** Anchor link for the CTA (e.g. "#remediation"). */
  anchor?: string;
}

/**
 * Pre-computed context passed to every answer function.
 * Build once with buildRiskAssistantContext and reuse for all questions.
 */
export interface AssistantContext {
  change: ChangeDetail;
  remediation: RemediationResult;
  fixPlan: FixPlanResult;
  preview: RemediationPreviewResult;
  relatedChangesCount: number;
  /** Title of the detected change cluster, if any (from M58.10 correlation). */
  clusterSummary?: string | null;
  // Derived / normalised fields (set once, used everywhere)
  provider: string;
  recordType: string;        // lowercase provider_metadata.record_type
  riskLevel: string;         // lowercase
  riskReason: string;        // lowercase (for logic matching)
  fieldPath: string;         // lowercase
  changeType: string;        // "added" | "removed" | "modified"
  recordIdentifier: string;
}

// ── Context builder ───────────────────────────────────────────────────────────

/**
 * Derive the provider key from provider_metadata.record_type.
 * Mirrors getTimelineProvider in timeline.ts — kept local to avoid circular dep.
 */
function _deriveProvider(rt: string): string {
  if (rt.startsWith("aws_"))       return "aws";
  if (rt.startsWith("github_"))    return "github";
  if (rt.startsWith("vercel_"))    return "vercel";
  if (rt.startsWith("stripe_"))    return "stripe";
  if (rt.startsWith("firebase_"))  return "firebase";
  if (rt.startsWith("supabase_"))  return "supabase";
  if (rt.startsWith("shopify_"))   return "shopify";
  // Cloudflare DNS record types are bare type strings ("a", "cname", etc.)
  if (rt !== "") return "cloudflare";
  return "unknown";
}

/** Build the context object used by all question answerers. */
export function buildRiskAssistantContext(
  change: ChangeDetail,
  remediation: RemediationResult,
  fixPlan: FixPlanResult,
  preview: RemediationPreviewResult,
  relatedChangesCount = 0,
  clusterSummary?: string | null,
): AssistantContext {
  const pm = change.provider_metadata ?? {};
  const rt = ((pm["record_type"] as string) ?? "").toLowerCase();
  return {
    change,
    remediation,
    fixPlan,
    preview,
    relatedChangesCount,
    clusterSummary: clusterSummary ?? null,
    provider:         _deriveProvider(rt),
    recordType:       rt,
    riskLevel:        (change.risk_level   ?? "unknown").toLowerCase(),
    riskReason:       (change.risk_reason  ?? "").toLowerCase(),
    fieldPath:        (change.field_path   ?? "").toLowerCase(),
    changeType:       change.change_type.toLowerCase(),
    recordIdentifier: change.record_identifier ?? "",
  };
}

// ── Question catalogue ────────────────────────────────────────────────────────

const ALL_QUESTIONS: AssistantQuestion[] = [
  { id: "why_risky",            label: "Why is this risky?" },
  { id: "what_changed",         label: "What changed?" },
  { id: "what_to_check",        label: "What should I check first?" },
  { id: "could_be_expected",    label: "Could this be expected?" },
  { id: "safest_fix",           label: "What's the safest fix?" },
  { id: "team_summary",         label: "Summarize for my team" },
  { id: "next_steps",           label: "What should I do next?" },
  { id: "non_security_summary", label: "Explain simply" },
];

const LOW_RISK_QUESTIONS: AssistantQuestion[] = [
  { id: "what_changed",         label: "What changed?" },
  { id: "could_be_expected",    label: "Could this be expected?" },
  { id: "next_steps",           label: "What should I do next?" },
  { id: "non_security_summary", label: "Explain simply" },
];

/**
 * Return the appropriate question list for this change.
 * Low / unknown risk gets a reduced set; safest_fix is omitted when no
 * remediation guidance is available.
 */
export function getAssistantQuestionsForChange(ctx: AssistantContext): AssistantQuestion[] {
  const rl = ctx.riskLevel;
  if (rl === "low" || rl === "unknown") return LOW_RISK_QUESTIONS;
  if (!ctx.remediation.available && !ctx.fixPlan.available) {
    return ALL_QUESTIONS.filter((q) => q.id !== "safest_fix");
  }
  return ALL_QUESTIONS;
}

// ── Provider-specific grounding sentences ─────────────────────────────────────

/** One to two sentences about why this kind of resource matters for security. */
function _providerContext(provider: string, rt: string): string {
  if (provider === "aws") {
    if (rt.includes("security_group"))
      return "AWS Security Groups are the primary network perimeter for EC2 and other VPC resources. " +
        "Inbound rules determine what traffic may reach attached instances.";
    if (rt.includes("iam"))
      return "AWS IAM policies and roles define what actions identities can perform. " +
        "Overly permissive policies may allow unauthorized resource access or privilege escalation.";
    if (rt.includes("cloudtrail"))
      return "AWS CloudTrail records API calls and management events across your account. " +
        "Disabling or narrowing it may reduce audit trail coverage and affect incident investigation.";
    if (rt.includes("cloudfront"))
      return "AWS CloudFront delivers content and enforces HTTPS and origin access controls. " +
        "Security configuration changes here may affect encryption enforcement or WAF integration.";
    if (rt.includes("waf"))
      return "AWS WAF filters HTTP/HTTPS requests before they reach your application. " +
        "Rule changes may reduce protection against injection, bot, or DDoS-style traffic patterns.";
    if (rt.includes("route53"))
      return "AWS Route 53 manages DNS for AWS-hosted domains. " +
        "Unexpected DNS changes can redirect traffic or affect service availability.";
    return "AWS configuration changes affect cloud infrastructure security, access control, and availability. " +
      "Review this change in the context of your AWS account security posture.";
  }

  if (provider === "cloudflare") {
    const cfDnsTypes = new Set(["a","aaaa","cname","mx","txt","ns","srv","ptr","spf","caa","ds","tlsa"]);
    if (cfDnsTypes.has(rt) || rt.includes("dns"))
      return "Cloudflare DNS records control traffic routing for your domain. " +
        "Unexpected changes may affect service availability, email delivery (MX/SPF/DKIM), or domain ownership verification.";
    if (rt.includes("waf"))
      return "Cloudflare WAF rules protect against web application attacks. " +
        "Rule changes may reduce filtering for injection, bot, or other threat categories.";
    if (rt.includes("ssl"))
      return "Cloudflare SSL/TLS settings enforce HTTPS and control certificate behavior. " +
        "Weakening these settings may expose traffic to interception.";
    return "Cloudflare manages DNS, CDN, and security services. " +
      "Configuration changes may affect traffic routing, HTTPS enforcement, or security filtering.";
  }

  if (provider === "firebase") {
    if (rt.includes("rules") || rt.includes("firestore") || rt.includes("realtime"))
      return "Firebase security rules govern client-side read/write access to Firestore and Realtime Database. " +
        "Overly permissive rules may expose data to unauthenticated or unauthorized users from client apps.";
    if (rt.includes("app_check"))
      return "Firebase App Check verifies that requests originate from your legitimate app. " +
        "Disabling it may allow unauthorized API usage from non-app clients.";
    if (rt.includes("auth"))
      return "Firebase Auth configuration controls sign-in providers, MFA settings, and session behavior. " +
        "Changes here affect how users authenticate to your application.";
    return "Firebase project configuration changes may affect authentication, client data access rules, " +
      "or security settings for your Firebase-backed services.";
  }

  if (provider === "supabase") {
    if (rt.includes("rls"))
      return "Supabase Row Level Security (RLS) controls which rows a database role can read or write. " +
        "Disabling RLS on a client-accessible table may expose all rows to any authenticated — or anonymous — user, " +
        "depending on the policies configured.";
    if (rt.includes("auth"))
      return "Supabase Auth settings control user authentication flows, external OAuth providers, and JWT configuration. " +
        "Changes may affect how users access your application.";
    if (rt.includes("storage"))
      return "Supabase Storage access control governs who can read or write stored objects. " +
        "Overly permissive policies may expose private files to unintended users.";
    return "Supabase configuration changes may affect database access control, authentication, " +
      "or storage security for your application.";
  }

  if (provider === "stripe") {
    if (rt.includes("webhook"))
      return "Stripe webhooks deliver real-time payment events including payment confirmations, " +
        "subscription renewals, refunds, and billing lifecycle events. " +
        "Unexpected endpoint changes or disablement may cause downstream systems to miss critical billing events.";
    if (rt.includes("api_key") || rt.includes("apikey"))
      return "Stripe API keys authorize payment-processing operations. " +
        "Unexpected key changes may indicate unauthorized rotation or potential key exposure.";
    if (rt.includes("billing"))
      return "Stripe Billing Portal configuration controls the customer-facing subscription management experience. " +
        "Changes may affect customer self-service capabilities.";
    return "Stripe configuration changes may affect payment processing, billing, or webhook delivery. " +
      "Review this change in the context of your payment and billing workflows.";
  }

  if (provider === "github") {
    if (rt.includes("branch_protection"))
      return "GitHub branch protection rules require pull request reviews and passing status checks before merging. " +
        "Weakening or removing these rules may allow commits to reach protected branches without review.";
    if (rt.includes("environment"))
      return "GitHub environment protection rules control deployment approvals, required reviewers, and deployment secrets. " +
        "Changes may affect security gates in your deployment pipeline.";
    if (rt.includes("webhook"))
      return "GitHub webhooks deliver repository events to CI/CD pipelines and external integrations. " +
        "Unexpected changes may affect the systems that depend on these event streams.";
    if (rt.includes("secret") || rt.includes("deploy_key"))
      return "GitHub repository secrets and deploy keys control access to your codebase and CI/CD pipelines. " +
        "Unexpected changes should be reviewed against your access control policy.";
    return "GitHub configuration changes may affect code review requirements, deployment pipelines, " +
      "or access controls for your repository.";
  }

  if (provider === "vercel") {
    if (rt.includes("deploy_hook"))
      return "Vercel deploy hooks are secret URLs that trigger deployments when called — they function like API keys for your pipeline. " +
        "Unexpected changes may indicate an unauthorized hook was added or a legitimate hook was removed.";
    if (rt.includes("protection") || rt.includes("deployment_protection"))
      return "Vercel deployment protection controls who can access preview and production deployments. " +
        "Changes here may affect access to in-progress or deployed versions of your app.";
    if (rt.includes("env"))
      return "Vercel environment variables store build-time and runtime configuration. " +
        "Unexpected changes may affect application behavior or expose configuration to unintended environments.";
    return "Vercel configuration changes may affect deployment settings, environment variables, " +
      "or access controls for your project.";
  }

  if (provider === "shopify") {
    if (rt.includes("webhook"))
      return "Shopify webhooks deliver store events to external systems. " +
        "Changes may affect order processing integrations, inventory sync, or third-party apps.";
    if (rt.includes("scope") || rt.includes("permission"))
      return "Shopify app permissions control what data and actions installed apps can access. " +
        "Unexpected permission changes may indicate unauthorized scope expansion.";
    return "Shopify configuration changes may affect store operations, installed app access, " +
      "or event delivery to external systems.";
  }

  return "Review this configuration change in the context of your security posture " +
    "and intended infrastructure state.";
}

/** Expected / not-expected framing, balanced per provider and record type. */
function _couldBeExpectedContext(
  provider: string, rt: string, rr: string, ct: string,
): { couldIf: string[]; needsReviewIf: string[] } {
  // AWS security group
  if (provider === "aws" && rt.includes("security_group")) {
    return {
      couldIf: [
        "The change was a documented emergency access rule added by an on-call engineer.",
        "A VPN or bastion host was being replaced and temporary public access was opened intentionally.",
        "This is a non-production environment with known relaxed rules.",
      ],
      needsReviewIf: [
        "No change ticket or team communication covers this rule.",
        "The attached resources include production databases, application servers, or other sensitive workloads.",
        "The rule allows access on administrative ports (SSH/RDP) from any IP.",
      ],
    };
  }

  // GitHub branch protection
  if (provider === "github" && rt.includes("branch_protection")) {
    return {
      couldIf: [
        "A team member was temporarily relaxing protection to perform an emergency hotfix.",
        "A repository migration required temporarily removing protection rules.",
        "The team is moving from one branch protection model to another.",
      ],
      needsReviewIf: [
        "No team communication or change ticket covers this.",
        "The affected branch is a production or main release branch.",
        "Required reviewers or status checks were removed without an alternative gating mechanism.",
      ],
    };
  }

  // Cloudflare DNS
  if (provider === "cloudflare") {
    return {
      couldIf: [
        "A planned DNS migration or hosting provider change was in progress.",
        "A new subdomain or service was being set up by the engineering team.",
        "An old record was intentionally removed as part of decommissioning.",
      ],
      needsReviewIf: [
        "No migration or infrastructure change was planned for this domain.",
        "The affected record is a root domain, mail (MX), or security record (SPF/DMARC).",
        "The change was not preceded by any infrastructure deployment activity.",
      ],
    };
  }

  // Firebase security rules
  if (provider === "firebase" && (rt.includes("rules") || rt.includes("firestore"))) {
    return {
      couldIf: [
        "Rules were temporarily opened for development or debugging purposes.",
        "A migration required temporarily allowing broader access.",
        "This is a development or staging Firebase project, not production.",
      ],
      needsReviewIf: [
        "This is a production project with real user data.",
        "The affected collection or path contains personally identifiable or sensitive information.",
        "No engineering task or PR corresponds to a rules deployment.",
      ],
    };
  }

  // Supabase RLS
  if (provider === "supabase" && rt.includes("rls")) {
    return {
      couldIf: [
        "RLS was disabled temporarily during a migration or schema change.",
        "This is a development database and the table does not contain production data.",
        "The table is only accessible via a backend service role, not the anon key.",
      ],
      needsReviewIf: [
        "The table is accessible via the Supabase anon or authenticated keys from client apps.",
        "The table contains user data, payment records, or other sensitive information.",
        "No migration or schema change was in progress when this was detected.",
      ],
    };
  }

  // Stripe webhooks
  if (provider === "stripe" && rt.includes("webhook")) {
    return {
      couldIf: [
        "The team was migrating the webhook endpoint to a new URL as part of an infrastructure change.",
        "A webhook was intentionally disabled during a maintenance window.",
        "The endpoint URL changed because of a deployment, domain change, or routing update.",
      ],
      needsReviewIf: [
        "No infrastructure change or deployment corresponds to the timing of this event.",
        "Payment confirmation, subscription lifecycle, or refund handling relies on this webhook.",
        "The endpoint is unknown or does not match any known service.",
      ],
    };
  }

  // Vercel deploy hook
  if (provider === "vercel" && rt.includes("deploy_hook")) {
    return {
      couldIf: [
        "A new CI/CD integration or CMS trigger was being set up.",
        "An existing hook was being replaced with a new one for a migrated integration.",
        "The hook was added by a team member for a scheduled deployment automation.",
      ],
      needsReviewIf: [
        "No team member recalls creating this hook.",
        "The hook targets an unexpected branch or production deployment.",
        "An existing hook was removed without a corresponding replacement.",
      ],
    };
  }

  // Generic added/removed/modified
  if (ct === "added") {
    return {
      couldIf: [
        "A team member added this configuration as part of a planned change.",
        "A new integration or feature deployment required this addition.",
      ],
      needsReviewIf: [
        "No change ticket or team communication corresponds to this addition.",
        "The addition grants new access or relaxes existing security controls.",
      ],
    };
  }
  if (ct === "removed") {
    return {
      couldIf: [
        "A team member removed this configuration as part of a decommission or cleanup.",
        "A migration to a new provider or service caused this removal.",
      ],
      needsReviewIf: [
        "No change ticket or team communication corresponds to this removal.",
        "The removed configuration was providing access control or security enforcement.",
      ],
    };
  }

  return {
    couldIf: [
      "A team member made this change as part of a planned configuration update.",
      "A deployment or migration required this setting to change.",
    ],
    needsReviewIf: [
      "No team member or change ticket accounts for this change.",
      "The change weakens an existing security control.",
    ],
  };
}

/** Generic first-checks if remediation.verify_first is not available. */
function _genericChecks(provider: string, rt: string): string[] {
  if (provider === "aws" && rt.includes("security_group")) {
    return [
      "Identify all resources attached to this security group.",
      "Confirm whether an alternate access path (VPN, bastion, or SSM) exists.",
      "Check CloudTrail to find who made this change and when.",
      "Determine whether attached resources are production or non-production.",
    ];
  }
  if (provider === "github" && rt.includes("branch_protection")) {
    return [
      "Identify the affected branch and whether it is a production or release branch.",
      "Check who made the change and whether it corresponds to a known task.",
      "Audit recent commits to this branch for any that bypassed review.",
      "Confirm the desired protection settings before restoring.",
    ];
  }
  if (provider === "firebase") {
    return [
      "Identify which collection or database path is affected.",
      "Check whether the project is production or development.",
      "Review recent rules deployments in your Firebase project history.",
      "Use the Firebase Rules Simulator to test current access levels.",
    ];
  }
  if (provider === "supabase" && rt.includes("rls")) {
    return [
      "Confirm whether the table is accessible via the anon or authenticated key.",
      "Check for existing RLS policies before re-enabling (Step 1 in the fix plan).",
      "Determine whether this is a production table with real user data.",
      "Review recent migration history for an intentional disable.",
    ];
  }
  if (provider === "stripe") {
    return [
      "Check the current webhook endpoint status in the Stripe Dashboard.",
      "Confirm whether the endpoint URL matches a known, active service.",
      "Review recent webhook delivery logs for failures.",
      "Identify which payment events this webhook is expected to handle.",
    ];
  }
  if (provider === "cloudflare") {
    return [
      "Confirm the expected DNS record value from your infrastructure documentation.",
      "Check DNS propagation using a tool like dnschecker.org.",
      "Identify which services depend on the affected record.",
      "Review Cloudflare Audit Logs for who made the change.",
    ];
  }
  return [
    "Confirm whether this change was intentional by checking team communications or change tickets.",
    "Identify all systems or users that may be affected by this change.",
    "Review audit logs for the provider to determine who made the change.",
    "Assess whether the change weakens an existing security control.",
  ];
}

/** Generic limitations when no remediation data is available. */
function _genericLimitations(provider: string, rt: string): string[] {
  if (provider === "aws" && rt.includes("security_group")) {
    return [
      "ConfigTrace can detect rule changes but cannot confirm whether the affected resources are reachable from the public internet without network topology context.",
      "Actual risk depends on attached resources, route table configuration, and whether resources have public IPs.",
    ];
  }
  if (provider === "firebase") {
    return [
      "ConfigTrace detects rule changes but cannot evaluate rule logic or determine which data paths are exposed without the full rule context.",
    ];
  }
  if (provider === "supabase" && rt.includes("rls")) {
    return [
      "ConfigTrace can detect RLS status changes but cannot confirm which roles or keys have access to the table without schema and policy context.",
      "Tables accessed only via the service role key are not exposed by RLS changes — anon/authenticated key access requires extra care.",
    ];
  }
  return [
    "ConfigTrace detects configuration drift but cannot always confirm the full impact without additional provider context.",
  ];
}

// ── Grounding builder ─────────────────────────────────────────────────────────

function _riskLabel(rl: string): string {
  return rl.charAt(0).toUpperCase() + rl.slice(1);
}

function _providerLabel(provider: string): string {
  const labels: Record<string, string> = {
    aws: "AWS",
    cloudflare: "Cloudflare",
    firebase: "Firebase",
    supabase: "Supabase",
    stripe: "Stripe",
    github: "GitHub",
    vercel: "Vercel",
    shopify: "Shopify",
    unknown: "Unknown provider",
  };
  return labels[provider] ?? provider;
}

function _buildGrounding(ctx: AssistantContext): string[] {
  const facts: string[] = [
    `Risk level: ${_riskLabel(ctx.riskLevel)}`,
    `Provider: ${_providerLabel(ctx.provider)}`,
  ];
  if (ctx.recordType) {
    facts.push(`Resource type: ${ctx.recordType}`);
  }
  if (ctx.change.field_path) {
    facts.push(`Field: ${ctx.change.field_path}`);
  }
  if (ctx.remediation.available) {
    facts.push(`Remediation: ${ctx.remediation.title}`);
  }
  if (ctx.fixPlan.available) {
    facts.push(`Fix plan: ${ctx.fixPlan.title}`);
  }
  return facts;
}

// ── Answer generators ─────────────────────────────────────────────────────────

function _answerWhyRisky(ctx: AssistantContext): AssistantResponse {
  const rem = ctx.remediation.available ? (ctx.remediation as RemediationGuidance) : null;

  // Use original-case risk_reason for display
  const riskReasonDisplay = ctx.change.risk_reason ?? null;
  const providerCtx = _providerContext(ctx.provider, ctx.recordType);

  // Compose answer: risk_reason → provider context → why_this_helps
  const parts: string[] = [];
  if (riskReasonDisplay) {
    const sentence = riskReasonDisplay.endsWith(".") ? riskReasonDisplay : riskReasonDisplay + ".";
    parts.push(sentence.charAt(0).toUpperCase() + sentence.slice(1));
  }
  parts.push(providerCtx);
  if (rem?.why_this_helps) {
    parts.push(rem.why_this_helps);
  }

  const answer = parts.join(" ");

  const bullets: string[] = rem?.verify_first?.slice(0, 4) ??
    _genericChecks(ctx.provider, ctx.recordType);

  const limitations: string[] = rem?.caveats?.slice(0, 2) ??
    _genericLimitations(ctx.provider, ctx.recordType);

  if (ctx.clusterSummary) {
    limitations.push(
      `A nearby change cluster was detected ("${ctx.clusterSummary}") — review whether this was part of a planned deployment.`,
    );
  } else if (ctx.relatedChangesCount > 0) {
    limitations.push(
      `There ${ctx.relatedChangesCount === 1 ? "is" : "are"} ${ctx.relatedChangesCount} other nearby change${ctx.relatedChangesCount === 1 ? "" : "s"} on this integration — review whether this was part of a coordinated deployment.`,
    );
  }

  const confidence: AssistantResponse["confidence"] =
    rem?.confidence === "high" ? "high" :
    rem?.confidence === "medium" ? "medium" :
    ctx.riskLevel === "critical" ? "high" :
    ctx.riskLevel === "high" ? "medium" : "low";

  return {
    question_id: "why_risky",
    title: rem?.title ?? `Why this is ${_riskLabel(ctx.riskLevel)} risk`,
    answer,
    bullets,
    confidence,
    grounding: _buildGrounding(ctx),
    limitations,
    recommended_action_label: rem ? "Review remediation guidance" : undefined,
    anchor: rem ? "#remediation" : undefined,
  };
}

function _answerWhatChanged(ctx: AssistantContext): AssistantResponse {
  const { change, provider, recordType, changeType, fieldPath } = ctx;

  // Build a safe plain-English sentence from structural metadata only.
  // Raw prev_value/new_value strings are never used.
  const recordName = (change.provider_metadata?.["record_name"] as string | undefined) ?? "";
  const ctLabel =
    changeType === "added" ? "added" :
    changeType === "removed" ? "removed" :
    "modified";

  let opening = "";

  // Provider-specific sentences
  if (provider === "aws") {
    if (recordType.includes("security_group")) {
      opening = fieldPath
        ? `An AWS Security Group rule was ${ctLabel} (field: ${fieldPath}).`
        : `An AWS Security Group was ${ctLabel}.`;
    } else if (recordType.includes("iam")) {
      opening = `An AWS IAM resource was ${ctLabel}.`;
    } else if (recordType.includes("cloudtrail")) {
      opening = `An AWS CloudTrail configuration was ${ctLabel}.`;
    } else {
      opening = `An AWS resource (${recordType}) was ${ctLabel}.`;
    }
  } else if (provider === "github") {
    if (recordType.includes("branch_protection")) {
      opening = fieldPath
        ? `A GitHub branch protection setting was ${ctLabel} (field: ${fieldPath}).`
        : `A GitHub branch protection rule was ${ctLabel}.`;
    } else if (recordType.includes("webhook")) {
      opening = `A GitHub repository webhook was ${ctLabel}.`;
    } else {
      opening = `A GitHub configuration (${recordType}) was ${ctLabel}.`;
    }
  } else if (provider === "cloudflare") {
    const dnsTypes = new Set(["a","aaaa","cname","mx","txt","ns","srv","ptr","spf","caa","ds","tlsa"]);
    const typeName = dnsTypes.has(recordType) ? recordType.toUpperCase() : "DNS";
    opening = recordName
      ? `The Cloudflare ${typeName} record for ${recordName} was ${ctLabel}.`
      : `A Cloudflare ${typeName} DNS record was ${ctLabel}.`;
  } else if (provider === "firebase") {
    opening = `A Firebase ${recordType.replace("firebase_", "").replace(/_/g, " ")} configuration was ${ctLabel}.`;
  } else if (provider === "supabase") {
    if (recordType.includes("rls")) {
      opening = changeType === "removed"
        ? `Row Level Security (RLS) was disabled on the table ${change.record_identifier || "(unknown)"}.`
        : `Row Level Security (RLS) status changed on the table ${change.record_identifier || "(unknown)"}.`;
    } else {
      opening = `A Supabase configuration (${recordType}) was ${ctLabel}.`;
    }
  } else if (provider === "stripe") {
    if (recordType.includes("webhook")) {
      opening = changeType === "removed"
        ? `A Stripe webhook endpoint was removed.`
        : changeType === "added"
          ? `A new Stripe webhook endpoint was added.`
          : `A Stripe webhook endpoint setting was modified${fieldPath ? ` (field: ${fieldPath})` : ""}.`;
    } else {
      opening = `A Stripe configuration (${recordType}) was ${ctLabel}.`;
    }
  } else if (provider === "vercel") {
    if (recordType.includes("deploy_hook")) {
      opening = changeType === "added"
        ? `A new Vercel deploy hook was added.`
        : changeType === "removed"
          ? `A Vercel deploy hook was removed.`
          : `A Vercel deploy hook was modified.`;
    } else {
      opening = `A Vercel configuration (${recordType}) was ${ctLabel}.`;
    }
  } else if (provider === "shopify") {
    opening = `A Shopify configuration (${recordType}) was ${ctLabel}.`;
  } else {
    opening = fieldPath
      ? `A configuration field (${fieldPath}) was ${ctLabel}.`
      : `A configuration resource was ${ctLabel}.`;
  }

  const providerCtx = _providerContext(provider, recordType);

  const answer = `${opening} ${providerCtx}`;

  const bullets: string[] = [
    `Change type: ${ctLabel}`,
    `Resource: ${change.record_identifier || "(see Technical Details)"}`,
    ...(fieldPath ? [`Affected field: ${fieldPath}`] : []),
    `Detected: ${new Date(change.created_at).toLocaleString()}`,
  ];

  return {
    question_id: "what_changed",
    title: "What changed",
    answer,
    bullets,
    confidence: "high",
    grounding: _buildGrounding(ctx),
    limitations: [
      "Previous and new values are shown in the Technical Diff section below when available.",
    ],
  };
}

function _answerWhatToCheck(ctx: AssistantContext): AssistantResponse {
  const rem = ctx.remediation.available ? (ctx.remediation as RemediationGuidance) : null;

  const checks = rem?.verify_first?.slice(0, 5) ??
    _genericChecks(ctx.provider, ctx.recordType);

  const answer =
    `Start by confirming whether this change was intentional, then assess its potential impact. ` +
    `The checks below are based on the resource type and risk classification.`;

  return {
    question_id: "what_to_check",
    title: "What to check first",
    answer,
    bullets: checks,
    confidence: rem ? (rem.confidence === "high" ? "high" : "medium") : "medium",
    grounding: _buildGrounding(ctx),
    limitations: _genericLimitations(ctx.provider, ctx.recordType),
    recommended_action_label: rem ? "See full remediation steps" : undefined,
    anchor: rem ? "#remediation" : undefined,
  };
}

function _answerCouldBeExpected(ctx: AssistantContext): AssistantResponse {
  const { provider, recordType, riskReason, changeType } = ctx;
  const { couldIf, needsReviewIf } = _couldBeExpectedContext(provider, recordType, riskReason, changeType);

  const answer =
    `This change could be expected depending on context. ` +
    `${_riskLabel(ctx.riskLevel)}-risk changes still need team review even if they were intentional, ` +
    `because undocumented access changes may accumulate and widen your attack surface over time.`;

  const bullets: string[] = [
    "Could be expected if:",
    ...couldIf.map((s) => `  → ${s}`),
    "Needs review if:",
    ...needsReviewIf.map((s) => `  → ${s}`),
  ];

  return {
    question_id: "could_be_expected",
    title: "Could this be expected?",
    answer,
    bullets,
    confidence: "medium",
    grounding: _buildGrounding(ctx),
    limitations: [
      "ConfigTrace cannot determine intent. Only your team can confirm whether this change was planned.",
    ],
    recommended_action_label: "Acknowledge or mark expected",
    anchor: "#review",
  };
}

function _answerSafestFix(ctx: AssistantContext): AssistantResponse {
  const rem = ctx.remediation.available ? (ctx.remediation as RemediationGuidance) : null;
  const fp  = ctx.fixPlan.available ? ctx.fixPlan : null;
  const prev = ctx.preview.available ? ctx.preview : null;

  let answer = "";
  const bullets: string[] = [];

  if (rem) {
    answer = rem.summary + " " + rem.why_this_helps;
    bullets.push(...(rem.manual_steps ?? []).slice(0, 4));
    if (rem.caveats?.length) bullets.push(`Caution: ${rem.caveats[0]}`);
  } else {
    answer =
      `Review the change in the provider console and assess whether the configuration needs to be restored. ` +
      `Use the remediation guidance and fix plan (if available) as a reference before applying any changes.`;
    bullets.push(
      "Confirm the change was not intentional before attempting remediation.",
      "Review the provider console for the current state of the resource.",
      "Apply changes in a non-production environment first if possible.",
      "Run a ConfigTrace sync after applying the fix to confirm the finding is resolved.",
    );
  }

  const fixAvailability: string[] = [];
  if (fp) fixAvailability.push("A fix plan with step-by-step guidance is available below.");
  if (prev) fixAvailability.push("A dry-run preview showing before/after state is available below.");

  const answer2 = fixAvailability.length > 0
    ? answer + " " + fixAvailability.join(" ")
    : answer;

  const limitations: string[] = [
    "ConfigTrace does not execute any changes. All remediation steps require manual review and application.",
    ...(rem?.caveats?.slice(1, 3) ?? []),
  ];

  return {
    question_id: "safest_fix",
    title: rem ? `Safest fix: ${rem.title}` : "Safest remediation path",
    answer: answer2,
    bullets,
    confidence: rem ? (rem.confidence === "high" ? "high" : "medium") : "low",
    grounding: _buildGrounding(ctx),
    limitations,
    recommended_action_label: fp ? "View fix plan" : rem ? "View remediation guidance" : undefined,
    anchor: fp ? "#fix-plan" : rem ? "#remediation" : undefined,
  };
}

function _answerTeamSummary(ctx: AssistantContext): AssistantResponse {
  const { change, provider, recordType, riskLevel } = ctx;
  const provLabel = _providerLabel(provider);
  const riskLabel = _riskLabel(riskLevel);
  const rem = ctx.remediation.available ? (ctx.remediation as RemediationGuidance) : null;

  // Build a concise shareable paragraph
  const ctLabel =
    change.change_type === "added" ? "addition" :
    change.change_type === "removed" ? "removal" :
    "modification";

  const remedSentence = rem
    ? ` Suggested remediation: ${rem.summary}`
    : " Review this change to confirm it was intentional and assess whether remediation is needed.";

  const relatedSentence = ctx.clusterSummary
    ? ` Note: A nearby change cluster was detected ("${ctx.clusterSummary}") — this change may be part of a coordinated deployment.`
    : ctx.relatedChangesCount > 0
      ? ` Note: ${ctx.relatedChangesCount} nearby change${ctx.relatedChangesCount === 1 ? " was" : "s were"} also detected on this integration around the same time.`
      : "";

  const answer =
    `ConfigTrace detected a ${riskLabel.toLowerCase()}-risk configuration change in ${provLabel}. ` +
    `A ${ctLabel} was detected on ${change.record_identifier || "a " + recordType + " resource"}.` +
    (change.risk_reason ? ` Reason: ${change.risk_reason}.` : "") +
    remedSentence +
    relatedSentence;

  const bullets: string[] = [
    `Provider: ${provLabel}`,
    `Risk level: ${riskLabel}`,
    `Change type: ${ctLabel}`,
    `Detected: ${new Date(change.created_at).toLocaleString()}`,
    ...(rem ? [`Suggested action: ${rem.title}`] : []),
  ];

  return {
    question_id: "team_summary",
    title: "Team summary",
    answer,
    bullets,
    confidence: "high",
    grounding: _buildGrounding(ctx),
    limitations: [
      "Review before sharing — confirm the risk context is accurate for your environment.",
    ],
  };
}

function _answerNextSteps(ctx: AssistantContext): AssistantResponse {
  const rem = ctx.remediation.available ? (ctx.remediation as RemediationGuidance) : null;
  const hasFixPlan = ctx.fixPlan.available;
  const hasPreview = ctx.preview.available;
  const isElevated = ctx.riskLevel === "critical" || ctx.riskLevel === "high";

  const answer =
    `Review the change details, confirm whether it was intentional, and update the review status in ConfigTrace. ` +
    `${isElevated ? "For high or critical changes, prompt team review and remediation are recommended. " : ""}` +
    `You can acknowledge it, mark it as expected if it was planned, or snooze it if you are investigating.`;

  const bullets: string[] = [];
  bullets.push("Review: Does this change match your expected infrastructure state?");
  bullets.push("If intentional: Acknowledge or mark as expected to close the finding.");
  bullets.push("If under investigation: Snooze to return to it later and add a team note.");
  if (rem) {
    bullets.push(`Remediation available: ${rem.title} — review guidance below.`);
  }
  if (hasFixPlan) {
    bullets.push("Fix plan available — step-by-step guidance is in the Remediation section.");
  }
  if (hasPreview) {
    bullets.push("Dry-run preview available — review the before/after state below.");
  }
  if (ctx.relatedChangesCount > 0) {
    bullets.push(
      `${ctx.relatedChangesCount} nearby related change${ctx.relatedChangesCount === 1 ? "" : "s"} detected — review the Related Changes panel below.`,
    );
  }
  bullets.push("After remediation: run a ConfigTrace sync to confirm the finding is resolved.");

  return {
    question_id: "next_steps",
    title: "What to do next",
    answer,
    bullets,
    confidence: "high",
    grounding: _buildGrounding(ctx),
    limitations: [],
    recommended_action_label: "Review status options",
    anchor: "#review",
  };
}

function _answerNonSecuritySummary(ctx: AssistantContext): AssistantResponse {
  const { change, provider, recordType, riskLevel } = ctx;
  const provLabel = _providerLabel(provider);
  const riskLabel = _riskLabel(riskLevel);

  // Friendly, jargon-free explanation per provider
  let simpleWhat = "";
  let simpleWhy = "";
  let simpleAction = "";

  if (provider === "aws" && recordType.includes("security_group")) {
    simpleWhat = "One of your AWS network access rules changed. These rules control who can connect to your servers.";
    simpleWhy = "If the rule now allows access from anywhere on the internet, it may be wider than intended.";
    simpleAction = "The security team should confirm this was expected and restrict access if needed.";
  } else if (provider === "cloudflare") {
    simpleWhat = "A DNS record for your domain changed. DNS records control where your web traffic is sent.";
    simpleWhy = "Unexpected DNS changes could redirect visitors or affect email delivery.";
    simpleAction = "The engineering team should confirm this matches a planned migration or infrastructure change.";
  } else if (provider === "firebase") {
    simpleWhat = "A Firebase access rule changed. These rules control who can read and write app data.";
    simpleWhy = "If rules became more permissive, data may be accessible to more users than intended.";
    simpleAction = "The development team should review the updated rules and confirm they are correct.";
  } else if (provider === "supabase" && recordType.includes("rls")) {
    simpleWhat = "A database access control setting changed. Row Level Security controls which data users can see.";
    simpleWhy = "If this was disabled, users might be able to access data that should be private.";
    simpleAction = "The engineering team should confirm this was intentional and re-enable it if needed.";
  } else if (provider === "stripe") {
    simpleWhat = "A Stripe payment system setting changed.";
    simpleWhy = "If a webhook endpoint changed unexpectedly, payment events like confirmations or refunds might not be processed correctly.";
    simpleAction = "The engineering team should confirm the change and verify payment flows are working.";
  } else if (provider === "github") {
    simpleWhat = "A GitHub repository setting changed.";
    simpleWhy = "Branch protection and approval rules help ensure that code changes are reviewed before being deployed.";
    simpleAction = "The engineering team should confirm this was intentional and restore any needed protections.";
  } else if (provider === "vercel") {
    simpleWhat = "A Vercel deployment setting changed.";
    simpleWhy = "Unexpected changes to deployment configuration can affect how your website or app is built and published.";
    simpleAction = "The engineering team should confirm this was expected and review any related deployments.";
  } else {
    simpleWhat = `A ${provLabel} configuration setting changed.`;
    simpleWhy = "Configuration drift from the expected state may indicate an unplanned change that needs review.";
    simpleAction = "The engineering or security team should confirm whether this change was intentional.";
  }

  const answer = `${simpleWhat} ${simpleWhy} ${simpleAction}`;

  const bullets: string[] = [
    `What: ${change.change_type === "added" ? "A new setting was added" : change.change_type === "removed" ? "An existing setting was removed" : "An existing setting was changed"}.`,
    `Where: ${provLabel}${change.record_identifier ? ` — ${change.record_identifier}` : ""}.`,
    `Risk level: ${riskLabel} — flagged for team review.`,
    "No automated action was taken. Review and decision needed from your team.",
  ];

  return {
    question_id: "non_security_summary",
    title: "Plain English explanation",
    answer,
    bullets,
    confidence: "high",
    grounding: _buildGrounding(ctx),
    limitations: [
      "This is a simplified summary. See the full technical details in the sections below.",
    ],
  };
}

// ── Main dispatcher ───────────────────────────────────────────────────────────

/**
 * Generate a deterministic, grounded answer for the given question ID.
 * All answers are derived from existing ConfigTrace data — no external API calls,
 * no hallucination, no sensitive values forwarded.
 */
export function answerAssistantQuestion(
  questionId: AssistantQuestionId,
  ctx: AssistantContext,
): AssistantResponse {
  switch (questionId) {
    case "why_risky":            return _answerWhyRisky(ctx);
    case "what_changed":         return _answerWhatChanged(ctx);
    case "what_to_check":        return _answerWhatToCheck(ctx);
    case "could_be_expected":    return _answerCouldBeExpected(ctx);
    case "safest_fix":           return _answerSafestFix(ctx);
    case "team_summary":         return _answerTeamSummary(ctx);
    case "next_steps":           return _answerNextSteps(ctx);
    case "non_security_summary": return _answerNonSecuritySummary(ctx);
  }
}
