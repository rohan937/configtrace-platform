"use client";

import { useParams } from "next/navigation";
import { useState, useEffect, Fragment } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import type { ChangeDetail, ChangeReviewResponse, DnsRecord, ReviewStatus } from "@/types";
import {
  getChange,
  acknowledgeChange,
  markChangeExpected,
  snoozeChange,
  reopenChange,
} from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import RiskBadge from "@/components/common/RiskBadge";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import DnsRecordView from "@/components/changes/DnsRecordView";
import {
  formatRelativeTime,
  formatAbsoluteTime,
  changeTypeLabel,
  formatDiffValue,
  formatSnapshotHash,
} from "@/lib/utils";
import {
  getTimelineEventTitle,
  getTimelineProvider,
  getTimelineCategory,
} from "@/lib/timeline";
import { getProviderMeta } from "@/lib/providers";
import {
  getRemediationGuidance,
  type RemediationGuidance,
  type FixPlan,
} from "@/lib/remediation";
import { getFixPlanForChange } from "@/lib/fixPlans";
import {
  getRemediationPreviewForChange,
  type RemediationPreview,
  type BeforeAfterItem,
} from "@/lib/remediationPreview";

// ── Risk panel background colors ──────────────────────────────────────────────

const RISK_PANEL_BG: Record<string, string> = {
  critical: "rgba(232,64,64,0.07)",
  high:     "rgba(245,99,42,0.07)",
  medium:   "rgba(245,166,35,0.07)",
  low:      "rgba(107,156,248,0.07)",
  unknown:  "rgba(86,91,110,0.10)",
};

const RISK_PANEL_BORDER: Record<string, string> = {
  critical: "rgba(232,64,64,0.25)",
  high:     "rgba(245,99,42,0.25)",
  medium:   "rgba(245,166,35,0.25)",
  low:      "rgba(107,156,248,0.25)",
  unknown:  "#2a2d38",
};

const RISK_TEXT: Record<string, string> = {
  critical: "#e84040",
  high:     "#f5632a",
  medium:   "#f5a623",
  low:      "#6b9cf8",
  unknown:  "#565b6e",
};

// ── Small layout helpers ──────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p
      style={{
        fontSize: "11px",
        color: "#565b6e",
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        marginBottom: "8px",
        fontWeight: 500,
      }}
    >
      {children}
    </p>
  );
}

function Panel({
  children,
  bg = "#13151a",
  border = "#2a2d38",
}: {
  children: React.ReactNode;
  bg?: string;
  border?: string;
}) {
  return (
    <div
      style={{
        background: bg,
        border: `1px solid ${border}`,
        borderRadius: "6px",
        padding: "16px",
      }}
    >
      {children}
    </div>
  );
}

function MetaRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline gap-3" style={{ marginBottom: "4px" }}>
      <span
        style={{
          width: "120px",
          flexShrink: 0,
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
        }}
      >
        {label}
      </span>
      <span style={{ fontSize: "13px", color: "#8b90a0" }}>{children}</span>
    </div>
  );
}

// ── Diff panel — modified ─────────────────────────────────────────────────────

function ModifiedDiffPanel({ change }: { change: ChangeDetail }) {
  const prevText = formatDiffValue(change.prev_value);
  const newText  = formatDiffValue(change.new_value);
  const isMultiline = prevText.includes("\n") || newText.includes("\n");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
      {change.field_path && (
        <p style={{ fontSize: "12px", color: "#565b6e", marginBottom: "4px" }}>
          Field:{" "}
          <span
            style={{
              fontFamily: "monospace",
              color: "#8b90a0",
              background: "#1c1e26",
              padding: "1px 5px",
              borderRadius: "3px",
            }}
          >
            {change.field_path}
          </span>
        </p>
      )}

      {/* Before */}
      <div
        style={{
          background: "rgba(232,64,64,0.07)",
          border: "1px solid rgba(232,64,64,0.20)",
          borderRadius: "4px",
          padding: "10px 12px",
        }}
      >
        <span
          style={{
            fontSize: "10px",
            color: "#e84040",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            display: "block",
            marginBottom: "4px",
          }}
        >
          Before
        </span>
        <pre
          style={{
            fontFamily: "monospace",
            fontSize: "13px",
            color: "#e8eaf0",
            margin: 0,
            whiteSpace: isMultiline ? "pre-wrap" : "pre",
            wordBreak: "break-all",
          }}
        >
          {prevText}
        </pre>
      </div>

      {/* After */}
      <div
        style={{
          background: "rgba(60,207,126,0.06)",
          border: "1px solid rgba(60,207,126,0.20)",
          borderRadius: "4px",
          padding: "10px 12px",
        }}
      >
        <span
          style={{
            fontSize: "10px",
            color: "#3ccf7e",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            display: "block",
            marginBottom: "4px",
          }}
        >
          After
        </span>
        <pre
          style={{
            fontFamily: "monospace",
            fontSize: "13px",
            color: "#e8eaf0",
            margin: 0,
            whiteSpace: isMultiline ? "pre-wrap" : "pre",
            wordBreak: "break-all",
          }}
        >
          {newText}
        </pre>
      </div>
    </div>
  );
}

// ── Diff panel — added / removed ──────────────────────────────────────────────

function AddedRemovedPanel({
  change,
  isGitHub = false,
}: {
  change: ChangeDetail;
  isGitHub?: boolean;
}) {
  const isAdded   = change.change_type === "added";
  const record    = isAdded ? change.new_value : change.prev_value;
  const tint      = isAdded ? "add" : "remove";
  const label     = isAdded
    ? isGitHub ? "Configuration Added" : "DNS Record Added"
    : isGitHub ? "Configuration Removed" : "DNS Record Removed";
  const labelColor = isAdded ? "#3ccf7e" : "#e84040";

  const isDnsRecord =
    record !== null &&
    record !== undefined &&
    typeof record === "object" &&
    !Array.isArray(record);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
      <p style={{ fontSize: "13px", color: labelColor, fontWeight: 500 }}>
        {label}
      </p>
      {isDnsRecord ? (
        <DnsRecordView
          record={record as Record<string, unknown>}
          tint={tint}
        />
      ) : (
        <div
          style={{
            background: "#1c1e26",
            border: "1px solid #2a2d38",
            borderRadius: "4px",
            padding: "10px 12px",
          }}
        >
          <pre
            style={{
              fontFamily: "monospace",
              fontSize: "12px",
              color: "#8b90a0",
              margin: 0,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
            }}
          >
            {formatDiffValue(record)}
          </pre>
        </div>
      )}
    </div>
  );
}

// ── Provider-aware helpers ────────────────────────────────────────────────────

/** "Cloudflare DNS" | "GitHub repo configuration" | "Vercel project configuration" | "Stripe account configuration" | "AWS account configuration" | "Firebase project configuration" | "Supabase project configuration" | "Shopify store configuration" */
function getProviderLabel(change: ChangeDetail): string {
  const rt = (
    (change.provider_metadata?.record_type as string | undefined) ?? ""
  ).toLowerCase();
  if (rt.startsWith("github_"))   return "GitHub repo configuration";
  if (rt.startsWith("vercel_"))   return "Vercel project configuration";
  if (rt.startsWith("stripe_"))   return "Stripe account configuration";
  if (rt.startsWith("aws_"))      return "AWS account configuration";
  if (rt.startsWith("firebase_")) return "Firebase project configuration";
  if (rt.startsWith("supabase_")) return "Supabase project configuration";
  if (rt.startsWith("shopify_"))  return "Shopify store configuration";
  if (change.provider_metadata?.record_type) return "Cloudflare DNS";
  return "Cloudflare DNS";
}

/** One-sentence description of what happened. */
function getChangeSummary(change: ChangeDetail): string {
  const rt = (
    (change.provider_metadata?.record_type as string | undefined) ?? ""
  ).toLowerCase();
  const rn = (change.provider_metadata?.record_name as string | undefined) ?? "";
  const fp = change.field_path ?? "";
  const nv = change.new_value;
  const pv = change.prev_value;

  // GitHub
  if (rt === "github_actions_secret") {
    const label = rn ? `The Actions secret ${rn}` : "An Actions secret";
    if (change.change_type === "removed") return `${label} was deleted.`;
    if (change.change_type === "added")   return `A new Actions secret${rn ? ` ${rn}` : ""} was added.`;
    return `${label} was rotated.`;
  }
  if (rt === "github_branch_protection") {
    if (change.change_type === "removed") return "A branch protection rule was deleted.";
    if (change.change_type === "added")   return "A branch protection rule was added.";
    return `A branch protection setting changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "github_repo_settings") {
    if (fp === "visibility") return `Repository visibility changed to ${String(nv)}.`;
    if (fp === "default_branch") return `The default branch changed from ${String(pv)} to ${String(nv)}.`;
    if (fp === "archived") return "The repository was archived.";
    return `A repository setting changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "github_webhook") {
    if (change.change_type === "removed") return "A repository webhook was deleted.";
    if (change.change_type === "added")   return "A new repository webhook was added.";
    if (fp === "url") return "The webhook delivery URL changed.";
    return "A webhook setting changed.";
  }
  if (rt === "github_deploy_key") {
    if (change.change_type === "removed") return "A deploy key was removed.";
    if (change.change_type === "added") {
      const rec = typeof nv === "object" && nv !== null ? nv as Record<string, unknown> : {};
      const access = rec.read_only === false ? "write-enabled" : "read-only";
      return `A ${access} deploy key was added.`;
    }
    return "A deploy key was modified.";
  }
  if (rt === "github_environment_protection") {
    const envName = rn || change.record_identifier;
    if (change.change_type === "added")   return `Environment protection rule was added for ${envName}.`;
    if (change.change_type === "removed") return `Environment protection rule was removed from ${envName}.`;
    return `Environment protection rule changed for ${envName}${fp ? ` (${fp})` : ""}.`;
  }
  if (rt.startsWith("github_")) {
    return `A GitHub configuration record changed (${rt}).`;
  }

  // Vercel
  if (rt === "vercel_project") {
    if (change.change_type === "modified") {
      if (fp === "framework")          return `The Vercel project framework changed to ${String(nv)}.`;
      if (fp === "build_command")      return `The Vercel build command changed.`;
      if (fp === "install_command")    return `The Vercel install command changed.`;
      if (fp === "root_directory")     return `The Vercel root directory changed to ${String(nv)}.`;
      if (fp === "output_directory")   return `The Vercel output directory changed.`;
      if (fp === "node_version")       return `The Node.js version changed to ${String(nv)}.`;
      if (fp === "git_branch")         return `The production branch changed to ${String(nv)}.`;
      if (fp === "git_repository")     return `The connected Git repository changed.`;
      if (fp === "sso_protection")     return nv ? `SSO protection was enabled on this Vercel project.` : `SSO protection was disabled on this Vercel project.`;
      if (fp === "password_protection") return nv ? `Password protection was enabled.` : `Password protection was disabled.`;
      return `A Vercel project setting changed (${fp}).`;
    }
    return `Vercel project configuration changed.`;
  }
  if (rt === "vercel_env_var") {
    // SECURITY: env var values are never stored — only metadata is shown.
    const envName = (change.provider_metadata?.record_name as string | undefined) ?? rn;
    if (change.change_type === "removed") return `The environment variable ${envName || "key"} was removed.`;
    if (change.change_type === "added")   return `A new environment variable${envName ? ` (${envName})` : ""} was added.`;
    return `An environment variable was modified (${fp}).`;
  }
  if (rt === "vercel_domain") {
    if (change.change_type === "removed") return `The domain ${rn || change.record_identifier} was removed from this Vercel project.`;
    if (change.change_type === "added")   return `The domain ${rn || change.record_identifier} was added to this Vercel project.`;
    return `Domain configuration changed for ${rn || change.record_identifier}.`;
  }
  if (rt === "vercel_deploy_hook_metadata") {
    const hookName = rn || change.record_identifier;
    if (change.change_type === "added")   return `Deploy hook ${hookName} was added to this Vercel project.`;
    if (change.change_type === "removed") return `Deploy hook ${hookName} was removed from this Vercel project.`;
    return `Deploy hook ${hookName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt.startsWith("vercel_")) {
    return `A Vercel configuration record changed (${rt}).`;
  }

  // Stripe
  if (rt === "stripe_account_settings") {
    if (fp === "charges_enabled" && nv === false) return "Charges were disabled on this Stripe account.";
    if (fp === "charges_enabled") return "Stripe charges enabled status changed.";
    if (fp === "payouts_enabled" && nv === false) return "Payouts were disabled on this Stripe account.";
    if (fp === "payouts_enabled") return "Stripe payouts enabled status changed.";
    if (fp === "payout_schedule_interval") return `The Stripe payout schedule changed to ${String(nv)}.`;
    if (fp === "default_currency") return `The Stripe account default currency changed to ${String(nv)}.`;
    if (fp === "business_name") return `The Stripe account business name changed to ${String(nv)}.`;
    if (fp === "display_name") return `The Stripe dashboard display name changed to ${String(nv)}.`;
    if (fp === "support_email") return "The Stripe account support email changed.";
    if (fp === "branding_primary_color") return `The Stripe branding primary color changed to ${String(nv)}.`;
    return "A Stripe account setting changed.";
  }
  if (rt === "stripe_webhook_endpoint") {
    if (change.change_type === "removed") return `A Stripe webhook endpoint was deleted.`;
    if (change.change_type === "added")   return `A new Stripe webhook endpoint was added.`;
    if (fp === "url") return "The Stripe webhook delivery URL changed.";
    if (fp === "status" && nv === "disabled") return "A Stripe webhook endpoint was disabled.";
    if (fp === "status") return "A Stripe webhook endpoint was re-enabled.";
    if (fp === "enabled_events") return "The event types subscribed to by a Stripe webhook changed.";
    if (fp === "api_version") return `The Stripe webhook API version changed to ${String(nv)}.`;
    return "A Stripe webhook setting changed.";
  }
  if (rt === "stripe_payment_method_configuration") {
    if (change.change_type === "removed") return "A Stripe payment method configuration was removed.";
    if (change.change_type === "added")   return "A new Stripe payment method configuration was added.";
    if (fp === "enabled_payment_methods") return "The set of enabled payment methods in a Stripe configuration changed.";
    if (fp === "is_default") return "The default Stripe payment method configuration changed.";
    return "A Stripe payment method configuration changed.";
  }
  if (rt === "stripe_payment_method_domain") {
    if (change.change_type === "removed") return "A Stripe payment method domain was removed.";
    if (change.change_type === "added")   return "A new Stripe payment method domain was added.";
    if (fp === "apple_pay_enabled" && nv === false) return "Apple Pay was disabled for a Stripe payment method domain.";
    if (fp === "apple_pay_enabled") return "Apple Pay was enabled for a Stripe payment method domain.";
    if (fp === "google_pay_enabled" && nv === false) return "Google Pay was disabled for a Stripe payment method domain.";
    if (fp === "google_pay_enabled") return "Google Pay was enabled for a Stripe payment method domain.";
    if (fp === "enabled" && nv === false) return "A Stripe payment method domain was disabled.";
    return "A Stripe payment method domain setting changed.";
  }
  if (rt === "stripe_billing_portal_config") {
    if (change.change_type === "added")   return "A Stripe billing portal configuration was added.";
    if (change.change_type === "removed") return "A Stripe billing portal configuration was removed.";
    if (fp === "is_default") return "The default Stripe billing portal configuration changed.";
    return `Stripe billing portal configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt.startsWith("stripe_")) {
    return `A Stripe configuration record changed (${rt}).`;
  }

  // AWS
  if (rt === "aws_account_identity") {
    if (change.change_type === "added")   return "AWS account identity was established for this integration.";
    if (change.change_type === "removed") return "The AWS account identity record was removed from monitoring.";
    if (fp === "principal_arn")           return "The AWS IAM principal (ARN) used by this integration changed.";
    if (fp === "account_id")              return "The AWS account ID changed — this integration may now point at a different account.";
    if (fp === "principal_type")          return `The AWS principal type changed to ${String(nv)}.`;
    if (fp === "selected_regions")        return "The set of monitored AWS regions changed.";
    if (fp === "default_region")          return `The default AWS region changed to ${String(nv)}.`;
    return "An AWS account identity setting changed.";
  }
  if (rt === "aws_region") {
    const regionId = change.record_identifier;
    if (change.change_type === "removed") return `AWS region ${regionId} was removed from monitoring.`;
    if (change.change_type === "added")   return `AWS region ${regionId} was added to monitoring.`;
    if (fp === "opt_in_status")           return `The opt-in status for AWS region ${regionId} changed.`;
    if (fp === "enabled")                 return `AWS region ${regionId} enabled status changed.`;
    return `AWS region ${regionId} metadata changed.`;
  }
  if (rt === "aws_service_inventory") {
    if (fp === "selected_regions") return "The set of AWS monitoring regions changed in the service inventory.";
    if (fp === "enabled_surfaces") return "The set of actively monitored AWS surfaces changed.";
    if (fp === "s3_bucket_count")  return `The number of visible S3 buckets changed to ${String(nv)}.`;
    return "The AWS service inventory record was updated.";
  }
  if (rt === "aws_s3_bucket") {
    // Derive bucket name from the record identifier (format: "aws_s3_bucket <name>")
    const bucketName = change.record_identifier?.replace(/^aws_s3_bucket\s+/, "") || change.record_identifier;
    if (change.change_type === "added")   return `S3 bucket ${bucketName} appeared in monitoring.`;
    if (change.change_type === "removed") return `S3 bucket ${bucketName} is no longer visible.`;
    // Modified field
    if (fp === "policy_status_is_public" && nv === true)  return `S3 bucket ${bucketName} is now publicly accessible according to AWS.`;
    if (fp === "policy_status_is_public" && nv === false) return `S3 bucket ${bucketName} is no longer publicly accessible.`;
    if (fp === "acl_all_users_write"     && nv === true)  return `Public WRITE access was granted on S3 bucket ${bucketName} via ACL.`;
    if (fp === "acl_all_users_read"      && nv === true)  return `Public READ access was granted on S3 bucket ${bucketName} via ACL.`;
    if (fp === "public_principals_detected" && nv === true) return `A public principal (* or all AWS accounts) was added to the bucket policy of ${bucketName}.`;
    if (fp === "block_public_acls"        && nv === false) return `Block Public ACLs was disabled on S3 bucket ${bucketName}.`;
    if (fp === "ignore_public_acls"       && nv === false) return `Ignore Public ACLs was disabled on S3 bucket ${bucketName}.`;
    if (fp === "block_public_policy"      && nv === false) return `Block Public Policy was disabled on S3 bucket ${bucketName}.`;
    if (fp === "restrict_public_buckets"  && nv === false) return `Restrict Public Buckets was disabled on S3 bucket ${bucketName}.`;
    if (fp === "public_access_block_configured" && nv === false) return `Block Public Access configuration was removed from S3 bucket ${bucketName}.`;
    if (fp === "encryption_enabled" && nv === false)  return `Default encryption was disabled on S3 bucket ${bucketName}.`;
    if (fp === "encryption_enabled" && nv === true)   return `Default encryption was enabled on S3 bucket ${bucketName}.`;
    if (fp === "versioning_status" && (nv === "suspended" || nv === "disabled")) return `Versioning was ${String(nv)} on S3 bucket ${bucketName}.`;
    if (fp === "versioning_status" && nv === "enabled") return `Versioning was enabled on S3 bucket ${bucketName}.`;
    if (fp === "logging_enabled" && nv === false) return `Access logging was disabled on S3 bucket ${bucketName}.`;
    if (fp === "logging_enabled" && nv === true)  return `Access logging was enabled on S3 bucket ${bucketName}.`;
    if (fp === "policy_hash")    return `The bucket policy for ${bucketName} changed.`;
    if (fp === "policy_present" && nv === true)  return `A bucket policy was added to S3 bucket ${bucketName}.`;
    if (fp === "policy_present" && nv === false) return `The bucket policy was removed from S3 bucket ${bucketName}.`;
    if (fp === "lifecycle_rule_count") return `Lifecycle rule count changed to ${String(nv)} on S3 bucket ${bucketName}.`;
    if (fp === "encryption_algorithm") return `Encryption algorithm changed to ${String(nv)} on S3 bucket ${bucketName}.`;
    if (fp === "bucket_region") return `The recorded region for S3 bucket ${bucketName} changed.`;
    return `S3 bucket ${bucketName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  // AWS M38 — Security Groups
  if (rt === "aws_security_group") {
    const sgName = (change.provider_metadata?.record_name as string | undefined) ?? change.record_identifier;
    if (change.change_type === "added") {
      const isPublic = change.new_value && typeof change.new_value === "object" && (change.new_value as Record<string, unknown>).has_public_inbound;
      return isPublic
        ? `Security group ${sgName} was added with publicly reachable inbound rules.`
        : `Security group ${sgName} was added to monitoring.`;
    }
    if (change.change_type === "removed") return `Security group ${sgName} is no longer monitored.`;
    if (fp === "has_public_ssh" && nv === true)  return `Security group ${sgName} now allows SSH (port 22) from the internet.`;
    if (fp === "has_public_rdp" && nv === true)  return `Security group ${sgName} now allows RDP (port 3389) from the internet.`;
    if (fp === "has_public_database_port" && nv === true) return `Security group ${sgName} now allows a database port from the internet.`;
    if (fp === "has_public_inbound" && nv === true) return `Security group ${sgName} now permits inbound traffic from public CIDRs.`;
    if (fp === "has_public_ssh" || fp === "has_public_rdp" || fp === "has_public_database_port" || fp === "has_public_inbound") {
      return `Security group ${sgName} public exposure status changed (${fp}).`;
    }
    if (fp === "inbound_rule_count" || fp === "outbound_rule_count") return `The number of rules in security group ${sgName} changed to ${String(nv)}.`;
    return `Security group ${sgName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_security_group_rule") {
    if (change.change_type === "added") {
      const isPublic = change.new_value && typeof change.new_value === "object" && (change.new_value as Record<string, unknown>).is_public;
      return isPublic
        ? `A new inbound rule allowing public traffic was added to a security group.`
        : `A new security group rule was added.`;
    }
    if (change.change_type === "removed") return "A security group rule was removed.";
    if (fp === "description") return "A security group rule description changed.";
    return "A security group rule was modified.";
  }

  // AWS M38 — VPC Network
  if (rt === "aws_vpc") {
    const vpcId = change.record_identifier;
    if (change.change_type === "added")   return `VPC ${vpcId} was added to monitoring.`;
    if (change.change_type === "removed") return `VPC ${vpcId} is no longer monitored.`;
    if (fp === "state" && nv !== "available") return `VPC ${vpcId} state changed to ${String(nv)}.`;
    if (fp === "instance_tenancy") return `VPC ${vpcId} instance tenancy changed to ${String(nv)}.`;
    if (fp === "cidr_block") return `The CIDR block for VPC ${vpcId} changed.`;
    return `VPC ${vpcId} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_subnet") {
    const subnetId = change.record_identifier;
    if (change.change_type === "added")   return `Subnet ${subnetId} was added to monitoring.`;
    if (change.change_type === "removed") return `Subnet ${subnetId} is no longer monitored.`;
    if (fp === "map_public_ip_on_launch" && nv === true)  return `Subnet ${subnetId} will now auto-assign public IPs to launched instances.`;
    if (fp === "map_public_ip_on_launch" && nv === false) return `Subnet ${subnetId} no longer auto-assigns public IPs.`;
    if (fp === "state") return `Subnet ${subnetId} state changed to ${String(nv)}.`;
    return `Subnet ${subnetId} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_route_table") {
    const rtId = change.record_identifier;
    if (change.change_type === "added")   return `Route table ${rtId} was added to monitoring.`;
    if (change.change_type === "removed") return `Route table ${rtId} is no longer monitored.`;
    if (fp === "has_igw_route" && nv === true)  return `Route table ${rtId} now routes traffic to an internet gateway.`;
    if (fp === "has_igw_route" && nv === false) return `Route table ${rtId} no longer routes traffic to an internet gateway.`;
    if (fp === "route_count") return `The number of routes in route table ${rtId} changed to ${String(nv)}.`;
    return `Route table ${rtId} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_internet_gateway") {
    const igwId = change.record_identifier;
    if (change.change_type === "added")   return `Internet gateway ${igwId} was added to monitoring.`;
    if (change.change_type === "removed") return `Internet gateway ${igwId} is no longer monitored.`;
    if (fp === "attached_vpc_id" && !pv && nv) return `Internet gateway ${igwId} was attached to a VPC.`;
    if (fp === "attached_vpc_id" && pv && !nv) return `Internet gateway ${igwId} was detached from its VPC.`;
    if (fp === "state") return `Internet gateway ${igwId} state changed to ${String(nv)}.`;
    return `Internet gateway ${igwId} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_network_acl") {
    const naclId = change.record_identifier;
    if (change.change_type === "added")   return `Network ACL ${naclId} was added to monitoring.`;
    if (change.change_type === "removed") return `Network ACL ${naclId} is no longer monitored.`;
    if (fp === "inbound_allow_all_count" && typeof nv === "number" && typeof pv === "number" && nv > (pv as number)) {
      return `Network ACL ${naclId} now has more permissive inbound allow-all rules.`;
    }
    return `Network ACL ${naclId} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  // AWS M39 — IAM
  if (rt === "aws_iam_account_summary") return "IAM Account Posture";
  if (rt === "aws_iam_user") return `IAM User: ${rn || change.record_identifier || ""}`;
  if (rt === "aws_iam_access_key") return `Access Key: ${rn || change.record_identifier || ""}`;
  if (rt === "aws_iam_group") return `IAM Group: ${rn || change.record_identifier || ""}`;
  if (rt === "aws_iam_role") return `IAM Role: ${rn || change.record_identifier || ""}`;
  if (rt === "aws_iam_policy") return `IAM Policy: ${rn || change.record_identifier || ""}`;
  if (rt === "aws_iam_policy_attachment") return `Policy Attachment: ${rn || change.record_identifier || ""}`;
  if (rt === "aws_iam_inline_policy") return `Inline Policy: ${rn || change.record_identifier || ""}`;
  if (rt === "aws_iam_identity_provider") return `Identity Provider: ${rn || change.record_identifier || ""}`;

  if (rt === "aws_route53_hosted_zone") {
    const zoneName = (change.provider_metadata?.name as string | undefined) ?? change.record_identifier ?? "unknown";
    if (change.change_type === "removed") return `Route53 hosted zone ${zoneName} was deleted.`;
    if (change.change_type === "added")   return `Route53 hosted zone ${zoneName} was added to monitoring.`;
    if (fp === "name_servers")            return `Name servers changed for Route53 zone ${zoneName}.`;
    if (fp === "zone_type")               return `Zone type changed for Route53 zone ${zoneName} (${String(pv)} → ${String(nv)}).`;
    if (fp === "private_zone")            return `Route53 zone ${zoneName} private flag changed.`;
    if (fp === "resource_record_set_count") return `Record count changed to ${String(nv)} in Route53 zone ${zoneName}.`;
    return `Route53 hosted zone ${zoneName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_route53_record") {
    const recName = (change.provider_metadata?.record_name as string | undefined) ?? change.record_identifier ?? "unknown";
    const dnsType = (change.provider_metadata?.dns_record_type as string | undefined) ?? "";
    const zoneName2 = (change.provider_metadata?.zone_name as string | undefined) ?? "";
    if (change.change_type === "removed") return `DNS record ${recName} (${dnsType}) was removed from zone ${zoneName2}.`;
    if (change.change_type === "added")   return `DNS record ${recName} (${dnsType}) was added to zone ${zoneName2}.`;
    if (fp === "value_hash")              return `DNS record ${recName} (${dnsType}) value changed in zone ${zoneName2}.`;
    if (fp === "alias_target_dns_name")   return `Alias target for ${recName} (${dnsType}) changed to ${String(nv)} in zone ${zoneName2}.`;
    if (fp === "dmarc_policy")            return `DMARC policy for zone ${zoneName2} changed from ${String(pv)} to ${String(nv)}.`;
    if (fp === "ttl")                     return `TTL for DNS record ${recName} (${dnsType}) changed from ${String(pv)} to ${String(nv)}s.`;
    if (fp === "routing_policy")          return `Routing policy for ${recName} (${dnsType}) changed to ${String(nv)}.`;
    return `DNS record ${recName} (${dnsType}) configuration changed${fp ? ` (${fp})` : ""} in zone ${zoneName2}.`;
  }
  if (rt === "aws_cloudfront_distribution") {
    const distName = (change.provider_metadata?.name as string | undefined) ?? change.record_identifier ?? "unknown";
    if (change.change_type === "removed") return `CloudFront distribution ${distName} was removed.`;
    if (change.change_type === "added")   return `CloudFront distribution ${distName} was added to monitoring.`;
    if (fp === "enabled" && nv === false) return `CloudFront distribution ${distName} was disabled.`;
    if (fp === "enabled" && nv === true)  return `CloudFront distribution ${distName} was enabled.`;
    if (fp === "web_acl_id" && (nv === null || nv === "")) return `WAF web ACL was removed from CloudFront distribution ${distName}.`;
    if (fp === "web_acl_id")              return `WAF web ACL changed on CloudFront distribution ${distName}.`;
    if (fp === "origins_summary")         return `Origin configuration changed on CloudFront distribution ${distName}.`;
    if (fp === "aliases")                 return `Domain aliases changed on CloudFront distribution ${distName}.`;
    if (fp === "default_cache_behavior_summary") return `Default cache behavior changed on CloudFront distribution ${distName}.`;
    if (fp === "viewer_certificate_summary") return `Viewer certificate / TLS settings changed on CloudFront distribution ${distName}.`;
    return `CloudFront distribution ${distName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_secretsmanager_secret") {
    const secretName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `Secrets Manager secret ${secretName} was removed.`;
    if (change.change_type === "added")   return `New Secrets Manager secret ${secretName} was added.`;
    if (fp === "rotation_enabled" && nv === false) return `Automatic rotation was disabled for secret ${secretName}.`;
    if (fp === "rotation_enabled" && nv === true)  return `Automatic rotation was enabled for secret ${secretName}.`;
    if (fp === "deleted_date" && nv !== null)       return `Secret ${secretName} was scheduled for deletion.`;
    if (fp === "kms_key_id_present" && nv === false) return `KMS key was removed from secret ${secretName}.`;
    if (fp === "policy_summary")                    return `Resource policy changed on secret ${secretName}.`;
    return `Secrets Manager secret ${secretName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_ssm_parameter") {
    const paramName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `SSM parameter ${paramName} was removed.`;
    if (change.change_type === "added")   return `New SSM parameter ${paramName} was added.`;
    if (fp === "parameter_type")          return `SSM parameter ${paramName} type changed from ${String(pv)} to ${String(nv)}.`;
    if (fp === "key_id_present" && nv === false) return `KMS key was removed from SSM parameter ${paramName}.`;
    if (fp === "version")                 return `SSM parameter ${paramName} was updated to version ${String(nv)}.`;
    return `SSM parameter ${paramName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_rds_db_instance") {
    const dbId = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `RDS DB instance ${dbId} is no longer visible to ConfigTrace.`;
    if (change.change_type === "added")   return `RDS DB instance ${dbId} was added to monitoring.`;
    if (fp === "publicly_accessible" && nv === true)  return `RDS DB instance ${dbId} is now publicly accessible.`;
    if (fp === "publicly_accessible" && nv === false) return `RDS DB instance ${dbId} is no longer publicly accessible.`;
    if (fp === "storage_encrypted" && nv === false)   return `Encryption at rest was disabled for RDS DB instance ${dbId}.`;
    if (fp === "deletion_protection" && nv === false) return `Deletion protection was disabled for RDS DB instance ${dbId}.`;
    if (fp === "backup_retention_days" && nv === 0)   return `Automated backups were disabled for RDS DB instance ${dbId}.`;
    if (fp === "multi_az" && nv === false)            return `Multi-AZ failover was disabled for RDS DB instance ${dbId}.`;
    if (fp === "iam_database_authentication_enabled" && nv === false) return `IAM database authentication was disabled for RDS DB instance ${dbId}.`;
    if (fp === "db_instance_status")                  return `RDS DB instance ${dbId} status changed to ${String(nv)}.`;
    if (fp === "engine_version")                      return `Engine version changed for RDS DB instance ${dbId} (${String(pv)} → ${String(nv)}).`;
    return `RDS DB instance ${dbId} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_rds_db_cluster") {
    const clusterId = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `RDS DB cluster ${clusterId} is no longer visible to ConfigTrace.`;
    if (change.change_type === "added")   return `RDS DB cluster ${clusterId} was added to monitoring.`;
    if (fp === "publicly_accessible" && nv === true)  return `RDS DB cluster ${clusterId} is now publicly accessible.`;
    if (fp === "storage_encrypted" && nv === false)   return `Encryption at rest was disabled for RDS DB cluster ${clusterId}.`;
    if (fp === "deletion_protection" && nv === false) return `Deletion protection was disabled for RDS DB cluster ${clusterId}.`;
    if (fp === "backup_retention_days" && nv === 0)   return `Automated backups were disabled for RDS DB cluster ${clusterId}.`;
    if (fp === "multi_az" && nv === false)            return `Multi-AZ was disabled for RDS DB cluster ${clusterId}.`;
    if (fp === "iam_database_authentication_enabled" && nv === false) return `IAM database authentication was disabled for RDS DB cluster ${clusterId}.`;
    if (fp === "status")                              return `RDS DB cluster ${clusterId} status changed to ${String(nv)}.`;
    if (fp === "instance_count")                      return `Instance count changed for RDS DB cluster ${clusterId} (${String(pv)} → ${String(nv)}).`;
    return `RDS DB cluster ${clusterId} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_rds_db_subnet_group") {
    const sgName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `RDS subnet group ${sgName} was removed.`;
    if (change.change_type === "added")   return `RDS subnet group ${sgName} was added.`;
    if (fp === "vpc_id")     return `VPC association changed for RDS subnet group ${sgName}.`;
    if (fp === "subnet_ids") return `Subnet membership changed for RDS subnet group ${sgName}.`;
    return `RDS subnet group ${sgName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_rds_db_snapshot") {
    const snapId = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `RDS snapshot ${snapId} was deleted.`;
    if (change.change_type === "added")   return `RDS snapshot ${snapId} was detected.`;
    if (fp === "publicly_accessible" && nv === true)  return `RDS snapshot ${snapId} is now publicly accessible.`;
    if (fp === "storage_encrypted" && nv === false)   return `RDS snapshot ${snapId} is unencrypted.`;
    return `RDS snapshot ${snapId} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_rds_db_cluster_snapshot") {
    const csnapId = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `RDS cluster snapshot ${csnapId} was deleted.`;
    if (change.change_type === "added")   return `RDS cluster snapshot ${csnapId} was detected.`;
    if (fp === "publicly_accessible" && nv === true)  return `RDS cluster snapshot ${csnapId} is now publicly accessible.`;
    if (fp === "storage_encrypted" && nv === false)   return `RDS cluster snapshot ${csnapId} is unencrypted.`;
    return `RDS cluster snapshot ${csnapId} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  // M43 Lambda
  if (rt === "aws_lambda_function") {
    const fnName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `Lambda function ${fnName} is no longer visible to ConfigTrace.`;
    if (change.change_type === "added")   return `Lambda function ${fnName} was added to monitoring.`;
    if (fp === "runtime")          return `Runtime changed for Lambda function ${fnName} (${String(pv)} → ${String(nv)}).`;
    if (fp === "role_arn_hash")    return `Execution role changed for Lambda function ${fnName}.`;
    if (fp === "kms_key_arn_present" && nv === false) return `KMS key was removed from Lambda function ${fnName}.`;
    if (fp === "environment_key_names") return `Environment variable keys changed for Lambda function ${fnName}. ConfigTrace does not read variable values.`;
    if (fp === "environment_key_count") return `Environment variable count changed for Lambda function ${fnName}.`;
    if (fp === "vpc_config_present" && nv === false) return `VPC configuration was removed from Lambda function ${fnName}.`;
    if (fp === "vpc_config_present" && nv === true)  return `Lambda function ${fnName} was added to a VPC.`;
    if (fp === "tracing_mode")     return `X-Ray tracing mode changed for Lambda function ${fnName} (${String(pv)} → ${String(nv)}).`;
    if (fp === "reserved_concurrent_executions") return `Reserved concurrency changed for Lambda function ${fnName} (${String(pv)} → ${String(nv)}).`;
    if (fp === "dead_letter_target_present" && nv === false) return `Dead letter queue/topic was removed from Lambda function ${fnName}.`;
    if (fp === "layer_arn_hashes") return `Lambda layer configuration changed for function ${fnName}.`;
    if (fp === "layers_count")     return `Layer count changed for Lambda function ${fnName} (${String(pv)} → ${String(nv)}).`;
    return `Lambda function ${fnName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_lambda_alias") {
    const aliasName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `Lambda alias ${aliasName} was deleted.`;
    if (change.change_type === "added")   return `Lambda alias ${aliasName} was added.`;
    if (fp === "function_version") return `Lambda alias ${aliasName} now points to version ${String(nv)}.`;
    if (fp === "routing_config_present" && nv === false) return `Traffic routing was removed from Lambda alias ${aliasName}.`;
    return `Lambda alias ${aliasName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_lambda_event_source_mapping") {
    const esmName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `Lambda event source mapping ${esmName} was deleted.`;
    if (change.change_type === "added")   return `Lambda event source mapping ${esmName} was added.`;
    if (fp === "enabled" && nv === false) return `Lambda event source mapping ${esmName} was disabled.`;
    if (fp === "enabled" && nv === true)  return `Lambda event source mapping ${esmName} was re-enabled.`;
    if (fp === "state")                   return `Lambda event source mapping ${esmName} state changed to ${String(nv)}.`;
    if (fp === "event_source_arn_present" && nv === false) return `Event source ARN was removed from Lambda mapping ${esmName}.`;
    if (fp === "function_name")           return `Lambda event source mapping ${esmName} now targets a different function.`;
    if (fp === "batch_size")              return `Batch size changed for Lambda event source mapping ${esmName} (${String(pv)} → ${String(nv)}).`;
    if (fp === "filter_criteria_present" && nv === false) return `Filter criteria were removed from Lambda event source mapping ${esmName}.`;
    return `Lambda event source mapping ${esmName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_lambda_function_url") {
    const urlName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `Lambda function URL for ${urlName} was deleted.`;
    if (change.change_type === "added") {
      const authT = typeof nv === "object" && nv !== null
        ? (nv as Record<string,unknown>).auth_type as string | undefined
        : undefined;
      if (authT === "NONE") return `Lambda function URL for ${urlName} was added with no authentication (publicly invokable).`;
      return `Lambda function URL for ${urlName} was added.`;
    }
    if (fp === "auth_type" && nv === "NONE") return `Lambda function URL for ${urlName} authentication was changed to NONE — function is now publicly invokable.`;
    if (fp === "auth_type")                  return `Lambda function URL for ${urlName} authentication changed to ${String(nv)}.`;
    if (fp === "cors_wildcard_origin_present" && nv === true)   return `Wildcard CORS origin (*) was added to Lambda function URL for ${urlName}.`;
    if (fp === "cors_allow_credentials" && nv === true)         return `CORS credentials were enabled on Lambda function URL for ${urlName}.`;
    return `Lambda function URL for ${urlName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  // M43 API Gateway REST
  if (rt === "aws_apigateway_rest_api") {
    const apiName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `API Gateway REST API ${apiName} is no longer visible to ConfigTrace.`;
    if (change.change_type === "added")   return `API Gateway REST API ${apiName} was added to monitoring.`;
    if (fp === "unauthenticated_method_count") return `Unauthenticated method count changed for REST API ${apiName} (${String(pv)} → ${String(nv)}).`;
    if (fp === "authorizer_count" && nv === 0) return `All authorizers were removed from REST API ${apiName}.`;
    if (fp === "authorizer_count")             return `Authorizer count changed for REST API ${apiName} (${String(pv)} → ${String(nv)}).`;
    if (fp === "policy_summary")               return `Resource policy changed on REST API ${apiName}.`;
    if (fp === "disable_execute_api_endpoint" && nv === false) return `The default execute-api endpoint was re-enabled on REST API ${apiName}.`;
    if (fp === "endpoint_configuration_types") return `Endpoint configuration type changed for REST API ${apiName}.`;
    return `API Gateway REST API ${apiName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_apigateway_rest_stage") {
    const stageName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `API Gateway REST stage ${stageName} was deleted.`;
    if (change.change_type === "added")   return `API Gateway REST stage ${stageName} was added.`;
    if (fp === "deployment_id_present" && nv === false) return `Deployment was detached from REST stage ${stageName}.`;
    if (fp === "web_acl_arn_present" && nv === false)   return `WAF web ACL was removed from REST stage ${stageName}.`;
    if (fp === "tracing_enabled" && nv === false)       return `X-Ray tracing was disabled for REST stage ${stageName}.`;
    if (fp === "access_logging_enabled" && nv === false) return `Access logging was disabled for REST stage ${stageName}.`;
    if (fp === "variables_key_names") return `Stage variable keys changed for REST stage ${stageName}. ConfigTrace does not read variable values.`;
    if (fp === "canary_settings_present" && nv === true)  return `Canary deployment settings were added to REST stage ${stageName}.`;
    if (fp === "canary_settings_present" && nv === false) return `Canary deployment settings were removed from REST stage ${stageName}.`;
    return `API Gateway REST stage ${stageName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  // M43 API Gateway V2
  if (rt === "aws_apigatewayv2_api") {
    const v2Name = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `API Gateway V2 API ${v2Name} is no longer visible to ConfigTrace.`;
    if (change.change_type === "added")   return `API Gateway V2 API ${v2Name} was added to monitoring.`;
    if (fp === "unauthenticated_route_count") return `Unauthenticated route count changed for V2 API ${v2Name} (${String(pv)} → ${String(nv)}).`;
    if (fp === "authorizer_count" && nv === 0) return `All authorizers were removed from V2 API ${v2Name}.`;
    if (fp === "authorizer_count")             return `Authorizer count changed for V2 API ${v2Name} (${String(pv)} → ${String(nv)}).`;
    if (fp === "cors_wildcard_origin_present" && nv === true) return `Wildcard CORS origin (*) was added to V2 API ${v2Name}.`;
    if (fp === "cors_allow_credentials" && nv === true)       return `CORS credentials were enabled on V2 API ${v2Name}.`;
    if (fp === "disable_execute_api_endpoint" && nv === false) return `The default execute-api endpoint was re-enabled on V2 API ${v2Name}.`;
    return `API Gateway V2 API ${v2Name} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_apigatewayv2_stage") {
    const v2Stage = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `API Gateway V2 stage ${v2Stage} was deleted.`;
    if (change.change_type === "added")   return `API Gateway V2 stage ${v2Stage} was added.`;
    if (fp === "auto_deploy" && nv === false) return `Auto-deploy was disabled for V2 stage ${v2Stage}.`;
    if (fp === "auto_deploy" && nv === true)  return `Auto-deploy was enabled for V2 stage ${v2Stage}.`;
    if (fp === "access_logging_enabled" && nv === false) return `Access logging was disabled for V2 stage ${v2Stage}.`;
    if (fp === "detailed_metrics_enabled" && nv === false) return `Detailed metrics were disabled for V2 stage ${v2Stage}.`;
    if (fp === "stage_variables_key_names") return `Stage variable keys changed for V2 stage ${v2Stage}. ConfigTrace does not read variable values.`;
    return `API Gateway V2 stage ${v2Stage} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  // M44 Load Balancers
  if (rt === "aws_elbv2_load_balancer") {
    const lbName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `Load balancer ${lbName} is no longer visible to ConfigTrace.`;
    if (change.change_type === "added")   return `Load balancer ${lbName} was added to monitoring.`;
    if (fp === "scheme" && pv === "internal" && nv === "internet-facing") return `Load balancer ${lbName} scheme changed from internal to internet-facing.`;
    if (fp === "scheme" && pv === "internet-facing" && nv === "internal") return `Load balancer ${lbName} was internalized (internet-facing → internal).`;
    if (fp === "security_group_ids" || fp === "security_group_count") return `Security groups changed on load balancer ${lbName}.`;
    if (fp === "deletion_protection_enabled" && nv === false) return `Deletion protection was disabled on load balancer ${lbName}.`;
    if (fp === "access_logs_enabled" && nv === false) return `Access logging was disabled for load balancer ${lbName}.`;
    if (fp === "desync_mitigation_mode") return `HTTP desync mitigation mode changed on load balancer ${lbName} (${String(pv)} → ${String(nv)}).`;
    if (fp === "drop_invalid_header_fields_enabled" && nv === false) return `Invalid header field dropping was disabled on load balancer ${lbName}.`;
    if (fp === "state") return `Load balancer ${lbName} state changed to ${String(nv)}.`;
    return `Load balancer ${lbName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_elbv2_target_group") {
    const tgName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `Target group ${tgName} is no longer visible to ConfigTrace.`;
    if (change.change_type === "added")   return `Target group ${tgName} was added to monitoring.`;
    if (fp === "protocol" || fp === "port" || fp === "target_type") return `Target group ${tgName} ${fp.replace(/_/g, " ")} changed (${String(pv)} → ${String(nv)}).`;
    if (fp === "health_check_enabled" && nv === false) return `Health checks were disabled on target group ${tgName}.`;
    if (fp === "target_count" && nv === 0) return `Target count dropped to zero on target group ${tgName}.`;
    if (fp === "unhealthy_target_count") return `Unhealthy target count changed on target group ${tgName} (${String(pv)} → ${String(nv)}).`;
    return `Target group ${tgName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_elbv2_listener") {
    const lstLb = (change.provider_metadata?.load_balancer_name as string | undefined) || rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") {
      const proto = (change.provider_metadata?.protocol as string | undefined) || "";
      if (proto && ["HTTPS","TLS","SSL"].includes(proto.toUpperCase())) return `HTTPS/TLS listener was removed from load balancer ${lstLb}.`;
      return `Listener was removed from load balancer ${lstLb}.`;
    }
    if (change.change_type === "added") return `Listener was added to load balancer ${lstLb}.`;
    if (fp === "protocol") return `Listener protocol changed (${String(pv)} → ${String(nv)}) on ${lstLb}.`;
    if (fp === "ssl_policy") return `SSL policy changed on listener for ${lstLb} (${String(pv)} → ${String(nv)}).`;
    if (fp === "certificate_count" && typeof nv === "number" && typeof pv === "number" && nv < pv) return `Certificate count decreased on listener for ${lstLb} (${String(pv)} → ${String(nv)}).`;
    if (fp === "default_target_group_arn_hashes") return `Default routing target changed on listener for ${lstLb}.`;
    return `Listener configuration changed on ${lstLb}${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_elbv2_listener_rule") {
    const ruleLb = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `Listener rule was removed on ${ruleLb}.`;
    if (change.change_type === "added")   return `Listener rule was added on ${ruleLb}.`;
    if (fp === "target_group_arn_hashes") return `Listener rule routing target changed on ${ruleLb}.`;
    if (fp === "action_types") return `Listener rule action types changed on ${ruleLb}.`;
    return `Listener rule configuration changed on ${ruleLb}${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_elb_classic_load_balancer") {
    const clbName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `Classic load balancer ${clbName} is no longer visible to ConfigTrace.`;
    if (change.change_type === "added")   return `Classic load balancer ${clbName} was added to monitoring.`;
    if (fp === "scheme" && pv === "internal" && nv === "internet-facing") return `Classic load balancer ${clbName} scheme changed from internal to internet-facing.`;
    if (fp === "security_group_ids") return `Security groups changed on classic load balancer ${clbName}.`;
    if (fp === "listener_protocols") return `Listener protocols changed on classic load balancer ${clbName}.`;
    if (fp === "access_logs_enabled" && nv === false) return `Access logging was disabled for classic load balancer ${clbName}.`;
    return `Classic load balancer ${clbName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  // M44 WAF
  if (rt === "aws_wafv2_web_acl") {
    const aclName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `WAF Web ACL ${aclName} is no longer visible to ConfigTrace.`;
    if (change.change_type === "added")   return `WAF Web ACL ${aclName} was added to monitoring.`;
    if (fp === "default_action" && nv === "allow") return `WAF Web ACL ${aclName} default action changed to allow — requests may pass through unfiltered.`;
    if (fp === "default_action") return `WAF Web ACL ${aclName} default action changed (${String(pv)} → ${String(nv)}).`;
    if (fp === "rule_count" && typeof nv === "number" && nv === 0) return `All WAF rules were removed from Web ACL ${aclName}.`;
    if (fp === "rule_count") return `WAF rule count changed on Web ACL ${aclName} (${String(pv)} → ${String(nv)}).`;
    if (fp === "managed_rule_group_count") return `Managed rule group count changed on WAF Web ACL ${aclName} (${String(pv)} → ${String(nv)}).`;
    if (fp === "logging_enabled" && nv === false) return `WAF logging was disabled for Web ACL ${aclName}.`;
    if (fp === "associated_resource_count") return `WAF Web ACL ${aclName} association count changed (${String(pv)} → ${String(nv)}).`;
    return `WAF Web ACL ${aclName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_wafv2_web_acl_association") {
    const assocName = rn || (change.record_identifier ?? "unknown");
    if (change.change_type === "removed") return `WAF Web ACL ${assocName} was disassociated from a protected resource.`;
    if (change.change_type === "added")   return `WAF Web ACL ${assocName} was associated with a resource.`;
    return `WAF Web ACL association changed for ${assocName}${fp ? ` (${fp})` : ""}.`;
  }

  // ── M45: CloudTrail + GuardDuty + Security Hub ──────────────────────────
  if (rt === "aws_cloudtrail_trail") {
    const trailName = rn || (change.record_identifier ?? "trail");
    if (change.change_type === "removed") return `CloudTrail trail ${trailName} is no longer visible. Confirm logging has not been silenced.`;
    if (change.change_type === "added")   return `CloudTrail trail ${trailName} is now monitored.`;
    if (fp === "is_logging" && change.new_value === false) return `CloudTrail trail ${trailName} stopped logging. Audit events may no longer be captured.`;
    if (fp === "is_multi_region_trail" && change.new_value === false) return `CloudTrail trail ${trailName} was downgraded from multi-region to single-region.`;
    if (fp === "log_file_validation_enabled" && change.new_value === false) return `CloudTrail trail ${trailName} log file validation was disabled. Log tampering detection is reduced.`;
    if (fp === "kms_key_id_present" && change.new_value === false) return `CloudTrail trail ${trailName} KMS encryption was removed.`;
    if (fp === "kms_key_id_hash") return `CloudTrail trail ${trailName} KMS encryption key changed.`;
    if (fp === "management_events_enabled" && change.new_value === false) return `CloudTrail trail ${trailName} stopped logging management events.`;
    if (fp === "s3_bucket_name_hash") return `CloudTrail trail ${trailName} S3 log destination changed.`;
    return `CloudTrail trail ${trailName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt === "aws_cloudtrail_event_data_store") {
    const edsName = rn || (change.record_identifier ?? "event data store");
    if (change.change_type === "removed") return `CloudTrail event data store ${edsName} was removed.`;
    if (change.change_type === "added")   return `CloudTrail event data store ${edsName} was added.`;
    if (fp === "termination_protection_enabled" && change.new_value === false) return `CloudTrail event data store ${edsName} termination protection was disabled.`;
    if (fp === "retention_period") return `CloudTrail event data store ${edsName} retention period changed.`;
    if (fp === "status") return `CloudTrail event data store ${edsName} status changed to ${change.new_value ?? "unknown"}.`;
    return `CloudTrail event data store ${edsName} changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt === "aws_guardduty_detector") {
    const detName = rn || (change.record_identifier ?? "detector");
    if (change.change_type === "removed") return `GuardDuty detector ${detName} is no longer visible. Threat detection coverage may be missing.`;
    if (change.change_type === "added")   return `GuardDuty detector ${detName} is now monitored.`;
    if (fp === "status" && String(change.new_value).toUpperCase() === "DISABLED") return `GuardDuty detector ${detName} was disabled. Threat detection has stopped in this region.`;
    if (fp === "finding_publishing_frequency") return `GuardDuty detector ${detName} finding publishing frequency changed to ${change.new_value ?? "unknown"}.`;
    if (fp?.endsWith("_enabled") && change.new_value === false) return `GuardDuty ${fp.replace(/_enabled$/, "").replace(/_/g, " ")} protection was disabled in ${detName}.`;
    return `GuardDuty detector ${detName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt === "aws_guardduty_publishing_destination") {
    const destName = rn || (change.record_identifier ?? "destination");
    if (change.change_type === "removed") return `GuardDuty publishing destination ${destName} was removed.`;
    if (change.change_type === "added")   return `GuardDuty publishing destination ${destName} was added.`;
    if (fp === "status") return `GuardDuty publishing destination ${destName} status changed to ${change.new_value ?? "unknown"}.`;
    return `GuardDuty publishing destination ${destName} changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt === "aws_securityhub_account") {
    const hubName = rn || (change.record_identifier ?? "Security Hub");
    if (change.change_type === "removed") return `Security Hub hub ${hubName} is no longer visible.`;
    if (change.change_type === "added")   return `Security Hub hub ${hubName} is now monitored.`;
    if (fp === "hub_enabled" && change.new_value === false) return `Security Hub was disabled in ${hubName}. Security findings will stop being generated.`;
    if (fp === "enabled_standards_count" && Number(change.new_value) === 0) return `All Security Hub standards were disabled in ${hubName}. Control coverage is now zero.`;
    if (fp === "auto_enable_controls" && change.new_value === false) return `Security Hub auto-enable controls was turned off in ${hubName}.`;
    if (fp === "finding_aggregator_present" && change.new_value === false) return `Security Hub finding aggregator was removed in ${hubName}.`;
    return `Security Hub account ${hubName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt === "aws_securityhub_standard_subscription") {
    const stdName = rn || (change.record_identifier ?? "standard");
    if (change.change_type === "removed") return `Security Hub standard subscription ${stdName} was removed. Compliance coverage may be reduced.`;
    if (change.change_type === "added")   return `Security Hub standard subscription ${stdName} was added.`;
    if (fp === "standards_status") return `Security Hub standard ${stdName} status changed to ${change.new_value ?? "unknown"}.`;
    return `Security Hub standard subscription ${stdName} changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt === "aws_securityhub_finding_aggregator") {
    const aggName = rn || (change.record_identifier ?? "aggregator");
    if (change.change_type === "removed") return `Security Hub finding aggregator ${aggName} was removed. Cross-region finding visibility may be reduced.`;
    if (change.change_type === "added")   return `Security Hub finding aggregator ${aggName} was added.`;
    if (fp === "linking_mode") return `Security Hub finding aggregator ${aggName} linking mode changed from ${change.prev_value ?? "unknown"} to ${change.new_value ?? "unknown"}.`;
    return `Security Hub finding aggregator ${aggName} changed${fp ? ` (${fp})` : ""}.`;
  }

  // ── M46: ECS ──────────────────────────────────────────────────────────────
  if (rt === "aws_ecs_cluster") {
    const clusterName = rn || (change.record_identifier ?? "cluster");
    if (change.change_type === "removed") return `ECS cluster ${clusterName} was removed from monitoring.`;
    if (change.change_type === "added")   return `ECS cluster ${clusterName} was added.`;
    if (fp === "container_insights_enabled") return `Container Insights ${change.new_value ? "enabled" : "disabled"} on ECS cluster ${clusterName}.`;
    if (fp === "status") return `ECS cluster ${clusterName} status changed to ${change.new_value ?? "unknown"}.`;
    return `ECS cluster ${clusterName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_ecs_service") {
    const svcName = rn || (change.record_identifier ?? "service");
    if (change.change_type === "removed") return `ECS service ${svcName} was removed from monitoring.`;
    if (change.change_type === "added")   return `ECS service ${svcName} was added.`;
    if (fp === "has_public_ip") return `ECS service ${svcName} ${change.new_value ? "now assigns" : "no longer assigns"} public IPs to tasks.`;
    if (fp === "circuit_breaker_enabled") return `Deployment circuit breaker ${change.new_value ? "enabled" : "disabled"} on ECS service ${svcName}.`;
    if (fp === "task_definition_arn_hash") return `ECS service ${svcName} task definition was updated.`;
    if (fp === "desired_count") return `ECS service ${svcName} desired count changed to ${change.new_value ?? "unknown"}.`;
    return `ECS service ${svcName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_ecs_task_definition") {
    const tdName = rn || (change.record_identifier ?? "task-definition");
    if (change.change_type === "removed") return `ECS task definition ${tdName} was removed.`;
    if (change.change_type === "added")   return `ECS task definition ${tdName} was added.`;
    if (fp === "has_privileged_container") return `ECS task definition ${tdName} ${change.new_value ? "now has" : "no longer has"} a privileged container.`;
    if (fp === "secret_ref_count") return `ECS task definition ${tdName} secret reference count changed to ${change.new_value ?? "unknown"}.`;
    if (fp === "env_sensitive_key_count") return `ECS task definition ${tdName} sensitive environment key count changed.`;
    return `ECS task definition ${tdName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  // ── M46: EKS ──────────────────────────────────────────────────────────────
  if (rt === "aws_eks_cluster") {
    const eksName = rn || (change.record_identifier ?? "cluster");
    if (change.change_type === "removed") return `EKS cluster ${eksName} was removed from monitoring.`;
    if (change.change_type === "added")   return `EKS cluster ${eksName} was added.`;
    if (fp === "public_access_fully_open") return `EKS cluster ${eksName} public API endpoint is now ${change.new_value ? "unrestricted (0.0.0.0/0)" : "CIDR-restricted"}.`;
    if (fp === "endpoint_public_access") return `EKS cluster ${eksName} public API endpoint access was ${change.new_value ? "enabled" : "disabled"}.`;
    if (fp === "secrets_encryption_enabled") return `Kubernetes Secrets encryption at rest was ${change.new_value ? "enabled" : "disabled"} on EKS cluster ${eksName}.`;
    if (fp === "has_audit_logging") return `EKS cluster ${eksName} audit logging was ${change.new_value ? "enabled" : "disabled"}.`;
    if (fp === "kubernetes_version") return `EKS cluster ${eksName} Kubernetes version changed from ${change.prev_value ?? "?"} to ${change.new_value ?? "?"}.`;
    return `EKS cluster ${eksName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_eks_node_group") {
    const ngName = rn || (change.record_identifier ?? "node-group");
    if (change.change_type === "removed") return `EKS node group ${ngName} was removed.`;
    if (change.change_type === "added")   return `EKS node group ${ngName} was added.`;
    if (fp === "ssh_unrestricted") return `EKS node group ${ngName} ${change.new_value ? "now allows unrestricted SSH access" : "SSH access is now restricted"}.`;
    if (fp === "has_remote_access") return `EKS node group ${ngName} remote SSH access was ${change.new_value ? "enabled" : "disabled"}.`;
    return `EKS node group ${ngName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_eks_fargate_profile") {
    const fpName = rn || (change.record_identifier ?? "fargate-profile");
    if (change.change_type === "removed") return `EKS Fargate profile ${fpName} was removed.`;
    if (change.change_type === "added")   return `EKS Fargate profile ${fpName} was added.`;
    if (fp === "selector_namespaces") return `EKS Fargate profile ${fpName} target namespaces changed.`;
    return `EKS Fargate profile ${fpName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_eks_addon") {
    const addonName = rn || (change.record_identifier ?? "addon");
    if (change.change_type === "removed") return `EKS add-on ${addonName} was removed.`;
    if (change.change_type === "added")   return `EKS add-on ${addonName} was added.`;
    if (fp === "addon_version") return `EKS add-on ${addonName} version changed from ${change.prev_value ?? "?"} to ${change.new_value ?? "?"}.`;
    if (fp === "status") return `EKS add-on ${addonName} status changed to ${change.new_value ?? "unknown"}.`;
    return `EKS add-on ${addonName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  // ── M46: ECR ──────────────────────────────────────────────────────────────
  if (rt === "aws_ecr_repository") {
    const repoName = rn || (change.record_identifier ?? "repository");
    if (change.change_type === "removed") return `ECR repository ${repoName} was removed from monitoring.`;
    if (change.change_type === "added")   return `ECR repository ${repoName} was added.`;
    if (fp === "policy_is_public") return `ECR repository ${repoName} policy ${change.new_value ? "now grants external/public access" : "no longer grants external access"}.`;
    if (fp === "scan_on_push") return `ECR repository ${repoName} scan-on-push was ${change.new_value ? "enabled" : "disabled"}.`;
    if (fp === "tag_immutable") return `ECR repository ${repoName} image tags are now ${change.new_value ? "immutable" : "mutable"}.`;
    return `ECR repository ${repoName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_ecr_registry_scanning_config") {
    const scanName = rn || (change.record_identifier ?? "registry-scanning");
    if (change.change_type === "removed") return `ECR registry scanning configuration for ${scanName} was removed.`;
    if (change.change_type === "added")   return `ECR registry scanning configuration for ${scanName} was added.`;
    if (fp === "scan_type") return `ECR registry scanning type changed from ${change.prev_value ?? "unknown"} to ${change.new_value ?? "unknown"} in ${scanName}.`;
    if (fp === "rule_count") return `ECR registry scanning rule count changed to ${change.new_value ?? "unknown"} in ${scanName}.`;
    return `ECR registry scanning configuration changed in ${scanName}${fp ? ` (${fp})` : ""}.`;
  }

  // ── M47: EventBridge ──────────────────────────────────────────────────────
  if (rt === "aws_eventbridge_event_bus") {
    const busName = rn || (change.record_identifier ?? "event-bus");
    if (change.change_type === "removed") return `EventBridge event bus ${busName} was removed from monitoring.`;
    if (change.change_type === "added")   return `EventBridge event bus ${busName} was added.`;
    if (fp === "public_or_cross_account_policy") return `EventBridge event bus ${busName} policy ${change.new_value ? "now grants external/cross-account access" : "no longer grants external access"}.`;
    if (fp === "policy_present") return `EventBridge event bus ${busName} resource policy was ${change.new_value ? "added" : "removed"}.`;
    return `EventBridge event bus ${busName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_eventbridge_rule") {
    const ruleName = rn || (change.record_identifier ?? "rule");
    if (change.change_type === "removed") return `EventBridge rule ${ruleName} was removed from monitoring.`;
    if (change.change_type === "added")   return `EventBridge rule ${ruleName} was added.`;
    if (fp === "state") return `EventBridge rule ${ruleName} state changed to ${change.new_value ?? "unknown"}.`;
    if (fp === "target_count") return `EventBridge rule ${ruleName} target count changed to ${change.new_value ?? "unknown"}.`;
    if (fp === "event_pattern_hash") return `EventBridge rule ${ruleName} event pattern changed.`;
    if (fp === "dlq_target_present") return `EventBridge rule ${ruleName} dead-letter queue target was ${change.new_value ? "added" : "removed"}.`;
    return `EventBridge rule ${ruleName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_eventbridge_target") {
    const tgtName = rn || (change.record_identifier ?? "target");
    if (change.change_type === "removed") return `EventBridge target ${tgtName} was removed.`;
    if (change.change_type === "added")   return `EventBridge target ${tgtName} was added.`;
    if (fp === "target_type") return `EventBridge target ${tgtName} type changed to ${change.new_value ?? "unknown"}.`;
    if (fp === "dead_letter_config_present") return `EventBridge target ${tgtName} dead-letter queue was ${change.new_value ? "configured" : "removed"}.`;
    return `EventBridge target ${tgtName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_eventbridge_archive") {
    const archName = rn || (change.record_identifier ?? "archive");
    if (change.change_type === "removed") return `EventBridge archive ${archName} was removed.`;
    if (change.change_type === "added")   return `EventBridge archive ${archName} was added.`;
    if (fp === "state") return `EventBridge archive ${archName} state changed to ${change.new_value ?? "unknown"}.`;
    if (fp === "retention_days") return `EventBridge archive ${archName} retention changed to ${change.new_value ?? "unknown"} days.`;
    return `EventBridge archive ${archName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  // ── M47: SQS ──────────────────────────────────────────────────────────────
  if (rt === "aws_sqs_queue") {
    const queueName = rn || (change.record_identifier ?? "queue");
    if (change.change_type === "removed") return `SQS queue ${queueName} was removed from monitoring.`;
    if (change.change_type === "added")   return `SQS queue ${queueName} was added.`;
    if (fp === "public_or_cross_account_policy") return `SQS queue ${queueName} policy ${change.new_value ? "now grants external/cross-account access" : "no longer grants external access"}.`;
    if (fp === "sqs_managed_sse_enabled") return `SQS managed SSE ${change.new_value ? "enabled" : "disabled"} on queue ${queueName}.`;
    if (fp === "kms_master_key_id_present") return `KMS encryption ${change.new_value ? "enabled" : "removed"} on SQS queue ${queueName}.`;
    if (fp === "redrive_policy_present") return `SQS queue ${queueName} redrive/DLQ policy was ${change.new_value ? "added" : "removed"}.`;
    if (fp === "message_retention_period") return `SQS queue ${queueName} message retention period changed to ${change.new_value ?? "unknown"}s.`;
    if (fp === "visibility_timeout") return `SQS queue ${queueName} visibility timeout changed to ${change.new_value ?? "unknown"}s.`;
    return `SQS queue ${queueName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  // ── M47: SNS ──────────────────────────────────────────────────────────────
  if (rt === "aws_sns_topic") {
    const topicName = rn || (change.record_identifier ?? "topic");
    if (change.change_type === "removed") return `SNS topic ${topicName} was removed from monitoring.`;
    if (change.change_type === "added")   return `SNS topic ${topicName} was added.`;
    if (fp === "public_or_cross_account_policy") return `SNS topic ${topicName} policy ${change.new_value ? "now grants external/cross-account access" : "no longer grants external access"}.`;
    if (fp === "kms_master_key_id_present") return `KMS encryption ${change.new_value ? "enabled" : "removed"} on SNS topic ${topicName}.`;
    if (fp === "subscription_count") return `SNS topic ${topicName} subscription count changed to ${change.new_value ?? "unknown"}.`;
    if (fp === "subscription_protocol_counts") return `SNS topic ${topicName} subscription protocol distribution changed.`;
    return `SNS topic ${topicName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_sns_subscription") {
    const subName = rn || (change.record_identifier ?? "subscription");
    if (change.change_type === "removed") return `SNS subscription ${subName} was removed.`;
    if (change.change_type === "added")   return `SNS subscription ${subName} was added.`;
    if (fp === "endpoint_hash") return `SNS subscription ${subName} endpoint changed.`;
    if (fp === "protocol") return `SNS subscription ${subName} protocol changed to ${change.new_value ?? "unknown"}.`;
    if (fp === "filter_policy_hash") return `SNS subscription ${subName} filter policy changed.`;
    if (fp === "raw_message_delivery") return `SNS subscription ${subName} raw message delivery was ${change.new_value ? "enabled" : "disabled"}.`;
    return `SNS subscription ${subName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  // ── M48: KMS ──────────────────────────────────────────────────────────────
  if (rt === "aws_kms_key") {
    const keyId = rn || (change.record_identifier ?? "key");
    if (change.change_type === "removed") return `KMS key ${keyId} is no longer visible. Services that depend on it may fail to encrypt or decrypt data.`;
    if (change.change_type === "added")   return `KMS key ${keyId} was added to monitoring.`;
    if (fp === "enabled" && nv === false) return `KMS key ${keyId} was disabled. Resources using it may fail to encrypt or decrypt data.`;
    if (fp === "key_state" && String(nv).toUpperCase() === "PENDINGDELETION") return `KMS key ${keyId} is scheduled for deletion. Once deleted it cannot be recovered and all encrypted data may become permanently inaccessible.`;
    if (fp === "deletion_date_present" && nv === true) return `A deletion date was set on KMS key ${keyId}.`;
    if (fp === "public_or_cross_account_policy" && nv === true) return `KMS key ${keyId} policy now grants access to external accounts or wildcard principals.`;
    if (fp === "wildcard_admin_policy" && nv === true) return `KMS key ${keyId} policy now contains a wildcard-action grant for external principals.`;
    if (fp === "rotation_enabled" && nv === false) return `Automatic key rotation was disabled on KMS key ${keyId}.`;
    return `KMS key ${keyId} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_kms_alias") {
    const aliasName = rn || (change.record_identifier ?? "alias");
    if (change.change_type === "removed") return `KMS alias ${aliasName} was deleted.`;
    if (change.change_type === "added")   return `KMS alias ${aliasName} was created.`;
    if (fp === "target_key_id_hash") return `KMS alias ${aliasName} now points to a different key.`;
    if (fp === "target_key_present" && nv === false) return `KMS alias ${aliasName} target key is no longer visible.`;
    return `KMS alias ${aliasName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  // ── M48: Backup ────────────────────────────────────────────────────────────
  if (rt === "aws_backup_vault") {
    const vaultName = rn || (change.record_identifier ?? "vault");
    if (change.change_type === "removed") return `AWS Backup vault ${vaultName} is no longer visible.`;
    if (change.change_type === "added")   return `AWS Backup vault ${vaultName} was added to monitoring.`;
    if (fp === "locked" && nv === false) return `AWS Backup vault ${vaultName} vault lock was removed — the vault may now be deletable.`;
    if (fp === "backup_vault_lock_configuration_present" && nv === false) return `AWS Backup vault lock configuration was removed from ${vaultName}.`;
    if (fp === "encryption_key_arn_present" && nv === false) return `Encryption key was removed from AWS Backup vault ${vaultName}.`;
    if (fp === "recovery_points_count" && typeof nv === "number" && typeof pv === "number" && nv < (pv as number)) return `Recovery point count decreased in AWS Backup vault ${vaultName} (${String(pv)} → ${String(nv)}).`;
    return `AWS Backup vault ${vaultName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_backup_plan") {
    const planName = (change.provider_metadata?.backup_plan_name as string | undefined) ?? rn ?? (change.record_identifier ?? "plan");
    if (change.change_type === "removed") return `AWS Backup plan ${planName} was removed — associated resources may no longer be backed up.`;
    if (change.change_type === "added")   return `AWS Backup plan ${planName} was added to monitoring.`;
    if (fp === "rule_count" && typeof nv === "number" && typeof pv === "number" && nv < (pv as number)) return `Backup rule count decreased on plan ${planName} (${String(pv)} → ${String(nv)}).`;
    if (fp === "continuous_backup_enabled_count" && nv === 0) return `All continuous backup rules were removed from backup plan ${planName}.`;
    if (fp === "lifecycle_delete_after_days_min" && nv === 0) return `Backup plan ${planName} has a rule that deletes recovery points immediately.`;
    return `AWS Backup plan ${planName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_backup_selection") {
    const selName = rn || (change.record_identifier ?? "selection");
    if (change.change_type === "removed") return `AWS Backup selection ${selName} was removed — some resources may no longer be included in a backup plan.`;
    if (change.change_type === "added")   return `AWS Backup selection ${selName} was added to monitoring.`;
    if (fp === "resource_count" && typeof nv === "number" && typeof pv === "number" && nv < (pv as number)) return `Resources covered by backup selection ${selName} decreased (${String(pv)} → ${String(nv)}).`;
    return `AWS Backup selection ${selName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_backup_recovery_point") {
    const rpId = rn || (change.record_identifier ?? "recovery-point");
    if (change.change_type === "removed") return `AWS Backup recovery point ${rpId} is no longer visible.`;
    if (change.change_type === "added")   return `AWS Backup recovery point ${rpId} was detected.`;
    if (fp === "status" && ["EXPIRED","DELETING","DELETED"].includes(String(nv).toUpperCase())) return `AWS Backup recovery point ${rpId} status changed to ${String(nv)}.`;
    if (fp === "is_encrypted" && nv === false) return `AWS Backup recovery point ${rpId} is not encrypted.`;
    return `AWS Backup recovery point ${rpId} configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  // ── M48: Organizations ─────────────────────────────────────────────────────
  if (rt === "aws_organizations_organization") {
    if (change.change_type === "removed") return "AWS Organizations organization record is no longer visible.";
    if (change.change_type === "added")   return "AWS Organizations organization was added to monitoring.";
    if (fp === "feature_set") return `AWS Organizations feature set changed from ${String(pv)} to ${String(nv)}.`;
    if (fp === "scp_count" && typeof nv === "number" && typeof pv === "number" && nv < (pv as number)) return `Service Control Policy count decreased in AWS Organizations (${String(pv)} → ${String(nv)}).`;
    if (fp === "policy_types_summary") return "AWS Organizations enabled policy types changed.";
    return `AWS Organizations organization configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_organizations_account") {
    const acctId = rn || (change.record_identifier ?? "account");
    if (change.change_type === "removed") return `AWS Organizations member account ${acctId} is no longer visible.`;
    if (change.change_type === "added")   return `AWS Organizations member account ${acctId} was added to monitoring.`;
    if (fp === "status" && ["SUSPENDED","PENDING_CLOSURE","CLOSED"].includes(String(nv).toUpperCase())) return `AWS Organizations member account ${acctId} status changed to ${String(nv)}.`;
    if (fp === "status") return `AWS Organizations member account ${acctId} status changed to ${String(nv)}.`;
    return `AWS Organizations member account ${acctId} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_organizations_ou") {
    const ouId = rn || (change.record_identifier ?? "OU");
    if (change.change_type === "removed") return `AWS Organizations OU ${ouId} is no longer visible.`;
    if (change.change_type === "added")   return `AWS Organizations OU ${ouId} was added to monitoring.`;
    if (fp === "attached_scp_count" && typeof nv === "number" && typeof pv === "number" && nv < (pv as number)) return `SCP count on OU ${ouId} decreased (${String(pv)} → ${String(nv)}).`;
    if (fp === "parent_id_hash") return `OU ${ouId} was moved to a different parent.`;
    return `AWS Organizations OU ${ouId} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_organizations_scp") {
    const scpName = (change.provider_metadata?.policy_name as string | undefined) ?? rn ?? (change.record_identifier ?? "SCP");
    if (change.change_type === "removed") return `Service Control Policy ${scpName} was removed — guardrails it enforced may no longer be in effect.`;
    if (change.change_type === "added")   return `Service Control Policy ${scpName} was added to monitoring.`;
    if (fp === "denies_full_admin_escape" && nv === false) return `SCP ${scpName} no longer prevents privilege-escalation to full admin.`;
    if (fp === "denied_action_count" && typeof nv === "number" && typeof pv === "number" && nv < (pv as number)) return `Denied action count in SCP ${scpName} decreased (${String(pv)} → ${String(nv)}).`;
    if (fp === "deny_statement_count" && typeof nv === "number" && typeof pv === "number" && nv < (pv as number)) return `Deny statement count in SCP ${scpName} decreased (${String(pv)} → ${String(nv)}).`;
    if (fp === "attached_target_count" && typeof nv === "number" && typeof pv === "number" && nv < (pv as number)) return `SCP ${scpName} is now attached to fewer targets (${String(pv)} → ${String(nv)}).`;
    return `Service Control Policy ${scpName} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "aws_organizations_scp_attachment") {
    const attachName = (change.provider_metadata?.policy_name as string | undefined) ?? rn ?? (change.record_identifier ?? "SCP attachment");
    if (change.change_type === "removed") return `SCP attachment for ${attachName} was removed — that policy's guardrails no longer apply to the target.`;
    if (change.change_type === "added")   return `SCP ${attachName} was attached to a new target.`;
    return `SCP attachment for ${attachName} changed${fp ? ` (${fp})` : ""}.`;
  }

  // ── M49: CloudWatch Alarms + Observability ─────────────────────────────────
  if (rt === "aws_cloudwatch_metric_alarm") {
    if (change.change_type === "added")   return `CloudWatch metric alarm "${rn}" was created.`;
    if (change.change_type === "removed") return `CloudWatch metric alarm "${rn}" was removed — monitoring coverage may have changed.`;
    if (fp === "actions_enabled")         return `CloudWatch alarm "${rn}" actions were ${change.new_value === false ? "disabled" : "re-enabled"}.`;
    if (fp === "alarm_state_value")       return `CloudWatch alarm "${rn}" state changed to ${String(change.new_value ?? "unknown")}.`;
    if (fp === "threshold")               return `CloudWatch alarm "${rn}" threshold changed from ${change.prev_value} to ${change.new_value}.`;
    return `CloudWatch metric alarm "${rn}" configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt === "aws_cloudwatch_composite_alarm") {
    if (change.change_type === "added")   return `CloudWatch composite alarm "${rn}" was created.`;
    if (change.change_type === "removed") return `CloudWatch composite alarm "${rn}" was removed.`;
    if (fp === "actions_enabled")         return `CloudWatch composite alarm "${rn}" actions were ${change.new_value === false ? "disabled" : "re-enabled"}.`;
    if (fp === "alarm_rule_hash")         return `CloudWatch composite alarm "${rn}" rule expression changed.`;
    return `CloudWatch composite alarm "${rn}" configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt === "aws_cloudwatch_dashboard") {
    if (change.change_type === "added")   return `CloudWatch dashboard "${rn}" was created.`;
    if (change.change_type === "removed") return `CloudWatch dashboard "${rn}" was removed.`;
    if (fp === "dashboard_body_hash")     return `CloudWatch dashboard "${rn}" content changed (body hash updated).`;
    return `CloudWatch dashboard "${rn}" configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt === "aws_cloudwatch_log_group") {
    if (change.change_type === "added")   return `CloudWatch Logs log group "${rn}" was created.`;
    if (change.change_type === "removed") return `CloudWatch Logs log group "${rn}" was removed.`;
    if (fp === "retention_configured" && change.new_value === false) return `CloudWatch Logs log group "${rn}" retention policy was removed — logs will be kept indefinitely.`;
    if (fp === "retention_in_days")       return `CloudWatch Logs log group "${rn}" retention changed from ${change.prev_value} to ${change.new_value} days.`;
    if (fp === "kms_key_id_present" && change.new_value === false) return `CloudWatch Logs log group "${rn}" KMS encryption was removed.`;
    return `CloudWatch Logs log group "${rn}" configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt === "aws_cloudwatch_metric_filter") {
    if (change.change_type === "added")   return `CloudWatch Logs metric filter "${rn}" was created.`;
    if (change.change_type === "removed") return `CloudWatch Logs metric filter "${rn}" was removed.`;
    if (fp === "filter_pattern_hash")     return `CloudWatch Logs metric filter "${rn}" pattern changed (hash updated).`;
    return `CloudWatch Logs metric filter "${rn}" configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt === "aws_cloudwatch_subscription_filter") {
    if (change.change_type === "added")   return `CloudWatch Logs subscription filter "${rn}" was created.`;
    if (change.change_type === "removed") return `CloudWatch Logs subscription filter "${rn}" was removed — log streaming may have stopped.`;
    if (fp === "destination_type")        return `CloudWatch Logs subscription filter "${rn}" destination type changed to ${String(change.new_value ?? "unknown")}.`;
    return `CloudWatch Logs subscription filter "${rn}" configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt === "aws_cloudwatch_metric_stream") {
    if (change.change_type === "added")   return `CloudWatch metric stream "${rn}" was created.`;
    if (change.change_type === "removed") return `CloudWatch metric stream "${rn}" was removed.`;
    if (fp === "state")                   return `CloudWatch metric stream "${rn}" state changed to ${String(change.new_value ?? "unknown")}.`;
    return `CloudWatch metric stream "${rn}" configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt === "aws_cloudwatch_anomaly_detector") {
    if (change.change_type === "added")   return `CloudWatch anomaly detector "${rn}" was created.`;
    if (change.change_type === "removed") return `CloudWatch anomaly detector "${rn}" was removed.`;
    if (fp === "state")                   return `CloudWatch anomaly detector "${rn}" state changed to ${String(change.new_value ?? "unknown")}.`;
    return `CloudWatch anomaly detector "${rn}" configuration changed${fp ? ` (${fp})` : ""}.`;
  }

  if (rt.startsWith("aws_")) {
    return `An AWS configuration record changed (${rt}).`;
  }

  // Firebase
  if (rt === "firebase_project") {
    if (change.change_type === "added")   return "Firebase project was added to monitoring.";
    if (change.change_type === "removed") return "Firebase project was removed from monitoring.";
    return `Firebase project settings changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "firebase_auth_config") {
    if (fp === "sign_in_providers") return `Firebase Auth sign-in providers changed${fp ? "" : ""}.`;
    return `Firebase Auth configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "firebase_auth_provider") {
    if (change.change_type === "added")   return `Firebase Auth provider ${rn || change.record_identifier} was enabled.`;
    if (change.change_type === "removed") return `Firebase Auth provider ${rn || change.record_identifier} was disabled.`;
    return `Firebase Auth provider configuration changed for ${rn || change.record_identifier}${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "firebase_authorized_domain") {
    if (change.change_type === "added")   return `Domain ${rn || change.record_identifier} was added to Firebase Auth authorized domains.`;
    if (change.change_type === "removed") return `Domain ${rn || change.record_identifier} was removed from Firebase Auth authorized domains.`;
    return `Firebase authorized domain changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "firebase_firestore_ruleset") {
    if (change.change_type === "added")   return "A new Firestore security ruleset was deployed.";
    if (change.change_type === "removed") return "A Firestore security ruleset was removed.";
    if (fp === "rules_hash") return "The Firestore security ruleset content changed.";
    return `Firestore security ruleset configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "firebase_storage_bucket") {
    if (change.change_type === "added")   return `Firebase Storage bucket ${rn || change.record_identifier} was added to monitoring.`;
    if (change.change_type === "removed") return `Firebase Storage bucket ${rn || change.record_identifier} was removed.`;
    return `Firebase Storage bucket ${rn || change.record_identifier} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "firebase_storage_ruleset") {
    if (change.change_type === "added")   return "A new Firebase Storage security ruleset was deployed.";
    if (change.change_type === "removed") return "A Firebase Storage security ruleset was removed.";
    if (fp === "rules_hash") return "Firebase Storage security ruleset content changed.";
    return `Firebase Storage security ruleset changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "firebase_hosting_site") {
    if (change.change_type === "added")   return `Firebase Hosting site ${rn || change.record_identifier} was added to monitoring.`;
    if (change.change_type === "removed") return `Firebase Hosting site ${rn || change.record_identifier} was removed.`;
    return `Firebase Hosting site ${rn || change.record_identifier} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "firebase_hosting_domain") {
    if (change.change_type === "added")   return `Custom domain ${rn || change.record_identifier} was added to Firebase Hosting.`;
    if (change.change_type === "removed") return `Custom domain ${rn || change.record_identifier} was removed from Firebase Hosting.`;
    return `Firebase Hosting domain ${rn || change.record_identifier} changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "firebase_function_metadata") {
    if (change.change_type === "added")   return `Cloud Function ${rn || change.record_identifier} was added.`;
    if (change.change_type === "removed") return `Cloud Function ${rn || change.record_identifier} was removed.`;
    return `Cloud Function ${rn || change.record_identifier} metadata changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt.startsWith("firebase_")) {
    return `A Firebase configuration record changed (${rt}).`;
  }

  // Supabase
  if (rt === "supabase_project") {
    if (change.change_type === "added")   return "Supabase project was added to monitoring.";
    if (change.change_type === "removed") return "Supabase project was removed from monitoring.";
    if (fp === "status") return `Supabase project status changed to ${String(nv)}.`;
    return `Supabase project settings changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "supabase_auth_config") {
    if (fp === "external_email_enabled" && nv === false) return "Email authentication was disabled in Supabase Auth.";
    if (fp === "mfa_totp_enabled" && nv === false) return "TOTP multi-factor authentication was disabled in Supabase Auth.";
    if (fp === "jwt_verification") return "Supabase JWT verification setting changed.";
    if (fp === "password_min_length") return `Supabase Auth minimum password length changed to ${String(nv)}.`;
    return `Supabase Auth configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "supabase_oauth_provider") {
    if (change.change_type === "added")   return `OAuth provider ${rn || change.record_identifier} was enabled in Supabase Auth.`;
    if (change.change_type === "removed") return `OAuth provider ${rn || change.record_identifier} was disabled in Supabase Auth.`;
    return `Supabase OAuth provider ${rn || change.record_identifier} configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "supabase_database_config") {
    return `Supabase database configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "supabase_storage_config") {
    return `Supabase Storage configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "supabase_edge_function") {
    if (change.change_type === "added")   return `Edge Function ${rn || change.record_identifier} was deployed to Supabase.`;
    if (change.change_type === "removed") return `Edge Function ${rn || change.record_identifier} was removed from Supabase.`;
    return `Supabase Edge Function ${rn || change.record_identifier} metadata changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "supabase_rls_status") {
    if (fp === "rls_enabled" && nv === false) return `Row Level Security was disabled on a Supabase table.`;
    if (fp === "rls_enabled" && nv === true)  return `Row Level Security was enabled on a Supabase table.`;
    if (fp === "rls_forced" && nv === false)  return `RLS enforcement was relaxed on a Supabase table.`;
    return `Supabase RLS status changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "supabase_api_config") {
    return `Supabase API configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "supabase_network_restriction") {
    if (change.change_type === "added")   return "Network restrictions were added to this Supabase project.";
    if (change.change_type === "removed") return "Network restrictions were removed from this Supabase project — the database is now reachable from any IP.";
    if (fp === "allowed_cidrs") return "The list of allowed IP ranges for this Supabase project changed.";
    return `Supabase network restriction changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "supabase_custom_domain") {
    if (change.change_type === "added")   return `Custom domain ${rn || change.record_identifier} was configured for this Supabase project.`;
    if (change.change_type === "removed") return `Custom domain was removed from this Supabase project.`;
    return `Supabase custom domain configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt.startsWith("supabase_")) {
    return `A Supabase configuration record changed (${rt}).`;
  }

  // Shopify
  if (rt === "shopify_shop_metadata") {
    if (fp === "password_protected" && nv === true)  return "Shopify storefront password protection was enabled.";
    if (fp === "password_protected" && nv === false) return "Shopify storefront password protection was disabled — the store is now publicly accessible.";
    if (fp === "plan_name")   return `Shopify store plan changed to ${String(nv)}.`;
    if (fp === "currency")    return `Shopify store default currency changed to ${String(nv)}.`;
    if (fp === "timezone")    return `Shopify store timezone changed to ${String(nv)}.`;
    return `Shopify store settings changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "shopify_webhook_subscription") {
    const hookTopic = rn || change.record_identifier;
    if (change.change_type === "added")   return `Shopify webhook subscription for ${hookTopic} was added.`;
    if (change.change_type === "removed") return `Shopify webhook subscription for ${hookTopic} was removed.`;
    if (fp === "address") return `Shopify webhook delivery URL changed for ${hookTopic}.`;
    if (fp === "format")  return `Shopify webhook format changed for ${hookTopic}.`;
    return `Shopify webhook subscription changed for ${hookTopic}${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "shopify_store_policy") {
    const policyName = rn || change.record_identifier;
    if (change.change_type === "added")   return `Shopify store policy ${policyName} was added.`;
    if (change.change_type === "removed") return `Shopify store policy ${policyName} was removed.`;
    if (fp === "content_hash") return `Shopify store policy content changed for ${policyName}.`;
    return `Shopify store policy ${policyName} changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "shopify_app_scope_summary") {
    if (change.change_type === "added")   return "Shopify app permission scopes were recorded.";
    if (change.change_type === "removed") return "Shopify app permission scopes record was removed.";
    if (fp === "scope_count") return `Shopify app permission scope count changed to ${String(nv)}.`;
    if (fp === "scopes")      return "Shopify app permission scopes changed.";
    return `Shopify app permission scope configuration changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt.startsWith("shopify_")) {
    return `A Shopify configuration record changed (${rt}).`;
  }

  // Cloudflare DNS
  const recordLabel = rn
    ? `${(change.provider_metadata?.record_type as string | undefined) ?? ""} ${rn}`.trim()
    : change.record_identifier;

  if (change.change_type === "removed") return `${recordLabel} was removed from Cloudflare DNS.`;
  if (change.change_type === "added")   return `${recordLabel} was added to Cloudflare DNS.`;
  if (fp === "content") {
    const recType = ((change.provider_metadata?.record_type as string | undefined) ?? "").toUpperCase();
    if (recType === "CNAME") return `The CNAME target for ${rn || change.record_identifier} changed.`;
    if (recType === "A" || recType === "AAAA") return `The IP address for ${rn || change.record_identifier} changed.`;
  }
  return `${recordLabel} was modified.`;
}

// ── Why it matters ───────────────────────────────────────────────────────────

/**
 * Provider-specific explanation of why this change category matters
 * from a security/ops perspective. Uses may/could language.
 * Returns null for trivial resource-type changes with no meaningful context.
 */
function getWhyItMatters(change: ChangeDetail): string | null {
  const rt = (
    (change.provider_metadata?.record_type as string | undefined) ?? ""
  ).toLowerCase();
  const fp = change.field_path ?? "";
  const nv = change.new_value;

  // ── AWS ──────────────────────────────────────────────────────────────
  if (rt === "aws_security_group" || rt === "aws_security_group_rule") {
    if (["has_public_ssh", "has_public_rdp", "has_public_database_port", "has_public_inbound"].includes(fp)) {
      return "Security group rule changes that open public ports may expose services attached to this group to the internet. Actual exposure depends on subnet, route table, public IP assignment, and resource attachment context.";
    }
    return "Security group changes affect inbound and outbound traffic rules for all resources attached to this group. Inbound rule additions can expand the network attack surface.";
  }
  if (rt.startsWith("aws_iam_")) {
    return "Identity and access changes can affect who can read, write, or administer production resources. IAM changes should always be tied to an expected, authorized activity and reviewed for least-privilege compliance.";
  }
  if (rt === "aws_s3_bucket") {
    if ((fp.includes("public") || fp.includes("acl")) && nv === true) {
      return "Public access changes on S3 buckets may expose objects stored in the bucket to anyone on the internet, depending on bucket policy and Block Public Access settings.";
    }
    if (fp === "encryption_enabled" && nv === false) {
      return "Disabling default encryption means future objects written to this bucket will not be encrypted at rest unless the uploading client explicitly specifies encryption.";
    }
    return "S3 bucket configuration changes can affect data access, encryption, versioning, and compliance posture for all objects stored in the bucket.";
  }
  if (rt.startsWith("aws_route53_") || rt === "aws_cloudfront_distribution") {
    return "DNS and CDN changes can affect how traffic routes to your application, service availability, and domain ownership verification. Unexpected changes may redirect users or cause service outages.";
  }
  if (rt.startsWith("aws_cloudtrail_") || rt.startsWith("aws_guardduty_") || rt.startsWith("aws_securityhub_")) {
    return "Detection and audit infrastructure changes can reduce visibility into security events. Disabling or modifying audit tools makes it harder to investigate incidents and may leave gaps in compliance coverage.";
  }
  if (rt.startsWith("aws_kms_")) {
    return "KMS key configuration changes can affect encryption for many dependent services including S3, RDS, Lambda, and Secrets Manager. Key deletion or policy changes may be irreversible and could make encrypted data permanently inaccessible.";
  }
  if (rt.startsWith("aws_lambda_")) {
    return "Lambda function changes can affect execution behavior, access to private resources, and security posture. Role, VPC, URL authentication, and environment key changes are especially sensitive.";
  }
  if (rt.startsWith("aws_rds_")) {
    return "Database configuration changes can affect data availability, encryption at rest, access controls, and disaster recovery posture. Changes to public accessibility or deletion protection should be reviewed carefully.";
  }
  if (rt.startsWith("aws_elbv2_") || rt === "aws_elb_classic_load_balancer") {
    return "Load balancer changes affect how traffic is distributed to backend services. Scheme changes from internal to internet-facing can expose previously private services. Listener and security group changes affect both availability and security.";
  }
  if (rt.startsWith("aws_apigateway")) {
    return "API Gateway configuration affects how client requests reach your backend services. Authorizer removal, routing, and logging changes can affect both authentication security and operational observability.";
  }
  if (rt.startsWith("aws_wafv2_")) {
    return "WAF configuration changes affect protection against web-layer attacks. Removing rules or disabling logging can reduce defense-in-depth and audit coverage for your API or application.";
  }
  if (rt.startsWith("aws_organizations_")) {
    return "AWS Organizations and SCP changes affect governance guardrails across all member accounts. Removing or modifying SCPs can allow previously blocked API actions throughout your organization hierarchy.";
  }
  if (rt.startsWith("aws_backup_")) {
    return "Backup configuration changes can affect data recoverability. Removing backup plans, vault locks, or recovery points could leave workloads without a recovery path in a disaster scenario.";
  }
  if (rt.startsWith("aws_cloudwatch_")) {
    return "CloudWatch configuration changes can affect monitoring, alerting, and log retention. Removing alarms or disabling access logging reduces operational visibility and incident response capability.";
  }
  if (rt.startsWith("aws_ecs_") || rt.startsWith("aws_eks_") || rt.startsWith("aws_ecr_")) {
    return "Container infrastructure changes can affect workload security and runtime isolation. Public IP assignment, privileged container flags, image scan settings, and public endpoint exposure are especially sensitive.";
  }
  if (rt.startsWith("aws_eventbridge_") || rt.startsWith("aws_sqs_") || rt.startsWith("aws_sns_")) {
    return "Messaging infrastructure changes can affect event routing, data delivery, and service integrations. Cross-account policy changes may allow external principals to publish or receive events from your queues and topics.";
  }
  if (rt.startsWith("aws_secretsmanager_") || rt.startsWith("aws_ssm_")) {
    return "Secrets and parameter store changes can affect how applications retrieve credentials or configuration. ConfigTrace monitors metadata only and never reads secret values. Rotation disablement or scheduled deletion should be reviewed carefully.";
  }
  if (rt.startsWith("aws_vpc") || rt.startsWith("aws_subnet") ||
      rt.startsWith("aws_route") || rt === "aws_internet_gateway" ||
      rt === "aws_network_acl") {
    return "Network configuration changes affect how traffic flows between resources, subnets, and the internet. Route table and internet gateway changes can make previously private resources publicly reachable.";
  }
  if (rt.startsWith("aws_")) {
    return "AWS configuration changes may affect security posture, compliance, or service behavior for connected resources.";
  }

  // ── Firebase ──────────────────────────────────────────────────────────
  if (rt === "firebase_firestore_ruleset") {
    return "Firestore rules control client-side access to database documents. Broad rules may allow unintended reads or writes by any authenticated or unauthenticated user — without affecting server-side admin SDK access.";
  }
  if (rt === "firebase_storage_ruleset") {
    return "Storage rules control access to uploaded files. Broad rules may expose files to unauthorized users or allow unwanted uploads from unauthenticated clients.";
  }
  if (rt === "firebase_auth_config" || rt === "firebase_auth_provider") {
    return "Auth configuration changes affect how users can sign in to your app. Enabling anonymous auth or additional sign-in providers can expand the authentication surface if not intentional.";
  }
  if (rt === "firebase_authorized_domain") {
    return "Authorized domains affect where Firebase Auth sign-in flows can be initiated. Adding unrecognized domains may allow auth flows from origins your team does not control.";
  }
  if (rt.startsWith("firebase_")) {
    return "Firebase configuration changes can affect authentication, database access, hosting, and function behavior for your application.";
  }

  // ── Supabase ──────────────────────────────────────────────────────────
  if (rt === "supabase_rls_status") {
    if (fp === "rls_enabled" && nv === false) {
      return "RLS controls row-level access through the Supabase API. Disabling it may allow any authenticated or anonymous user to read or write all rows in this table, depending on applied policies and API exposure.";
    }
    return "RLS status changes affect access control for this table through the Supabase API and client libraries.";
  }
  if (rt === "supabase_auth_config") {
    if (fp === "jwt_verification") {
      return "JWT verification helps protect Edge Functions and API routes from unauthenticated requests. Disabling it may expose functions to callers without a valid session.";
    }
    return "Supabase Auth configuration changes affect how users authenticate and what session properties are enforced across your application.";
  }
  if (rt === "supabase_network_restriction") {
    return "Network restrictions control which IP ranges can connect to the Supabase database directly. Removing restrictions may allow connections from any IP address.";
  }
  if (rt === "supabase_edge_function") {
    return "Edge Function changes affect serverless functionality running close to users. JWT verification and deployment changes can affect security and availability.";
  }
  if (rt.startsWith("supabase_")) {
    return "Supabase configuration changes can affect authentication, database access controls, storage policies, and function behavior.";
  }

  // ── GitHub ────────────────────────────────────────────────────────────
  if (rt === "github_branch_protection") {
    return "Branch protection changes can weaken code review and deployment controls. Removing required approvals or status checks may allow code to be merged or deployed without proper peer review.";
  }
  if (rt === "github_webhook") {
    return "Webhook changes can affect CI/CD pipelines, security integrations, and third-party automations. Unexpected endpoint URL changes may indicate an unauthorized configuration modification or supply chain risk.";
  }
  if (rt === "github_actions_secret") {
    return "Actions secrets are used in CI/CD workflows for authentication and deployment. Unintended rotation or deletion may break pipelines or indicate that a credential was exposed.";
  }
  if (rt === "github_deploy_key") {
    return "Deploy keys grant repository read (or write) access. Write-enabled keys can push code directly to the repository. Unexpected key additions should be investigated immediately.";
  }
  if (rt === "github_environment_protection") {
    return "Environment protection rules control which branches can deploy to an environment and may require designated reviewers. Removing or weakening rules can allow deployments without approval gates.";
  }
  if (rt === "github_repo_settings") {
    if (fp === "visibility") {
      return "Repository visibility changes affect who can view the source code and its history. Making a private repository public could expose proprietary code, credentials, or sensitive commit history.";
    }
    return "Repository setting changes can affect access control, branch policies, integrations, and deployment pipelines.";
  }
  if (rt.startsWith("github_")) {
    return "GitHub configuration changes can affect code security, CI/CD pipelines, and repository access control.";
  }

  // ── Vercel ────────────────────────────────────────────────────────────
  if (rt === "vercel_domain") {
    return "Domain changes affect production routing. Removing or modifying domains can break live deployments and make your app unreachable at its expected URL.";
  }
  if (rt === "vercel_deploy_hook_metadata") {
    return "Deploy hooks allow external services to trigger Vercel deployments. Adding or removing hooks affects which systems can initiate production deployments, and unexpected hook additions may indicate an unauthorized pipeline modification.";
  }
  if (rt === "vercel_env_var") {
    return "Environment variable metadata changes can indicate deployment configuration drift. ConfigTrace monitors key names and metadata only — variable values are never read or stored.";
  }
  if (rt === "vercel_project") {
    if (fp === "sso_protection" || fp === "password_protection") {
      return "Access protection changes affect whether deployment previews and branch deployments are publicly accessible. Disabling protection may expose preview environments to unintended visitors.";
    }
    return "Vercel project setting changes can affect build behavior, production branch routing, and deployment configuration.";
  }
  if (rt.startsWith("vercel_")) {
    return "Vercel configuration changes can affect how your application is built, deployed, and served to users.";
  }

  // ── Stripe ────────────────────────────────────────────────────────────
  if (rt === "stripe_webhook_endpoint") {
    return "Webhook endpoint changes can break payment fulfillment, subscription lifecycle events, and financial reconciliation. An unexpected URL change may indicate an unauthorized modification to payment event delivery.";
  }
  if (rt === "stripe_account_settings") {
    if (fp === "charges_enabled" || fp === "payouts_enabled") {
      return "Enabling or disabling charges or payouts affects whether your Stripe account can process payments or transfer funds. These changes can have immediate business impact.";
    }
    return "Stripe account setting changes can affect payment processing, payout schedules, and how customers interact with your checkout flows.";
  }
  if (rt === "stripe_billing_portal_config") {
    return "Billing portal configuration determines what subscription and payment management options are available to customers. Changes may affect customers' ability to update payment methods or cancel subscriptions.";
  }
  if (rt.startsWith("stripe_payment_")) {
    return "Payment method configuration changes affect which payment options are available to customers at checkout. Removing methods may reduce checkout completion rates.";
  }
  if (rt.startsWith("stripe_")) {
    return "Stripe configuration changes can affect payment processing, webhook delivery, and account behavior.";
  }

  // ── Cloudflare ────────────────────────────────────────────────────────
  if (rt.startsWith("cloudflare_firewall_") || rt.startsWith("cloudflare_ssl_") ||
      rt.startsWith("cloudflare_zone_") || rt.startsWith("cloudflare_page_")) {
    return "Edge security settings affect how traffic reaches your application at the CDN layer. Firewall, SSL/TLS, and zone setting changes can expose or restrict services for all requests through Cloudflare.";
  }
  // Bare DNS record types (A, CNAME, MX, TXT, etc.) have no underscore in record_type
  if (!rt.includes("_") || rt.startsWith("cloudflare_dns_")) {
    const recType = ((change.provider_metadata?.record_type as string | undefined) ?? "").toUpperCase();
    if (recType === "MX" || recType === "TXT") {
      return "Email authentication record changes (MX, SPF, DKIM, DMARC) can affect mail deliverability and email spoofing protections. Changes should be verified against your email provider's expected configuration.";
    }
    return "DNS changes can affect where traffic for this hostname is routed. Unintended changes may cause service outages or redirect users to unexpected destinations.";
  }
  if (rt.startsWith("cloudflare_")) {
    return "Cloudflare configuration changes affect how traffic is routed, secured, and delivered for your domain.";
  }

  // ── Shopify ───────────────────────────────────────────────────────────
  if (rt === "shopify_shop_metadata") {
    if (fp === "password_protected") {
      return nv === false
        ? "Disabling storefront password protection makes your store publicly accessible to all visitors without restriction."
        : "Storefront password protection limits who can browse the store — useful for pre-launch or private stores.";
    }
    return "Shopify store settings affect storefront accessibility, regional configuration, and how customers interact with your store.";
  }
  if (rt === "shopify_webhook_subscription") {
    return "Webhook endpoint changes can affect order fulfillment integrations, inventory sync, and third-party automations. An unexpected URL change may indicate an unauthorized modification to event delivery.";
  }
  if (rt === "shopify_app_scope_summary") {
    return "App permission scopes define what data a Shopify app can access. Scope changes should correspond to an authorized app update or installation.";
  }
  if (rt.startsWith("shopify_")) {
    return "Shopify configuration changes can affect storefront accessibility, order integrations, and store policies.";
  }

  return null;
}

/** Suggested next steps for high/critical changes. Returns [] for low/medium. */
function getSuggestedChecks(change: ChangeDetail): string[] {
  const riskKey = (change.risk_level ?? "").toLowerCase();
  if (riskKey === "low" || riskKey === "unknown") return [];

  const rt = (
    (change.provider_metadata?.record_type as string | undefined) ?? ""
  ).toLowerCase();

  // For medium risk: concise per-provider checklist
  if (riskKey === "medium") {
    if (rt.startsWith("aws_"))        return ["Confirm this AWS change was expected.", "Check AWS CloudTrail for who made the change.", "Review the affected resource in the AWS Console."];
    if (rt.startsWith("github_"))     return ["Confirm this GitHub change was intentional.", "Review the GitHub repository audit log.", "Verify workflows and deployments still pass."];
    if (rt.startsWith("vercel_"))     return ["Confirm this Vercel change was intentional.", "Verify recent deployments are functioning correctly.", "Review the affected setting in the Vercel Dashboard."];
    if (rt.startsWith("stripe_"))     return ["Confirm this Stripe change was intentional.", "Verify payment and checkout flows are working.", "Review the Stripe Dashboard for related settings."];
    if (rt.startsWith("firebase_"))   return ["Confirm this Firebase change was intentional.", "Review the affected setting in the Firebase Console.", "Verify app functionality is not affected."];
    if (rt.startsWith("supabase_"))   return ["Confirm this Supabase change was intentional.", "Review the Supabase Dashboard for the affected setting.", "Verify database connectivity and auth are functioning."];
    if (rt.startsWith("shopify_"))    return ["Confirm this Shopify change was intentional.", "Review the Shopify Admin → Settings for affected configuration.", "Verify storefront and webhook integrations are functioning correctly."];
    return ["Confirm this change was intentional.", "Test DNS resolution for the affected hostname.", "Check Cloudflare audit logs for who made the change."];
  }

  if (rt === "github_actions_secret") {
    return [
      "Confirm the rotation was intentional.",
      "Verify workflows or deployments using this secret still pass.",
      "Check GitHub audit logs for who made the change.",
      "Roll back or update dependent services if needed.",
    ];
  }
  if (rt === "github_webhook") {
    return [
      "Confirm the change was intentional.",
      "Verify the webhook endpoint is under your control.",
      "Check GitHub audit logs for who made the change.",
      "Test that events are being received by the correct endpoint.",
      "Restore the previous URL if this was accidental.",
    ];
  }
  if (rt === "github_branch_protection") {
    return [
      "Confirm the change was intentional.",
      "Review branch protection rules in GitHub repository settings.",
      "Check GitHub audit logs for who made the change.",
      "Verify that CI/CD gates and merge requirements are still in place.",
      "Re-enable protection if this was accidental.",
    ];
  }
  if (rt === "github_repo_settings") {
    return [
      "Confirm this change was intentional.",
      "Review whether sensitive data or proprietary code may be exposed.",
      "Check GitHub audit logs for who made the change.",
      "Change visibility back to private if this was accidental.",
    ];
  }
  if (rt === "github_environment_protection") {
    return [
      "Confirm the environment protection rule change was intentional.",
      "Review GitHub → Repository settings → Environments for current rules.",
      "Verify required reviewers and branch restrictions are still appropriate.",
      "Check GitHub audit logs for who changed the protection rule.",
      "Re-enable protection rules if this was accidental.",
    ];
  }
  if (rt.startsWith("github_")) {
    return [
      "Confirm the change was intentional.",
      "Review GitHub repository settings.",
      "Check GitHub audit logs for who made the change.",
      "Verify workflows and deployments still pass.",
      "Restore the previous setting if this was accidental.",
    ];
  }

  // Vercel
  if (rt === "vercel_project") {
    const fp2 = change.field_path ?? "";
    if (fp2 === "sso_protection" && !change.new_value) {
      return [
        "Confirm SSO protection was intentionally disabled.",
        "Verify all deployment URLs are still restricted to intended users.",
        "Check the Vercel project protection settings in the Vercel dashboard.",
        "Re-enable SSO protection if this was accidental.",
      ];
    }
    if (fp2 === "password_protection" && !change.new_value) {
      return [
        "Confirm password protection was intentionally disabled.",
        "Verify deployments are still restricted to intended users.",
        "Check the Vercel project settings in the Vercel dashboard.",
        "Re-enable password protection if this was accidental.",
      ];
    }
    if (fp2 === "git_branch") {
      return [
        "Confirm the production branch change was intentional.",
        "Verify the new branch is correctly configured for production deployments.",
        "Check that CI/CD pipelines target the correct branch.",
        "Restore the previous branch if this was accidental.",
      ];
    }
    if (fp2 === "git_repository") {
      return [
        "Confirm the repository connection change was intentional.",
        "Verify the new repository has the correct source code.",
        "Check that deployments are still functioning.",
        "Restore the previous repository if this was accidental.",
      ];
    }
    return [
      "Confirm the Vercel project setting change was intentional.",
      "Verify the project builds and deploys correctly after the change.",
      "Check the Vercel dashboard for any deployment failures.",
      "Restore the previous setting if this was accidental.",
    ];
  }
  if (rt === "vercel_env_var") {
    return [
      "Confirm the environment variable change was intentional.",
      "Verify deployments that depend on this variable still function correctly.",
      "Check the Vercel project environment variables for unexpected additions or removals.",
      "Rotate any potentially exposed credentials if this was unintentional.",
    ];
  }
  if (rt === "vercel_domain") {
    return [
      "Confirm the domain change was intentional.",
      "Verify DNS records are correctly configured for the domain.",
      "Check that the domain is verified and active in the Vercel project.",
      "Re-add the domain and update DNS if it was accidentally removed.",
    ];
  }
  if (rt === "vercel_deploy_hook_metadata") {
    if (change.change_type === "removed") {
      return [
        "Confirm the deploy hook deletion was intentional.",
        "Verify no automated pipeline relied on this hook to trigger deployments.",
        "Check the Vercel project → Settings → Git for current deploy hooks.",
        "Re-add the hook if this was accidental.",
      ];
    }
    return [
      "Confirm the deploy hook change was intentional.",
      "Verify the hook is not publicly exposed in source code or documentation.",
      "Check the Vercel project → Settings → Git for current deploy hooks.",
      "Regenerate the hook URL if it may have been exposed.",
    ];
  }
  if (rt.startsWith("vercel_")) {
    return [
      "Confirm the Vercel configuration change was intentional.",
      "Review the Vercel project settings in the Vercel dashboard.",
      "Verify recent deployments are functioning correctly.",
      "Restore the previous setting if this was accidental.",
    ];
  }

  // Stripe
  if (rt === "stripe_webhook_endpoint") {
    const fp3 = change.field_path ?? "";
    if (fp3 === "url") {
      return [
        "Confirm the webhook URL change was intentional.",
        "Verify the new endpoint URL is under your control.",
        "Check the Stripe Dashboard → Developers → Webhooks.",
        "Test that events are being delivered to the new URL.",
        "Restore the previous URL immediately if this was unauthorized.",
      ];
    }
    if (change.change_type === "removed") {
      return [
        "Confirm the webhook deletion was intentional.",
        "Verify that no services rely on events from this endpoint.",
        "Re-add the endpoint in the Stripe Dashboard if this was accidental.",
        "Check Stripe event delivery logs for missed events.",
      ];
    }
    return [
      "Confirm the webhook change was intentional.",
      "Verify the delivery URL and subscribed events are correct.",
      "Check the Stripe Dashboard → Developers → Webhooks.",
      "Test that events are being received by the correct endpoint.",
    ];
  }
  if (rt === "stripe_account_settings") {
    if (change.field_path === "charges_enabled" || change.field_path === "payouts_enabled") {
      return [
        "Confirm this change was intentional — this is a service-impacting event.",
        "Check your Stripe Dashboard → Account → Business settings for alerts.",
        "Contact Stripe support if this was triggered unexpectedly.",
        "Verify that payment flows and payouts are operational.",
      ];
    }
    return [
      "Confirm the Stripe account setting change was intentional.",
      "Review your Stripe Dashboard → Account → Business settings.",
      "Verify that checkout and payout flows still function correctly.",
    ];
  }
  if (rt === "stripe_payment_method_domain") {
    return [
      "Confirm the payment method domain change was intentional.",
      "Verify Apple Pay and Google Pay still work on your checkout pages.",
      "Check the Stripe Dashboard → Settings → Payment methods → Domains.",
      "Re-add the domain if it was accidentally removed.",
    ];
  }
  if (rt === "stripe_billing_portal_config") {
    return [
      "Confirm the billing portal configuration change was intentional.",
      "Verify the customer-facing billing portal still works as expected.",
      "Check the Stripe Dashboard → Settings → Billing → Customer portal.",
      "Restore the previous configuration if this was accidental.",
    ];
  }
  if (rt.startsWith("stripe_")) {
    return [
      "Confirm the Stripe configuration change was intentional.",
      "Review your Stripe Dashboard for related settings.",
      "Verify that checkout and payment flows still function correctly.",
    ];
  }

  // AWS M38 — Security Groups + VPC Network
  if (rt === "aws_security_group" || rt === "aws_security_group_rule") {
    const fp6 = change.field_path ?? "";
    const isPublicOpen = (
      fp6 === "has_public_ssh" || fp6 === "has_public_rdp" || fp6 === "has_public_database_port"
    ) && change.new_value === true;
    if (isPublicOpen || change.change_type === "added") {
      return [
        "Confirm the security group change was intentional.",
        "Verify only intended CIDR ranges or security group IDs are permitted.",
        "Check the AWS VPC Console → Security Groups for the current ruleset.",
        "Review whether this group is attached to internet-facing subnets or instances.",
        "Remove or tighten the rule if this exposure was accidental.",
        "Check AWS CloudTrail for who made the change and when.",
      ];
    }
    if (change.change_type === "removed") {
      return [
        "Confirm the security group removal was intentional.",
        "Verify any instances or services that referenced this group are unaffected.",
        "Check AWS CloudTrail for who made the change.",
      ];
    }
    return [
      "Confirm the security group change was intentional.",
      "Review the AWS VPC Console → Security Groups for the current ruleset.",
      "Check AWS CloudTrail for who made the change.",
    ];
  }
  if (rt === "aws_subnet") {
    if (change.field_path === "map_public_ip_on_launch" && change.new_value === true) {
      return [
        "Confirm that auto-assign public IP was intentionally enabled on this subnet.",
        "Verify instances launched into this subnet should be internet-accessible.",
        "Check that the subnet's route table routes to an internet gateway only if intended.",
        "Review the AWS VPC Console → Subnets → Modify auto-assign IP settings.",
        "Disable auto-assign public IP if this was accidental.",
        "Check AWS CloudTrail for who made the change.",
      ];
    }
    return [
      "Confirm the subnet configuration change was intentional.",
      "Review the AWS VPC Console → Subnets for current settings.",
      "Check AWS CloudTrail for who made the change.",
    ];
  }
  if (rt === "aws_route_table") {
    if (change.field_path === "has_igw_route" && change.new_value === true) {
      return [
        "Confirm that adding an internet gateway route to this route table was intentional.",
        "Verify only intended subnets are associated with this route table.",
        "Check that instances in associated subnets should be internet-accessible.",
        "Review the AWS VPC Console → Route Tables → Routes.",
        "Remove the internet gateway route if this was accidental.",
        "Check AWS CloudTrail for who made the change.",
      ];
    }
    return [
      "Confirm the route table change was intentional.",
      "Review the AWS VPC Console → Route Tables for current routes.",
      "Check AWS CloudTrail for who made the change.",
    ];
  }
  if (rt === "aws_internet_gateway") {
    if (change.field_path === "attached_vpc_id" && !change.prev_value && change.new_value) {
      return [
        "Confirm the internet gateway attachment was intentional.",
        "Verify the VPC has route tables configured for the intended public/private subnet split.",
        "Check that security groups and NACLs restrict traffic to intended sources.",
        "Review the AWS VPC Console → Internet Gateways.",
        "Detach the internet gateway if this was accidental.",
        "Check AWS CloudTrail for who made the change.",
      ];
    }
    return [
      "Confirm the internet gateway change was intentional.",
      "Review the AWS VPC Console → Internet Gateways for current attachment.",
      "Check AWS CloudTrail for who made the change.",
    ];
  }

  // AWS S3
  if (rt === "aws_s3_bucket") {
    const fp5 = change.field_path ?? "";
    const bucketName2 = change.record_identifier?.replace(/^aws_s3_bucket\s+/, "") || change.record_identifier;
    if (fp5 === "policy_status_is_public" && change.new_value === true) {
      return [
        `Open the AWS S3 Console and check the bucket access settings for ${bucketName2}.`,
        "Review the bucket policy and remove any Allow * (public) statements unless intentional.",
        "Verify Block Public Access is enabled if this bucket should not be public.",
        "Check S3 server access logs or CloudTrail for recent access from external IPs.",
        "Enable Block Public Access immediately if this exposure was accidental.",
      ];
    }
    if (fp5 === "acl_all_users_write" && change.new_value === true) {
      return [
        `Remove the public WRITE ACL grant from S3 bucket ${bucketName2} immediately.`,
        "Check S3 server access logs for any unauthorized uploads or deletions.",
        "Review CloudTrail for who made the ACL change and when.",
        "Verify no malicious objects were uploaded to the bucket.",
        "Enable Block Public Access to prevent future ACL grants from taking effect.",
      ];
    }
    if (fp5 === "acl_all_users_read" && change.new_value === true) {
      return [
        `Remove the public READ ACL grant from S3 bucket ${bucketName2}.`,
        "Verify Block Public Access is enabled to prevent ACL grants from taking effect.",
        "Check whether sensitive objects are stored in this bucket.",
        "Review CloudTrail for who made the ACL change.",
        "Enable access logging on the bucket if not already enabled.",
      ];
    }
    if (fp5 === "public_principals_detected" && change.new_value === true) {
      return [
        `Review the bucket policy for ${bucketName2} in the AWS S3 Console.`,
        "Remove any Allow statement with Principal: * unless explicitly required.",
        "Restrict the policy to specific AWS account principals or IAM roles.",
        "Enable Block Public Access as a defence-in-depth measure.",
        "Review CloudTrail for who changed the bucket policy.",
      ];
    }
    if ((fp5 === "block_public_policy" || fp5 === "restrict_public_buckets" || fp5 === "block_public_acls" || fp5 === "ignore_public_acls") && change.new_value === false) {
      return [
        `Re-evaluate whether S3 bucket ${bucketName2} needs this Block Public Access control disabled.`,
        "Check the current bucket policy and ACLs for any public grants that may now take effect.",
        "Verify the AWS S3 Console shows the expected access level.",
        "Re-enable the Block Public Access control if this was accidental.",
        "Review CloudTrail for who made the change.",
      ];
    }
    if (fp5 === "encryption_enabled" && change.new_value === false) {
      return [
        `Re-enable default encryption on S3 bucket ${bucketName2} in the AWS S3 Console.`,
        "Verify existing objects are still encrypted (encryption changes apply to new objects only).",
        "Check your compliance and security policy requirements for this bucket.",
        "Review CloudTrail for who disabled encryption and when.",
      ];
    }
    if (fp5 === "versioning_status" && (change.new_value === "suspended" || change.new_value === "disabled")) {
      return [
        `Consider re-enabling versioning on S3 bucket ${bucketName2}.`,
        "Verify that object recovery requirements for this bucket are still met.",
        "Check whether any lifecycle rules depended on versioned objects.",
        "Review CloudTrail for who changed the versioning setting.",
      ];
    }
    return [
      `Review the S3 bucket ${bucketName2} settings in the AWS S3 Console.`,
      "Verify that public access settings match your intended access level.",
      "Check CloudTrail for recent changes to this bucket's configuration.",
      "Review access logs for unexpected access patterns.",
      "Confirm that encryption, versioning, and logging settings meet your requirements.",
    ];
  }

  // AWS M39 — IAM
  if (rt === "aws_iam_account_summary") {
    const fp7 = change.field_path ?? "";
    if (fp7 === "mfa_enabled_for_root") {
      return [
        "Re-enable MFA on the AWS root account immediately via the AWS Console → Security credentials.",
        "Verify the root account is used exclusively for break-glass scenarios.",
        "Check AWS CloudTrail for recent root account login activity.",
        "Ensure all day-to-day access uses IAM users or roles, not root.",
      ];
    }
    if (fp7 === "root_access_keys_present" && change.new_value === true) {
      return [
        "Delete the root account access keys immediately via the AWS Console → Security credentials.",
        "AWS best practice is to never create or use root access keys.",
        "Create a dedicated IAM user or role for programmatic access instead.",
        "Check AWS CloudTrail for any API calls made using the root access keys.",
      ];
    }
    if (fp7 === "password_policy_present" && change.new_value === false) {
      return [
        "Re-enable the IAM account password policy via the AWS Console → IAM → Account settings.",
        "Enforce minimum length, complexity requirements, and password expiration.",
        "Check AWS CloudTrail for who removed the password policy.",
        "Verify all IAM users have strong passwords.",
      ];
    }
    return [
      "Review the IAM account summary changes in the AWS Console → IAM → Account settings.",
      "Verify root account MFA is enabled and root access keys do not exist.",
      "Confirm password policy settings meet your security requirements.",
      "Check AWS CloudTrail for who made the change.",
    ];
  }
  if (rt === "aws_iam_user") {
    const fp8 = change.field_path ?? "";
    if (fp8 === "mfa_enabled" && change.new_value === false) {
      return [
        "Re-enable MFA for this IAM user immediately via the AWS Console → IAM → Users.",
        "Verify no unauthorized access occurred while MFA was disabled.",
        "Check AWS CloudTrail for recent API calls by this user.",
        "Consider deactivating the user's access keys until MFA is restored.",
      ];
    }
    if (fp8 === "active_key_count" && typeof change.new_value === "number" && typeof change.prev_value === "number" && change.new_value > (change.prev_value as number)) {
      return [
        "Confirm the new access key was intentionally created for this IAM user.",
        "Verify the key is securely stored and not committed to version control.",
        "Check AWS CloudTrail for who created the key.",
        "Rotate or deactivate the key if it was created unintentionally.",
      ];
    }
    return [
      "Review this IAM user's configuration in the AWS Console → IAM → Users.",
      "Verify MFA is enabled and only expected access keys are active.",
      "Check AWS CloudTrail for recent activity by this user.",
      "Confirm attached policies and group memberships are appropriate.",
    ];
  }
  if (rt === "aws_iam_role") {
    const fp9 = change.field_path ?? "";
    if (fp9 === "trust_summary") {
      return [
        "Review the IAM role trust policy in the AWS Console → IAM → Roles.",
        "Verify that all trusted principals are expected and appropriate.",
        "Confirm any cross-account trust uses ExternalId conditions to prevent confused deputy attacks.",
        "Remove wildcard (*) principals from the trust policy immediately if present.",
        "Check AWS CloudTrail for who modified the trust policy.",
      ];
    }
    return [
      "Review this IAM role's configuration in the AWS Console → IAM → Roles.",
      "Verify the trust policy allows only expected principals to assume this role.",
      "Check attached and inline policies for overly broad permissions.",
      "Check AWS CloudTrail for recent role assumption activity.",
    ];
  }
  if (rt === "aws_iam_policy" || rt === "aws_iam_inline_policy") {
    return [
      "Review the full policy document in the AWS Console → IAM → Policies.",
      "Check for wildcard actions (*) or wildcard resources (*) that grant broad access.",
      "Verify the policy is attached only to principals that require these permissions.",
      "Check AWS CloudTrail for who modified the policy and when.",
      "Consider using IAM Access Analyzer to identify overly permissive policies.",
    ];
  }
  if (rt === "aws_iam_policy_attachment") {
    return [
      "Confirm this policy attachment was intentionally made.",
      "Review the full permissions granted by the attached policy.",
      "Verify the principal (user, group, or role) should have these permissions.",
      "Check AWS CloudTrail for who made the attachment.",
      "Remove the attachment if it was unauthorized or accidental.",
    ];
  }
  if (rt === "aws_iam_identity_provider") {
    return [
      "Confirm this identity provider change was intentional.",
      "Verify the provider configuration is correct and uses trusted OIDC or SAML metadata.",
      "Check which IAM roles trust this provider in their trust policies.",
      "Review AWS CloudTrail for who made the change.",
      "Disable the provider if it was added unintentionally.",
    ];
  }
  if (rt === "aws_iam_access_key") {
    if (change.field_path === "status" && change.new_value === "active" && change.prev_value === "inactive") {
      return [
        "Confirm this access key reactivation was intentional.",
        "Verify the key belongs to the expected IAM user.",
        "Check AWS CloudTrail for any API calls using this key.",
        "Deactivate the key immediately if reactivation was unauthorized.",
      ];
    }
    return [
      "Confirm the access key change was intentional.",
      "Review the IAM user's access keys in the AWS Console → IAM → Users → Security credentials.",
      "Check AWS CloudTrail for recent API calls using this key.",
    ];
  }

  // AWS M40 — Route53 + CloudFront
  if (rt === "aws_route53_hosted_zone") {
    if (change.field_path === "name_servers") {
      return [
        "Confirm the name server change was intentional.",
        "Verify the new NS records match what your domain registrar expects.",
        "Check Route53 console → Hosted Zones for current NS records.",
        "If name servers were changed without intent, revert immediately — incorrect NS records make the domain unreachable.",
        "Check AWS CloudTrail for who made the change.",
      ];
    }
    if (change.change_type === "removed") {
      return [
        "Confirm the hosted zone deletion was intentional.",
        "Verify DNS is resolving correctly for all subdomains that were in this zone.",
        "If accidental, recreate the hosted zone and re-add all records.",
        "Update the domain registrar NS records if they still point to Route53.",
        "Check AWS CloudTrail for who deleted the zone.",
      ];
    }
    return [
      "Confirm the Route53 hosted zone change was intentional.",
      "Verify DNS resolution is working correctly for records in this zone.",
      "Check AWS CloudTrail for who made the change.",
    ];
  }
  if (rt === "aws_route53_record") {
    const fp9 = change.field_path ?? "";
    if (fp9 === "dmarc_policy" && change.new_value === "none") {
      return [
        "Update the DMARC policy from 'none' to 'quarantine' or 'reject' to protect against email spoofing.",
        "Test email delivery before switching to 'reject' to avoid legitimate email being dropped.",
        "Use a DMARC analyzer tool to verify your SPF and DKIM records are correctly configured.",
        "Review your email authentication setup in Route53 and your email provider.",
        "Check AWS CloudTrail for who modified the DMARC record.",
      ];
    }
    if (fp9 === "value_hash" || fp9 === "alias_target_dns_name") {
      return [
        "Confirm the DNS record change was intentional.",
        "Test the affected hostname (dig, nslookup, or browser) to verify it resolves correctly.",
        "Verify the new target or IP address is under your control.",
        "Check AWS CloudTrail for who modified the record.",
        "Restore the previous value if this was accidental.",
      ];
    }
    if (change.change_type === "removed") {
      return [
        "Confirm the DNS record removal was intentional.",
        "Test the affected hostname to verify the service is still reachable.",
        "Recreate the record if it was removed accidentally.",
        "Check AWS CloudTrail for who deleted the record.",
      ];
    }
    return [
      "Confirm the DNS record change was intentional.",
      "Test DNS resolution for the affected hostname.",
      "Check AWS CloudTrail for who made the change.",
    ];
  }
  if (rt === "aws_cloudfront_distribution") {
    const fp10 = change.field_path ?? "";
    if (fp10 === "enabled" && change.new_value === false) {
      return [
        "Confirm the distribution was intentionally disabled.",
        "Verify the origin (S3, ALB, or custom) is still available if you plan to re-enable.",
        "Check if any CNAME/alias DNS records still point to this distribution's domain.",
        "Re-enable the distribution in the CloudFront console if this was accidental.",
        "Check AWS CloudTrail for who made the change.",
      ];
    }
    if (fp10 === "web_acl_id") {
      return [
        "Confirm the WAF web ACL change was intentional.",
        "Verify the distribution is still protected against common web attacks.",
        "Re-attach the WAF web ACL in the CloudFront console if it was removed accidentally.",
        "Review AWS WAF logs for any attack traffic during the unprotected window.",
        "Check AWS CloudTrail for who made the change.",
      ];
    }
    if (fp10 === "origins_summary") {
      return [
        "Confirm the origin change was intentional.",
        "Verify the new origin is under your control and returning the expected content.",
        "Test the distribution URL to confirm it serves the correct response.",
        "Revert the origin if it was changed accidentally.",
        "Check AWS CloudTrail for who made the change.",
      ];
    }
    if (fp10 === "default_cache_behavior_summary") {
      return [
        "Confirm the cache behavior change was intentional.",
        "Verify the viewer protocol policy enforces HTTPS (redirect-to-https or https-only).",
        "Test the distribution URL to confirm the expected protocol policy is in effect.",
        "Review the CloudFront console → Behaviors for the current settings.",
        "Check AWS CloudTrail for who made the change.",
      ];
    }
    return [
      "Confirm the CloudFront distribution change was intentional.",
      "Test the distribution URL to verify it serves the expected content.",
      "Review the CloudFront console for the current distribution configuration.",
      "Check AWS CloudTrail for who made the change.",
    ];
  }

  // AWS M41 — Secrets Manager + SSM
  if (rt === "aws_secretsmanager_secret") {
    const fp11 = change.field_path ?? "";
    if (fp11 === "rotation_enabled" && change.new_value === false) {
      return [
        "Confirm rotation was intentionally disabled for this secret.",
        "Review the rotation configuration in Secrets Manager → Rotation tab.",
        "Re-enable automatic rotation if this was accidental.",
        "Check AWS CloudTrail for who made the change.",
        "ConfigTrace does not read or store secret values.",
      ];
    }
    if (fp11 === "deleted_date" || change.change_type === "removed") {
      return [
        "Confirm the secret deletion is intentional and no application still uses it.",
        "Check AWS CloudTrail for who triggered the deletion.",
        "Search your codebase for references to this secret name.",
        "If deletion is scheduled, verify the deletion window gives enough time to update consumers.",
        "ConfigTrace does not read or store secret values.",
      ];
    }
    if (fp11 === "policy_summary") {
      return [
        "Review the resource policy in Secrets Manager → Resource permissions.",
        "Confirm no wildcard principal (*) grants unintended access.",
        "Check AWS CloudTrail for who modified the resource policy.",
        "Confirm rotation settings match production requirements.",
        "ConfigTrace does not read or store secret values.",
      ];
    }
    return [
      "Confirm rotation settings match production requirements.",
      "If deletion is scheduled, confirm this secret is not still used.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not read or store secret values.",
    ];
  }
  if (rt === "aws_ssm_parameter") {
    const fp12 = change.field_path ?? "";
    if (fp12 === "parameter_type") {
      return [
        "If type changed from SecureString to String, review whether parameter should remain encrypted.",
        "Check AWS CloudTrail for who changed the parameter type.",
        "Search your codebase for consumers that may depend on the parameter type.",
        "Re-encrypt the parameter if the type change was accidental.",
        "ConfigTrace does not read or store parameter values.",
      ];
    }
    if (change.change_type === "removed") {
      return [
        "Confirm the parameter deletion was intentional.",
        "Search your codebase for references to this parameter name.",
        "Check AWS CloudTrail for who deleted the parameter.",
        "Recreate the parameter if it was removed accidentally.",
        "ConfigTrace does not read or store parameter values.",
      ];
    }
    return [
      "If type changed from SecureString to String, review whether parameter should remain encrypted.",
      "Check AWS CloudTrail for who made the change.",
      "Verify consumer applications are updated if the parameter structure changed.",
      "ConfigTrace does not read or store parameter values.",
    ];
  }

  // M42 RDS
  if (rt === "aws_rds_db_instance") {
    const fpRds = change.field_path ?? "";
    if (fpRds === "publicly_accessible" && change.new_value === true) {
      return [
        "Verify that public accessibility is intentional for this database instance.",
        "Confirm security groups restrict inbound access to trusted IP ranges only.",
        "Check if the instance is in a public subnet with an internet gateway route.",
        "Review network ACLs for the associated subnets.",
        "Check AWS CloudTrail for who changed the publicly_accessible setting.",
        "ConfigTrace does not connect to databases or read database content.",
      ];
    }
    if (fpRds === "storage_encrypted" && change.new_value === false) {
      return [
        "Verify encryption was intentionally disabled — this cannot be undone on an existing instance.",
        "Consider creating a new encrypted instance and migrating data.",
        "Check AWS CloudTrail for who disabled encryption.",
        "Review your data residency and compliance requirements.",
        "ConfigTrace does not connect to databases or read database content.",
      ];
    }
    if (fpRds === "deletion_protection" && change.new_value === false) {
      return [
        "Confirm deletion protection was intentionally disabled.",
        "Verify no automated process or script is about to delete this instance.",
        "Re-enable deletion protection if this was accidental.",
        "Check AWS CloudTrail for who made the change.",
        "ConfigTrace does not connect to databases or read database content.",
      ];
    }
    if (fpRds === "backup_retention_days" && change.new_value === 0) {
      return [
        "Confirm automated backups were intentionally disabled.",
        "Ensure manual snapshots exist before disabling backups.",
        "Review your RPO requirements — disabling backups removes point-in-time recovery.",
        "Re-enable automated backups if this was accidental.",
        "ConfigTrace does not connect to databases or read database content.",
      ];
    }
    if (fpRds === "multi_az" && change.new_value === false) {
      return [
        "Confirm Multi-AZ was intentionally disabled.",
        "Assess impact on availability SLAs — single-AZ instances are not HA.",
        "Re-enable Multi-AZ if this was accidental.",
        "Check AWS CloudTrail for who made the change.",
        "ConfigTrace does not connect to databases or read database content.",
      ];
    }
    return [
      "Confirm the RDS configuration change was intentional.",
      "Check AWS CloudTrail for who made the change.",
      "Verify the instance security groups, encryption, and backup settings are correct.",
      "ConfigTrace does not connect to databases or read database content.",
    ];
  }
  if (rt === "aws_rds_db_cluster") {
    const fpCluster = change.field_path ?? "";
    if (fpCluster === "publicly_accessible" && change.new_value === true) {
      return [
        "Verify public accessibility is intentional for this cluster.",
        "Confirm security groups restrict inbound access to trusted IP ranges only.",
        "Review network ACLs for the associated subnets.",
        "Check AWS CloudTrail for who changed the setting.",
        "ConfigTrace does not connect to databases or read database content.",
      ];
    }
    if (fpCluster === "storage_encrypted" && change.new_value === false) {
      return [
        "Verify encryption was intentionally disabled.",
        "Check AWS CloudTrail for who made the change.",
        "Review compliance and data residency requirements.",
        "ConfigTrace does not connect to databases or read database content.",
      ];
    }
    if (fpCluster === "deletion_protection" && change.new_value === false) {
      return [
        "Confirm deletion protection was intentionally disabled.",
        "Verify no automated process is about to delete this cluster.",
        "Re-enable deletion protection if this was accidental.",
        "Check AWS CloudTrail for who made the change.",
        "ConfigTrace does not connect to databases or read database content.",
      ];
    }
    if (fpCluster === "backup_retention_days" && change.new_value === 0) {
      return [
        "Confirm automated backups were intentionally disabled for this cluster.",
        "Ensure cluster snapshots exist before disabling backups.",
        "Review RPO requirements — disabling backups removes point-in-time recovery.",
        "ConfigTrace does not connect to databases or read database content.",
      ];
    }
    return [
      "Confirm the RDS cluster configuration change was intentional.",
      "Check AWS CloudTrail for who made the change.",
      "Verify cluster security groups, encryption, and backup settings are correct.",
      "ConfigTrace does not connect to databases or read database content.",
    ];
  }
  if (rt === "aws_rds_db_subnet_group") {
    return [
      "Verify the subnet group change was intentional.",
      "Confirm databases using this subnet group have coverage in the required availability zones.",
      "Check AWS CloudTrail for who made the change.",
      "Verify the new subnets belong to the expected VPC.",
    ];
  }
  if (rt === "aws_rds_db_snapshot") {
    const fpSnap = change.field_path ?? "";
    if (fpSnap === "publicly_accessible" && change.new_value === true) {
      return [
        "Restrict snapshot access immediately if this was not intentional.",
        "Public snapshots can be copied and restored by any AWS account.",
        "Check the snapshot for sensitive data before allowing public access.",
        "Remove public access via RDS → Snapshots → Actions → Share snapshot.",
        "Check AWS CloudTrail for who changed the snapshot visibility.",
        "ConfigTrace does not connect to databases or read database content.",
      ];
    }
    if (change.change_type === "removed") {
      return [
        "Confirm the snapshot deletion was intentional.",
        "Verify the database can be recovered from another backup if needed.",
        "Check AWS CloudTrail for who deleted the snapshot.",
        "Review your backup retention policy.",
        "ConfigTrace does not connect to databases or read database content.",
      ];
    }
    return [
      "Confirm the snapshot configuration change was intentional.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not connect to databases or read database content.",
    ];
  }
  if (rt === "aws_rds_db_cluster_snapshot") {
    const fpCSnap = change.field_path ?? "";
    if (fpCSnap === "publicly_accessible" && change.new_value === true) {
      return [
        "Restrict cluster snapshot access immediately if this was not intentional.",
        "Public cluster snapshots can be copied and restored by any AWS account.",
        "Remove public access via RDS → Snapshots → Actions → Share snapshot.",
        "Check AWS CloudTrail for who changed the snapshot visibility.",
        "ConfigTrace does not connect to databases or read database content.",
      ];
    }
    if (change.change_type === "removed") {
      return [
        "Confirm the cluster snapshot deletion was intentional.",
        "Verify the cluster can be recovered from another backup if needed.",
        "Check AWS CloudTrail for who deleted the snapshot.",
        "ConfigTrace does not connect to databases or read database content.",
      ];
    }
    return [
      "Confirm the cluster snapshot configuration change was intentional.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not connect to databases or read database content.",
    ];
  }

  // M43 Lambda
  if (rt === "aws_lambda_function") {
    const fpLambda = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "Confirm the Lambda function was intentionally deleted or is no longer in this region.",
        "Verify dependent services or event sources that called this function are updated.",
        "Check AWS CloudTrail for who deleted the function.",
        "ConfigTrace does not read function code or environment variable values.",
      ];
    }
    if (fpLambda === "role_arn_hash") {
      return [
        "Confirm the execution role change was intentional.",
        "Review the new role's IAM policies for least-privilege compliance.",
        "Ensure the role does not have excessive permissions (e.g. AdministratorAccess).",
        "Check AWS CloudTrail for who changed the execution role.",
        "ConfigTrace does not read function code or environment variable values.",
      ];
    }
    if (fpLambda === "environment_key_names" || fpLambda === "environment_key_count" || fpLambda === "environment_sensitive_key_count") {
      return [
        "Confirm the environment variable key names are expected.",
        "Verify no sensitive keys were unexpectedly added or removed.",
        "ConfigTrace stores only key names — variable values are never read or stored.",
        "Check AWS CloudTrail for who updated the function configuration.",
      ];
    }
    if (fpLambda === "vpc_config_present" && change.new_value === false) {
      return [
        "Confirm VPC attachment was intentionally removed.",
        "Verify the function can still reach required private resources (databases, internal APIs).",
        "Check if public endpoints are now exposed where previously protected by VPC.",
        "Check AWS CloudTrail for who changed the VPC configuration.",
        "ConfigTrace does not read function code or environment variable values.",
      ];
    }
    if (fpLambda === "kms_key_arn_present" && change.new_value === false) {
      return [
        "Confirm KMS encryption was intentionally removed from this function.",
        "Review whether environment variables contain sensitive data that should be encrypted.",
        "Check AWS CloudTrail for who changed the KMS configuration.",
        "ConfigTrace does not read function code or environment variable values.",
      ];
    }
    if (fpLambda === "reserved_concurrent_executions" && change.new_value === 0) {
      return [
        "Confirm reserved concurrency of 0 is intentional — this throttles the function to zero invocations.",
        "Verify no dependent services or event sources are blocked.",
        "Re-enable concurrency if this was accidental.",
        "Check AWS CloudTrail for who changed the concurrency setting.",
        "ConfigTrace does not read function code or environment variable values.",
      ];
    }
    return [
      "Confirm the Lambda function configuration change was intentional.",
      "Verify the function still exists in the expected region.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not read function code or environment variable values.",
    ];
  }
  if (rt === "aws_lambda_alias") {
    const fpAlias = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "Confirm the Lambda alias was intentionally deleted.",
        "Verify services that invoke this alias have been updated to the correct version.",
        "Check AWS CloudTrail for who deleted the alias.",
      ];
    }
    if (fpAlias === "function_version") {
      return [
        "Confirm the alias was intentionally updated to a new function version.",
        "Verify the new version has been tested and behaves as expected.",
        "Check AWS CloudTrail for who updated the alias.",
      ];
    }
    if (fpAlias === "routing_config_present" && change.new_value === false) {
      return [
        "Confirm traffic routing (weighted alias) was intentionally removed.",
        "Verify 100% of traffic now routes to the primary version as expected.",
        "Check AWS CloudTrail for who changed the routing configuration.",
      ];
    }
    return [
      "Confirm the Lambda alias configuration change was intentional.",
      "Check AWS CloudTrail for who made the change.",
    ];
  }
  if (rt === "aws_lambda_event_source_mapping") {
    const fpEsm = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "Confirm the event source mapping was intentionally deleted.",
        "Verify the stream, queue, or topic still has a consumer if needed.",
        "Check if messages are accumulating unprocessed in the source.",
        "Check AWS CloudTrail for who deleted the mapping.",
      ];
    }
    if (fpEsm === "enabled" && change.new_value === false) {
      return [
        "Confirm the event source mapping was intentionally disabled.",
        "Verify messages or records are not accumulating unprocessed in the source.",
        "Re-enable the mapping if this was accidental.",
        "Check AWS CloudTrail for who disabled the mapping.",
      ];
    }
    if (fpEsm === "event_source_arn_present" && change.new_value === false) {
      return [
        "Confirm the event source ARN was intentionally removed.",
        "Verify the function still has a trigger if one is required.",
        "Check AWS CloudTrail for who changed the event source mapping.",
      ];
    }
    if (fpEsm === "filter_criteria_present" && change.new_value === false) {
      return [
        "Confirm event filter criteria were intentionally removed.",
        "Verify the function is designed to handle all incoming events without filtering.",
        "Check AWS CloudTrail for who changed the mapping.",
      ];
    }
    return [
      "Confirm the event source mapping configuration change was intentional.",
      "Verify stream/queue processing is functioning as expected.",
      "Check AWS CloudTrail for who made the change.",
    ];
  }
  if (rt === "aws_lambda_function_url") {
    const fpUrl = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "Confirm the Lambda function URL was intentionally deleted.",
        "Verify clients that used this URL have been updated.",
        "Check AWS CloudTrail for who deleted the function URL.",
      ];
    }
    if ((fpUrl === "auth_type" && change.new_value === "NONE") || change.change_type === "added") {
      return [
        "CRITICAL: Verify that public (unauthenticated) invocation is intentional for this function.",
        "A Lambda function URL with auth_type=NONE is publicly accessible by anyone on the internet.",
        "Confirm the function itself implements its own authorization logic if auth_type=NONE is intended.",
        "Consider using AWS_IAM auth_type for all non-public function URLs.",
        "Review the function code logic to ensure it cannot be exploited without authentication.",
        "ConfigTrace does not invoke functions or read function code.",
      ];
    }
    if (fpUrl === "cors_wildcard_origin_present" && change.new_value === true) {
      return [
        "Confirm wildcard CORS origin (*) is intentional for this function URL.",
        "Wildcard CORS allows any browser origin to call this function URL.",
        "Consider restricting cors_allow_origins to specific trusted domains.",
        "If cors_allow_credentials is also enabled, this is a critical CORS misconfiguration.",
        "ConfigTrace does not invoke functions or read function code.",
      ];
    }
    if (fpUrl === "cors_allow_credentials" && change.new_value === true) {
      return [
        "Confirm CORS credentials are intentionally enabled on this function URL.",
        "Credentials + wildcard origin is a critical CORS misconfiguration — browsers will reject this combination.",
        "Ensure cors_allow_origins is restricted to specific trusted domains when credentials are enabled.",
        "ConfigTrace does not invoke functions or read function code.",
      ];
    }
    return [
      "Confirm the Lambda function URL configuration change was intentional.",
      "Verify the authentication and CORS settings are appropriate for the intended audience.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not invoke functions or read function code.",
    ];
  }

  // M43 API Gateway REST
  if (rt === "aws_apigateway_rest_api") {
    const fpRestApi = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "Confirm the REST API was intentionally deleted or is no longer in this region.",
        "Verify dependent clients and services have been updated.",
        "Check AWS CloudTrail for who deleted the API.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpRestApi === "unauthenticated_method_count") {
      return [
        "Confirm the increase in unauthenticated methods is intentional.",
        "Review each newly open method to ensure public access is expected.",
        "Verify no sensitive data or operations are exposed without authentication.",
        "Check AWS CloudTrail for who changed the API resource/method configuration.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpRestApi === "authorizer_count" && change.new_value === 0) {
      return [
        "Confirm all authorizers were intentionally removed from this REST API.",
        "Verify that all routes requiring authentication use another mechanism.",
        "Check whether any routes are now publicly accessible without authentication.",
        "Check AWS CloudTrail for who removed the authorizers.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpRestApi === "policy_summary") {
      return [
        "Confirm the resource policy change was intentional.",
        "Verify the updated policy does not grant overly broad access (e.g. wildcard principals).",
        "Check AWS CloudTrail for who modified the resource policy.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    return [
      "Confirm the REST API configuration change was intentional.",
      "Verify the API exists in the expected region and is correctly configured.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not read API traffic or request/response content.",
    ];
  }
  if (rt === "aws_apigateway_rest_stage") {
    const fpRestStage = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "Confirm the REST stage was intentionally deleted.",
        "Verify clients using this stage URL have been updated.",
        "Check AWS CloudTrail for who deleted the stage.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpRestStage === "deployment_id_present" && change.new_value === false) {
      return [
        "Confirm the deployment was intentionally detached from this stage.",
        "A stage without a deployment will not serve requests.",
        "Re-associate a deployment if this was accidental.",
        "Check AWS CloudTrail for who changed the stage.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpRestStage === "web_acl_arn_present" && change.new_value === false) {
      return [
        "Confirm WAF protection was intentionally removed from this REST stage.",
        "Without WAF, the stage is now unprotected from common web attacks.",
        "Re-attach a WAF web ACL if this was accidental.",
        "Check AWS CloudTrail for who removed WAF protection.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpRestStage === "tracing_enabled" && change.new_value === false) {
      return [
        "Confirm X-Ray tracing was intentionally disabled for this stage.",
        "Review your observability requirements and incident response capabilities.",
        "Re-enable tracing if needed.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpRestStage === "access_logging_enabled" && change.new_value === false) {
      return [
        "Confirm access logging was intentionally disabled for this stage.",
        "Access logs are important for security investigation and audit.",
        "Re-enable access logging and ensure logs are stored in a secure, monitored S3 bucket.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    return [
      "Confirm the REST stage configuration change was intentional.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not read API traffic or request/response content.",
    ];
  }

  // M43 API Gateway V2
  if (rt === "aws_apigatewayv2_api") {
    const fpV2Api = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "Confirm the HTTP/WebSocket API was intentionally deleted or is no longer in this region.",
        "Verify dependent clients and services have been updated.",
        "Check AWS CloudTrail for who deleted the API.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpV2Api === "unauthenticated_route_count") {
      return [
        "Confirm the increase in unauthenticated routes is intentional.",
        "Review each newly open route to ensure public access is expected.",
        "Verify no sensitive operations are exposed without authentication.",
        "Check AWS CloudTrail for who changed the API route configuration.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpV2Api === "authorizer_count" && change.new_value === 0) {
      return [
        "Confirm all authorizers were intentionally removed from this V2 API.",
        "Verify that routes requiring authentication use another mechanism.",
        "Check whether any routes are now publicly accessible without authentication.",
        "Check AWS CloudTrail for who removed the authorizers.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpV2Api === "cors_wildcard_origin_present" && change.new_value === true) {
      return [
        "Confirm wildcard CORS origin (*) is intentional for this API.",
        "Wildcard CORS allows any browser origin to make cross-origin requests.",
        "Consider restricting to specific trusted domains.",
        "If cors_allow_credentials is also true, this is a critical CORS misconfiguration.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpV2Api === "cors_allow_credentials" && change.new_value === true) {
      return [
        "Confirm CORS credentials are intentionally enabled on this API.",
        "Credentials + wildcard origin is a critical CORS misconfiguration.",
        "Ensure cors_allow_origins is restricted to specific domains when credentials are enabled.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    return [
      "Confirm the V2 API configuration change was intentional.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not read API traffic or request/response content.",
    ];
  }
  if (rt === "aws_apigatewayv2_stage") {
    const fpV2Stage = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "Confirm the V2 stage was intentionally deleted.",
        "Verify clients using this stage URL have been updated.",
        "Check AWS CloudTrail for who deleted the stage.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpV2Stage === "auto_deploy" && change.new_value === false) {
      return [
        "Confirm auto-deploy was intentionally disabled for this stage.",
        "Future API changes will require manual deployment to take effect on this stage.",
        "Check AWS CloudTrail for who changed the auto-deploy setting.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpV2Stage === "access_logging_enabled" && change.new_value === false) {
      return [
        "Confirm access logging was intentionally disabled for this stage.",
        "Access logs support security investigation and audit requirements.",
        "Re-enable logging and store logs in a secure, monitored destination.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    if (fpV2Stage === "detailed_metrics_enabled" && change.new_value === false) {
      return [
        "Confirm detailed CloudWatch metrics were intentionally disabled for this stage.",
        "Review your observability and alerting requirements.",
        "Re-enable metrics if needed for monitoring or SLA tracking.",
        "ConfigTrace does not read API traffic or request/response content.",
      ];
    }
    return [
      "Confirm the V2 stage configuration change was intentional.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not read API traffic or request/response content.",
    ];
  }

  // M44 Load Balancers
  if (rt === "aws_elbv2_load_balancer") {
    const fpLb = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "Confirm this load balancer was intentionally deleted or is no longer in this region.",
        "Verify dependent services have been updated to use an alternative endpoint.",
        "Check AWS CloudTrail for who deleted the load balancer.",
        "ConfigTrace does not read load balancer access logs or request traffic.",
      ];
    }
    if (fpLb === "scheme" && change.prev_value === "internal" && change.new_value === "internet-facing") {
      return [
        "If scheme changed to internet-facing, review listeners, security groups, and subnet routing.",
        "Verify no internal-only services are now exposed to the public internet.",
        "Confirm listener protocols and SSL/TLS policies are appropriate for public exposure.",
        "Review security groups to ensure access is restricted to expected sources.",
        "Check AWS CloudTrail for who changed the load balancer scheme.",
        "ConfigTrace does not read load balancer access logs or request traffic.",
      ];
    }
    if (fpLb === "deletion_protection_enabled" && change.new_value === false) {
      return [
        "Confirm deletion protection was intentionally disabled.",
        "Verify no automated process or deployment pipeline is about to delete this load balancer.",
        "Re-enable deletion protection for production load balancers if this was accidental.",
        "Check AWS CloudTrail for who changed the setting.",
        "ConfigTrace does not read load balancer access logs or request traffic.",
      ];
    }
    if (fpLb === "access_logs_enabled" && change.new_value === false) {
      return [
        "Confirm access logging was intentionally disabled.",
        "Access logs support security investigation and compliance requirements.",
        "Re-enable access logging and store logs in a secure, monitored S3 bucket.",
        "Check AWS CloudTrail for who disabled logging.",
        "ConfigTrace does not read load balancer access logs or request traffic.",
      ];
    }
    return [
      "Confirm this load balancer should exist in this region.",
      "If listeners, security groups, or subnets changed, verify traffic routing.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not read load balancer access logs or request traffic.",
    ];
  }
  if (rt === "aws_elbv2_target_group") {
    const fpTg = change.field_path ?? "";
    if (fpTg === "target_count" && change.new_value === 0) {
      return [
        "Target count dropped to zero — all traffic to this target group may fail.",
        "Verify application instances/tasks are healthy and registered.",
        "Check AWS CloudTrail for recent deregistration events.",
        "Confirm auto-scaling or ECS task replacement is functioning.",
        "ConfigTrace does not read load balancer access logs or request traffic.",
      ];
    }
    if (fpTg === "health_check_enabled" && change.new_value === false) {
      return [
        "Confirm health checks were intentionally disabled on this target group.",
        "Without health checks, unhealthy targets may receive traffic.",
        "Re-enable health checks for production target groups.",
        "ConfigTrace does not read load balancer access logs or request traffic.",
      ];
    }
    return [
      "Confirm the target group change was intentional.",
      "If target health changed, check application instances/tasks.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not read load balancer access logs or request traffic.",
    ];
  }
  if (rt === "aws_elbv2_listener") {
    const fpLst = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "Confirm this listener was intentionally removed.",
        "If HTTPS/TLS listener/certificate/SSL policy changed, confirm TLS requirements are still met.",
        "Verify dependent clients are redirected or updated.",
        "Check AWS CloudTrail for who removed the listener.",
        "ConfigTrace does not read load balancer access logs or request traffic.",
      ];
    }
    if (fpLst === "protocol" || fpLst === "ssl_policy" || fpLst === "certificate_count") {
      return [
        "If HTTPS/TLS listener, certificate, or SSL policy changed, confirm TLS requirements.",
        "Verify the SSL policy meets your minimum TLS version requirements.",
        "Confirm certificate coverage is adequate for all expected hostnames.",
        "Check AWS CloudTrail for who changed the listener.",
        "ConfigTrace does not read load balancer access logs or request traffic.",
      ];
    }
    if (fpLst === "default_target_group_arn_hashes") {
      return [
        "Confirm the default routing target change was intentional.",
        "Verify traffic routes to the expected target group.",
        "Check AWS CloudTrail for who changed the listener default action.",
        "ConfigTrace does not read load balancer access logs or request traffic.",
      ];
    }
    return [
      "Confirm the listener configuration change was intentional.",
      "Verify listener protocol, port, and routing are correct.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not read load balancer access logs or request traffic.",
    ];
  }
  if (rt === "aws_elbv2_listener_rule" || rt === "aws_elb_classic_load_balancer") {
    return [
      "Confirm this load balancer should exist in this region.",
      "If scheme changed to internet-facing, review listeners, security groups, and subnet routing.",
      "If listener configuration changed, confirm traffic routing requirements.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not read load balancer access logs or request traffic.",
    ];
  }

  // M44 WAF
  if (rt === "aws_wafv2_web_acl") {
    const fpAcl = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "Confirm this Web ACL was intentionally deleted.",
        "Verify associated resources (ALBs, API Gateways) have alternative WAF protection.",
        "Check AWS CloudTrail for who deleted the Web ACL.",
        "ConfigTrace does not read sampled requests or request contents.",
      ];
    }
    if (fpAcl === "default_action" && change.new_value === "allow") {
      return [
        "Confirm the Web ACL should exist and be associated with the affected resource.",
        "If default action changed to allow, review intended filtering posture.",
        "Requests not matching explicit rules will now pass through unfiltered.",
        "If managed rules were removed, confirm equivalent protection exists.",
        "Check AWS CloudTrail for who changed the default action.",
        "ConfigTrace does not read sampled requests or request contents.",
      ];
    }
    if (fpAcl === "managed_rule_group_count" || fpAcl === "rule_count") {
      return [
        "If managed rules were removed, confirm equivalent protection exists.",
        "Verify the remaining rule set covers expected attack patterns.",
        "Check AWS CloudTrail for who changed the WAF rules.",
        "ConfigTrace does not read sampled requests or request contents.",
      ];
    }
    if (fpAcl === "logging_enabled" && change.new_value === false) {
      return [
        "If logging changed, confirm security monitoring requirements are still met.",
        "WAF logs support security investigation, compliance, and threat detection.",
        "Re-enable logging to a secure destination if this was accidental.",
        "Check AWS CloudTrail for who disabled WAF logging.",
        "ConfigTrace does not read sampled requests or request contents.",
      ];
    }
    return [
      "Confirm this Web ACL should be associated with the affected resource.",
      "Review the current rule set to ensure adequate protection.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace does not read sampled requests or request contents.",
    ];
  }
  if (rt === "aws_wafv2_web_acl_association") {
    if (change.change_type === "removed") {
      return [
        "Confirm this Web ACL should be associated with the affected resource.",
        "The resource may no longer have WAF protection — review your security posture.",
        "If association was intentionally removed, confirm alternative protection exists.",
        "Check AWS CloudTrail for who removed the WAF association.",
        "ConfigTrace does not read sampled requests or request contents.",
      ];
    }
    return [
      "Confirm the Web ACL association is intentional.",
      "Verify the Web ACL rules are appropriate for the associated resource.",
      "ConfigTrace does not read sampled requests or request contents.",
    ];
  }

  // ── M45: CloudTrail + GuardDuty + Security Hub ──────────────────────────
  if (rt === "aws_cloudtrail_trail") {
    const fp5 = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "Confirm this trail was intentionally removed or replaced.",
        "Verify another trail is still capturing management events for this account.",
        "Check AWS IAM access logs for who deleted or disabled the trail.",
        "If the trail was deleted without authorization, escalate as a security incident.",
        "ConfigTrace never reads CloudTrail event logs or S3 log objects.",
      ];
    }
    if (fp5 === "is_logging" && change.new_value === false) {
      return [
        "Investigate why CloudTrail logging was stopped — this may indicate credential misuse.",
        "Re-enable logging immediately if this was not authorized.",
        "Check IAM access logs for who called cloudtrail:StopLogging.",
        "Verify no audit gaps occurred during the period logging was off.",
        "ConfigTrace never calls cloudtrail:LookupEvents or reads log files.",
      ];
    }
    if (fp5 === "log_file_validation_enabled" && change.new_value === false) {
      return [
        "Log file validation ensures CloudTrail logs have not been tampered with.",
        "Re-enable log file validation to restore tamper detection.",
        "Review whether this change was authorized.",
        "ConfigTrace never reads CloudTrail log objects from S3.",
      ];
    }
    if (fp5 === "kms_key_id_present" && change.new_value === false) {
      return [
        "CloudTrail KMS encryption was removed — logs may be stored unencrypted.",
        "Re-enable KMS encryption if this was not intentional.",
        "Verify the KMS key change was authorized by a security administrator.",
        "ConfigTrace does not store or access KMS key material.",
      ];
    }
    return [
      "Confirm this CloudTrail configuration change was authorized.",
      "Verify logging coverage is still sufficient for your compliance requirements.",
      "ConfigTrace never reads CloudTrail events, log objects, or S3 buckets.",
    ];
  }

  if (rt === "aws_cloudtrail_event_data_store") {
    if (change.change_type === "removed" || (change.field_path === "status" && ["STOPPED", "STOPPED_INGESTION", "DELETED"].includes(String(change.new_value).toUpperCase()))) {
      return [
        "Confirm the event data store removal or shutdown was intentional.",
        "Events stored in a deleted data store may be permanently lost.",
        "Verify alternative audit data stores cover the affected event types.",
        "ConfigTrace never reads events from CloudTrail event data stores.",
      ];
    }
    return [
      "Confirm the event data store configuration change was authorized.",
      "Verify retention period and termination protection settings meet your requirements.",
      "ConfigTrace never reads events from CloudTrail event data stores.",
    ];
  }

  if (rt === "aws_guardduty_detector") {
    if (change.change_type === "removed" || (change.field_path === "status" && String(change.new_value).toUpperCase() === "DISABLED")) {
      return [
        "GuardDuty is your primary AWS threat detection layer — disabling it silences all findings.",
        "Re-enable GuardDuty immediately if this was not authorized.",
        "Investigate whether an attacker disabled GuardDuty to avoid detection.",
        "Check CloudTrail for who called guardduty:DeleteDetector or guardduty:UpdateDetector.",
        "ConfigTrace never calls guardduty:GetFindings or accesses finding details.",
      ];
    }
    if (change.field_path?.endsWith("_enabled") && change.new_value === false) {
      return [
        "A GuardDuty protection feature was disabled — detection coverage for this threat category is reduced.",
        "Re-enable the protection feature if this was not intentional.",
        "Review whether alternative detection mechanisms cover this threat category.",
        "ConfigTrace never calls guardduty:GetFindings or accesses finding details.",
      ];
    }
    return [
      "Confirm this GuardDuty configuration change was authorized.",
      "Verify threat detection coverage remains appropriate for your environment.",
      "ConfigTrace never calls guardduty:GetFindings or accesses finding details.",
    ];
  }

  if (rt === "aws_guardduty_publishing_destination") {
    if (change.change_type === "removed") {
      return [
        "GuardDuty findings will no longer be exported to this destination.",
        "Confirm alternative destinations or SIEM integrations are in place.",
        "Verify the removal was authorized by a security administrator.",
        "ConfigTrace never reads GuardDuty finding payloads.",
      ];
    }
    if (change.field_path === "status") {
      return [
        "GuardDuty cannot export findings to this destination — findings may be accumulating without alerting.",
        "Check S3 bucket permissions or KMS key access for the destination.",
        "Restore export functionality to ensure finding delivery to your SIEM.",
        "ConfigTrace never reads GuardDuty finding payloads.",
      ];
    }
    return [
      "Confirm the GuardDuty publishing destination change was authorized.",
      "ConfigTrace never reads GuardDuty finding payloads.",
    ];
  }

  if (rt === "aws_securityhub_account") {
    const sfp = change.field_path ?? "";
    if (change.change_type === "removed" || (sfp === "hub_enabled" && change.new_value === false)) {
      return [
        "Security Hub was disabled — all security standards and control findings will stop.",
        "Re-enable Security Hub if this was not intentional.",
        "Investigate who disabled Security Hub and whether it was authorized.",
        "ConfigTrace never calls securityhub:GetFindings or accesses finding details.",
      ];
    }
    if (sfp === "enabled_standards_count" && Number(change.new_value) === 0) {
      return [
        "All Security Hub compliance standards were disabled — no controls are being evaluated.",
        "Re-enable the appropriate standards (e.g., FSBP, CIS) for your compliance posture.",
        "ConfigTrace never calls securityhub:GetFindings or accesses finding details.",
      ];
    }
    return [
      "Confirm this Security Hub configuration change was authorized.",
      "Verify compliance standards and control coverage remain appropriate.",
      "ConfigTrace never calls securityhub:GetFindings or accesses finding details.",
    ];
  }

  if (rt === "aws_securityhub_standard_subscription") {
    if (change.change_type === "removed") {
      return [
        "A Security Hub compliance standard was disabled — controls for this standard are no longer evaluated.",
        "If this standard is required by your compliance framework, re-enable it.",
        "ConfigTrace never calls securityhub:GetFindings or accesses finding details.",
      ];
    }
    return [
      "Confirm the standard subscription change was authorized.",
      "ConfigTrace never calls securityhub:GetFindings or accesses finding details.",
    ];
  }

  if (rt === "aws_securityhub_finding_aggregator") {
    if (change.change_type === "removed") {
      return [
        "Cross-region Security Hub finding aggregation was removed — findings from other regions may not be visible.",
        "Confirm this was intentional if you operate a multi-region environment.",
        "ConfigTrace never calls securityhub:GetFindings or accesses finding details.",
      ];
    }
    if (change.field_path === "linking_mode" && String(change.new_value) === "SPECIFIED_REGIONS") {
      return [
        "Security Hub finding aggregation was narrowed to specific regions.",
        "Verify the selected regions cover all regions where you run workloads.",
        "ConfigTrace never calls securityhub:GetFindings or accesses finding details.",
      ];
    }
    return [
      "Confirm the finding aggregator configuration change was authorized.",
      "ConfigTrace never calls securityhub:GetFindings or accesses finding details.",
    ];
  }

  // ── M46: ECS ──────────────────────────────────────────────────────────────
  if (rt === "aws_ecs_cluster") {
    if (change.field_path === "container_insights_enabled" && change.new_value === false) {
      return [
        "Container Insights was disabled — ECS metrics and logs will not be forwarded to CloudWatch.",
        "Re-enable Container Insights if operational observability is required.",
        "ConfigTrace never reads ECS task logs or container output.",
      ];
    }
    return ["Confirm the ECS cluster configuration change was authorized.", "ConfigTrace never reads ECS task logs or environment variable values."];
  }
  if (rt === "aws_ecs_service") {
    const sfp = change.field_path ?? "";
    if (sfp === "has_public_ip" && change.new_value === true) {
      return [
        "ECS tasks are now assigned public IPs — they may be directly reachable from the internet.",
        "Ensure your security groups restrict inbound access to only required ports.",
        "Consider using a load balancer instead of direct public IPs for better control.",
        "ConfigTrace never reads ECS task logs or environment variable values.",
      ];
    }
    if (sfp === "desired_count" && Number(change.new_value) === 0) {
      return [
        "ECS service desired count was set to 0 — all running tasks will stop.",
        "Verify this was intentional and not caused by an erroneous deployment or automation.",
        "ConfigTrace never reads ECS task logs or environment variable values.",
      ];
    }
    return ["Confirm the ECS service configuration change was authorized.", "ConfigTrace never reads ECS task logs or environment variable values."];
  }
  if (rt === "aws_ecs_task_definition") {
    const sfp = change.field_path ?? "";
    if (sfp === "has_privileged_container" && change.new_value === true) {
      return [
        "A privileged container was added to this task definition — containers run with host-level privileges.",
        "Review whether privileged mode is required; it greatly increases blast radius on compromise.",
        "Ensure the task definition was updated by an authorized party.",
        "ConfigTrace never reads ECS environment variable values or secret values.",
      ];
    }
    if (sfp === "secret_ref_count") {
      return [
        "The number of injected secrets changed — review the task definition for unintended additions or removals.",
        "ConfigTrace never reads ECS environment variable values or secret values.",
      ];
    }
    return ["Confirm the ECS task definition change was authorized.", "ConfigTrace never reads ECS environment variable values or secret values."];
  }

  // ── M46: EKS ──────────────────────────────────────────────────────────────
  if (rt === "aws_eks_cluster") {
    const sfp = change.field_path ?? "";
    if (sfp === "public_access_fully_open" && change.new_value === true) {
      return [
        "The EKS Kubernetes API is now accessible from any IP (0.0.0.0/0) — immediate action recommended.",
        "Restrict publicAccessCidrs to your organization's trusted IP ranges.",
        "Consider disabling public endpoint access and using private endpoint instead.",
        "ConfigTrace never calls the Kubernetes API or reads pod/secret/configmap data.",
      ];
    }
    if (sfp === "secrets_encryption_enabled" && change.new_value === false) {
      return [
        "Kubernetes Secrets encryption at rest was disabled — secrets in etcd are no longer KMS-encrypted.",
        "Re-enable envelope encryption with a customer-managed KMS key.",
        "ConfigTrace never calls the Kubernetes API or reads pod/secret data.",
      ];
    }
    if (sfp === "has_audit_logging" && change.new_value === false) {
      return [
        "EKS audit logging was disabled — Kubernetes API audit events will no longer be captured.",
        "Re-enable audit logging; it is essential for detecting unauthorized API calls.",
        "ConfigTrace never calls the Kubernetes API or reads pod/secret data.",
      ];
    }
    return [
      "Confirm the EKS cluster configuration change was authorized.",
      "ConfigTrace never calls the Kubernetes API or reads pod, secret, or configmap data.",
    ];
  }
  if (rt === "aws_eks_node_group") {
    if (change.field_path === "ssh_unrestricted" && change.new_value === true) {
      return [
        "EKS nodes are now accessible via SSH from any source — restrict the source security group immediately.",
        "If SSH access is required, limit it to a specific bastion/VPN security group.",
        "ConfigTrace never calls the Kubernetes API or reads pod/secret data.",
      ];
    }
    return ["Confirm the EKS node group configuration change was authorized.", "ConfigTrace never calls the Kubernetes API."];
  }
  if (rt === "aws_eks_fargate_profile") {
    return ["Confirm the EKS Fargate profile configuration change was authorized.", "ConfigTrace never calls the Kubernetes API."];
  }
  if (rt === "aws_eks_addon") {
    return ["Confirm the EKS add-on change was authorized and the new version is compatible.", "ConfigTrace never calls the Kubernetes API."];
  }

  // ── M46: ECR ──────────────────────────────────────────────────────────────
  if (rt === "aws_ecr_repository") {
    const sfp = change.field_path ?? "";
    if (sfp === "policy_is_public" && change.new_value === true) {
      return [
        "ECR repository policy now grants access to external principals or * — images may be publicly accessible.",
        "Review and restrict the repository policy to only authorized accounts and roles.",
        "Verify no unauthorized images were pushed during the window of public access.",
        "ConfigTrace never pulls images, reads image layers, or requests GetAuthorizationToken.",
      ];
    }
    if (sfp === "scan_on_push" && change.new_value === false) {
      return [
        "Scan-on-push was disabled — images pushed to this repository will not be automatically scanned for vulnerabilities.",
        "Re-enable scan-on-push or ensure images are scanned by another mechanism.",
        "ConfigTrace never pulls images or reads vulnerability scan findings.",
      ];
    }
    return ["Confirm the ECR repository configuration change was authorized.", "ConfigTrace never pulls images or reads image layers."];
  }
  if (rt === "aws_ecr_registry_scanning_config") {
    if (change.field_path === "scan_type" && String(change.new_value).toUpperCase() === "BASIC") {
      return [
        "ECR registry scanning was downgraded from ENHANCED to BASIC — continuous scanning across all images will stop.",
        "Enhanced scanning uses Amazon Inspector for continuous CVE coverage; BASIC only scans on push.",
        "Re-enable ENHANCED scanning if continuous vulnerability detection is required.",
        "ConfigTrace never reads vulnerability scan findings.",
      ];
    }
    if (change.field_path === "rule_count" && Number(change.new_value) === 0) {
      return [
        "All ECR registry scanning rules were removed — repositories may no longer be scanned.",
        "Add scanning rules to ensure image vulnerability coverage.",
        "ConfigTrace never reads vulnerability scan findings.",
      ];
    }
    return ["Confirm the ECR registry scanning configuration change was authorized.", "ConfigTrace never reads vulnerability scan findings."];
  }

  // ── M47: EventBridge ──────────────────────────────────────────────────────
  if (rt === "aws_eventbridge_event_bus") {
    const sfp = change.field_path ?? "";
    if (sfp === "public_or_cross_account_policy" && change.new_value === true) {
      return [
        "EventBridge event bus policy now allows external or '*' principals — review immediately.",
        "Restrict the bus resource policy to only authorized accounts and roles.",
        "Confirm no unauthorized cross-account event publishing is now possible.",
        "ConfigTrace does not read EventBridge event payloads.",
      ];
    }
    return [
      "Confirm this EventBridge event bus should exist in this region.",
      "If policy changed, review public/cross-account event access.",
      "ConfigTrace does not read EventBridge event payloads.",
    ];
  }
  if (rt === "aws_eventbridge_rule") {
    const sfp = change.field_path ?? "";
    if (sfp === "state" && change.new_value === "DISABLED") {
      return [
        "EventBridge rule was disabled — events matching this rule will not route to targets.",
        "Verify the disable was intentional and not caused by an automated process.",
        "Re-enable the rule if event routing must be restored.",
        "ConfigTrace does not read EventBridge event payloads.",
      ];
    }
    if (sfp === "target_count" && Number(change.new_value) === 0) {
      return [
        "EventBridge rule has zero targets — matching events will be silently discarded.",
        "Add at least one target to restore event routing.",
        "ConfigTrace does not read EventBridge event payloads.",
      ];
    }
    if (sfp === "event_pattern_hash") {
      return [
        "EventBridge rule event pattern changed — verify the new pattern routes the correct events.",
        "If accidental, restore the previous event pattern from version history.",
        "ConfigTrace does not read EventBridge event payloads.",
      ];
    }
    return [
      "Confirm this EventBridge rule should exist in this region.",
      "If target changed, confirm events still route to the expected destination.",
      "If DLQ/retry changed, confirm failure handling requirements are still met.",
      "ConfigTrace does not read EventBridge event payloads.",
    ];
  }
  if (rt === "aws_eventbridge_target") {
    return [
      "Confirm the EventBridge target change was authorized.",
      "Verify events still route to the expected destination.",
      "If DLQ was removed, confirm failure handling and replay requirements.",
      "ConfigTrace does not read EventBridge event payloads.",
    ];
  }
  if (rt === "aws_eventbridge_archive") {
    const sfp = change.field_path ?? "";
    if (sfp === "retention_days") {
      return [
        "EventBridge archive retention changed — verify event replay requirements are still met.",
        "Confirm the new retention period aligns with compliance and debugging needs.",
        "ConfigTrace does not read archived EventBridge event payloads.",
      ];
    }
    return [
      "Confirm the EventBridge archive change was authorized.",
      "Verify archive state and retention meet event replay requirements.",
      "ConfigTrace does not read archived EventBridge event payloads.",
    ];
  }

  // ── M47: SQS ──────────────────────────────────────────────────────────────
  if (rt === "aws_sqs_queue") {
    const sfp = change.field_path ?? "";
    if (sfp === "public_or_cross_account_policy" && change.new_value === true) {
      return [
        "SQS queue policy now allows external principals or '*' — review immediately.",
        "Restrict the queue policy to only authorized accounts and roles.",
        "Verify no unauthorized cross-account send/receive access is now possible.",
        "ConfigTrace does not read SQS messages.",
      ];
    }
    if ((sfp === "sqs_managed_sse_enabled" || sfp === "kms_master_key_id_present") && change.new_value === false) {
      return [
        "SQS queue encryption was removed or disabled — messages may no longer be encrypted at rest.",
        "Re-enable SSE or KMS encryption to meet security requirements.",
        "ConfigTrace does not read SQS messages.",
      ];
    }
    if (sfp === "redrive_policy_present" && change.new_value === false) {
      return [
        "SQS queue dead-letter/redrive policy was removed — failed messages will not be redirected to a DLQ.",
        "Re-add a redrive policy if failed message handling is required.",
        "ConfigTrace does not read SQS messages.",
      ];
    }
    return [
      "Confirm this SQS queue should exist in this region.",
      "If queue policy changed, review public/cross-account send/receive access.",
      "If encryption changed, confirm KMS/SSE requirements.",
      "If redrive policy changed, confirm failed-message handling.",
      "ConfigTrace does not read SQS messages.",
    ];
  }

  // ── M47: SNS ──────────────────────────────────────────────────────────────
  if (rt === "aws_sns_topic") {
    const sfp = change.field_path ?? "";
    if (sfp === "public_or_cross_account_policy" && change.new_value === true) {
      return [
        "SNS topic policy now allows external principals or '*' — review immediately.",
        "Restrict the topic policy to only authorized publishers and subscribers.",
        "Confirm no unauthorized cross-account publish access is now possible.",
        "ConfigTrace does not publish SNS messages or read notification contents.",
      ];
    }
    if (sfp === "kms_master_key_id_present" && change.new_value === false) {
      return [
        "SNS topic KMS encryption was removed — published messages may no longer be encrypted at rest.",
        "Re-enable KMS encryption if encryption requirements apply to this topic.",
        "ConfigTrace does not publish SNS messages or read notification contents.",
      ];
    }
    return [
      "Confirm this SNS topic should exist in this region.",
      "If topic policy changed, review public/cross-account publish/subscribe access.",
      "If subscription count changed, confirm endpoints are expected.",
      "If filter/redrive/delivery policy changed, confirm routing and failure handling.",
      "ConfigTrace does not publish SNS messages or read notification contents.",
    ];
  }
  if (rt === "aws_sns_subscription") {
    const sfp = change.field_path ?? "";
    if (sfp === "endpoint_hash") {
      return [
        "SNS subscription endpoint changed — verify the new destination is authorized.",
        "Confirm the endpoint change was intentional and not the result of unauthorized access.",
        "ConfigTrace does not store raw endpoint values or publish SNS messages.",
      ];
    }
    if (sfp === "filter_policy_hash" || sfp === "filter_policy_present") {
      return [
        "SNS subscription filter policy changed — verify the new filter routes expected message types.",
        "If the filter was removed, all topic messages will now be delivered to this endpoint.",
        "ConfigTrace does not publish SNS messages or read notification contents.",
      ];
    }
    return [
      "Confirm this SNS subscription should exist in this region.",
      "If endpoint changed, confirm the new destination is expected and authorized.",
      "If filter/redrive/delivery policy changed, confirm routing and failure handling.",
      "ConfigTrace does not publish SNS messages or read notification contents.",
    ];
  }

  // ── M48: KMS ──────────────────────────────────────────────────────────────
  if (rt === "aws_kms_key") {
    const sfp = change.field_path ?? "";
    if (change.change_type === "removed" || (sfp === "key_state" && String(change.new_value).toUpperCase() === "PENDINGDELETION")) {
      return [
        "Confirm KMS key deletion is intentional and all encrypted resources have been re-encrypted or migrated.",
        "Identify every service, bucket, RDS instance, or secret using this key before it is deleted.",
        "A deleted KMS key is unrecoverable — any data encrypted solely with it may be permanently inaccessible.",
        "Check AWS CloudTrail for who scheduled the deletion.",
        "ConfigTrace never calls kms:Decrypt, kms:Encrypt, or kms:GenerateDataKey.",
      ];
    }
    if (sfp === "enabled" && change.new_value === false) {
      return [
        "Confirm the KMS key was intentionally disabled.",
        "Resources using this key will fail to encrypt or decrypt data while it is disabled.",
        "Re-enable the key immediately if this was accidental.",
        "Check AWS CloudTrail for who disabled the key.",
        "ConfigTrace never calls kms:Decrypt, kms:Encrypt, or kms:GenerateDataKey.",
      ];
    }
    if (sfp === "public_or_cross_account_policy" && change.new_value === true) {
      return [
        "KMS key policy now allows external accounts or wildcard principals — review immediately.",
        "Restrict the key policy to only authorized accounts and roles.",
        "Verify no unauthorized cross-account decryption or encryption is now possible.",
        "Check AWS CloudTrail for who modified the key policy.",
        "ConfigTrace never calls kms:Decrypt, kms:Encrypt, or kms:GenerateDataKey.",
      ];
    }
    if (sfp === "wildcard_admin_policy" && change.new_value === true) {
      return [
        "KMS key policy now grants wildcard action to external principals — a potentially critical misconfiguration.",
        "Restrict the key policy to least-privilege actions for each authorized principal.",
        "Check AWS CloudTrail for who modified the key policy.",
        "ConfigTrace never calls kms:Decrypt, kms:Encrypt, or kms:GenerateDataKey.",
      ];
    }
    if (sfp === "rotation_enabled" && change.new_value === false) {
      return [
        "Confirm automatic key rotation was intentionally disabled for this KMS key.",
        "Review your compliance and key management policy requirements.",
        "Re-enable rotation in the AWS KMS Console if this was accidental.",
        "ConfigTrace never calls kms:Decrypt, kms:Encrypt, or kms:GenerateDataKey.",
      ];
    }
    return [
      "Confirm the KMS key configuration change was intentional.",
      "Check AWS CloudTrail for who made the change.",
      "Verify dependent encrypted resources are not affected.",
      "ConfigTrace never calls kms:Decrypt, kms:Encrypt, or kms:GenerateDataKey.",
    ];
  }
  if (rt === "aws_kms_alias") {
    const sfp = change.field_path ?? "";
    if (sfp === "target_key_id_hash") {
      return [
        "Confirm the KMS alias target key change was intentional.",
        "All resources that use this alias by name will now use the new key — verify encrypt/decrypt compatibility.",
        "Check AWS CloudTrail for who modified the alias.",
        "ConfigTrace never calls kms:Decrypt, kms:Encrypt, or kms:GenerateDataKey.",
      ];
    }
    if (change.change_type === "removed") {
      return [
        "Confirm the KMS alias was intentionally deleted.",
        "Resources that reference this alias by name will now fail until updated.",
        "Check AWS CloudTrail for who deleted the alias.",
        "ConfigTrace never calls kms:Decrypt, kms:Encrypt, or kms:GenerateDataKey.",
      ];
    }
    return [
      "Confirm the KMS alias change was intentional.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace never calls kms:Decrypt, kms:Encrypt, or kms:GenerateDataKey.",
    ];
  }

  // ── M48: Backup ────────────────────────────────────────────────────────────
  if (rt === "aws_backup_vault") {
    const sfp = change.field_path ?? "";
    if (sfp === "locked" && change.new_value === false) {
      return [
        "AWS Backup vault lock was removed — the vault and its recovery points may now be deletable.",
        "Confirm the lock removal was intentional and authorized.",
        "Review who made this change in AWS CloudTrail immediately.",
        "Re-apply vault lock if this was accidental — once deleted, recovery points cannot be restored.",
        "ConfigTrace never starts backup jobs, restores backups, or reads backup contents.",
      ];
    }
    if (sfp === "encryption_key_arn_present" && change.new_value === false) {
      return [
        "KMS encryption key was removed from this backup vault — recovery points may be stored unencrypted.",
        "Confirm this was intentional and meets your compliance requirements.",
        "ConfigTrace never starts backup jobs, restores backups, or reads backup contents.",
      ];
    }
    if (sfp === "recovery_points_count" && typeof change.new_value === "number" && typeof change.prev_value === "number" && change.new_value < (change.prev_value as number)) {
      return [
        "Recovery point count decreased in this backup vault — some backups may have been deleted or expired.",
        "Verify the decrease is due to intentional deletion or expected lifecycle expiration.",
        "Check AWS CloudTrail for recent DeleteRecoveryPoint operations.",
        "ConfigTrace never deletes recovery points, starts backup jobs, or restores backups.",
      ];
    }
    return [
      "Confirm the AWS Backup vault configuration change was intentional.",
      "Verify vault lock, encryption, and recovery point settings meet your requirements.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace never starts backup jobs, restores backups, or reads backup contents.",
    ];
  }
  if (rt === "aws_backup_plan") {
    const sfp = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "AWS Backup plan was removed — resources previously covered may no longer be backed up.",
        "Verify an alternative backup plan covers the affected resources.",
        "Check AWS CloudTrail for who deleted the backup plan.",
        "ConfigTrace never starts backup jobs, restores backups, or reads backup contents.",
      ];
    }
    if (sfp === "rule_count" && typeof change.new_value === "number" && typeof change.prev_value === "number" && change.new_value < (change.prev_value as number)) {
      return [
        "Backup rule count decreased — some backup schedules may have been removed.",
        "Confirm all required backup frequencies and vault targets are still in place.",
        "ConfigTrace never starts backup jobs, restores backups, or reads backup contents.",
      ];
    }
    if (sfp === "lifecycle_delete_after_days_min" && change.new_value === 0) {
      return [
        "A backup rule now has a zero-day delete lifecycle — recovery points may be deleted immediately on creation.",
        "Review the backup plan rules and correct the lifecycle configuration.",
        "ConfigTrace never starts backup jobs, restores backups, or reads backup contents.",
      ];
    }
    return [
      "Confirm the backup plan configuration change was intentional.",
      "Verify all required resources are still covered by the remaining backup rules.",
      "Check AWS CloudTrail for who made the change.",
      "ConfigTrace never starts backup jobs, restores backups, or reads backup contents.",
    ];
  }
  if (rt === "aws_backup_selection") {
    if (change.change_type === "removed") {
      return [
        "AWS Backup selection was removed — resources in this selection may no longer be backed up.",
        "Confirm the removal was intentional or move resources to another selection.",
        "Check AWS CloudTrail for who deleted the backup selection.",
        "ConfigTrace never starts backup jobs, restores backups, or reads backup contents.",
      ];
    }
    return [
      "Confirm the backup selection change was intentional.",
      "Verify the expected resources are still covered.",
      "ConfigTrace never starts backup jobs, restores backups, or reads backup contents.",
    ];
  }
  if (rt === "aws_backup_recovery_point") {
    const sfp = change.field_path ?? "";
    if (change.change_type === "removed" || (sfp === "status" && ["EXPIRED","DELETING","DELETED"].includes(String(change.new_value).toUpperCase()))) {
      return [
        "A backup recovery point was removed or is being deleted.",
        "Verify this is expected (lifecycle expiration) and not unauthorized deletion.",
        "Check AWS CloudTrail for recent DeleteRecoveryPoint operations.",
        "Confirm the database, resource, or workload can be recovered from an alternative point if needed.",
        "ConfigTrace never deletes recovery points, starts backup jobs, or restores backups.",
      ];
    }
    if (sfp === "is_encrypted" && change.new_value === false) {
      return [
        "This backup recovery point is unencrypted — verify your compliance requirements allow this.",
        "ConfigTrace never starts backup jobs, restores backups, or reads backup contents.",
      ];
    }
    return [
      "Confirm the backup recovery point change was intentional.",
      "ConfigTrace never starts backup jobs, restores backups, or reads backup contents.",
    ];
  }

  // ── M48: Organizations ─────────────────────────────────────────────────────
  if (rt === "aws_organizations_organization") {
    const sfp = change.field_path ?? "";
    if (sfp === "feature_set") {
      return [
        "AWS Organizations feature set changed — certain governance features (e.g. SCPs) require ALL features mode.",
        "Confirm this was intentional and authorized at the management account level.",
        "Reverting from ALL_FEATURES to CONSOLIDATED_BILLING disables SCPs, tag policies, and other guardrails.",
        "ConfigTrace does not mutate AWS Organizations or attach/detach/modify SCPs.",
      ];
    }
    if (sfp === "scp_count" && typeof change.new_value === "number" && typeof change.prev_value === "number" && change.new_value < (change.prev_value as number)) {
      return [
        "An SCP was removed from AWS Organizations — guardrails it enforced may no longer be in effect.",
        "Review the remaining SCPs to confirm all required preventive controls are still in place.",
        "Check AWS CloudTrail for who deleted the SCP.",
        "ConfigTrace does not mutate AWS Organizations or attach/detach/modify SCPs.",
      ];
    }
    return [
      "Confirm this AWS Organizations configuration change was authorized.",
      "ConfigTrace does not mutate AWS Organizations or attach/detach/modify SCPs.",
    ];
  }
  if (rt === "aws_organizations_account") {
    const sfp = change.field_path ?? "";
    if (sfp === "status" && ["SUSPENDED","PENDING_CLOSURE","CLOSED"].includes(String(change.new_value).toUpperCase())) {
      return [
        "An AWS Organizations member account status changed — verify this is intentional.",
        "Suspended or closed accounts may lose access to their workloads and data.",
        "Confirm this was authorized at the management account level.",
        "ConfigTrace does not mutate AWS Organizations or account memberships.",
      ];
    }
    return [
      "Confirm the AWS Organizations account change was authorized.",
      "ConfigTrace does not mutate AWS Organizations or account memberships.",
    ];
  }
  if (rt === "aws_organizations_ou") {
    const sfp = change.field_path ?? "";
    if (sfp === "attached_scp_count" && typeof change.new_value === "number" && typeof change.prev_value === "number" && change.new_value < (change.prev_value as number)) {
      return [
        "SCP count on this OU decreased — guardrails on this OU and its children may have been relaxed.",
        "Verify the remaining SCPs provide the required preventive controls for accounts in this OU.",
        "Check AWS CloudTrail for who detached the SCP.",
        "ConfigTrace does not mutate AWS Organizations or attach/detach SCPs.",
      ];
    }
    return [
      "Confirm the OU configuration change was authorized.",
      "ConfigTrace does not mutate AWS Organizations or attach/detach SCPs.",
    ];
  }
  if (rt === "aws_organizations_scp") {
    const sfp = change.field_path ?? "";
    if (change.change_type === "removed") {
      return [
        "An SCP was deleted from AWS Organizations — any guardrails it enforced are no longer active.",
        "Confirm the deletion was intentional and no required preventive controls have been lost.",
        "Verify that attached targets (OUs, accounts) have alternative SCP coverage.",
        "Check AWS CloudTrail for who deleted the policy.",
        "ConfigTrace does not mutate AWS Organizations or modify SCPs.",
      ];
    }
    if (sfp === "denies_full_admin_escape" && change.new_value === false) {
      return [
        "This SCP no longer prevents privilege escalation to full admin — this may be a critical security regression.",
        "Review the SCP to confirm the protective deny statement is still in place.",
        "Verify no unauthorized modification of the SCP occurred.",
        "Check AWS CloudTrail for who modified the policy.",
        "ConfigTrace does not mutate AWS Organizations or modify SCPs.",
      ];
    }
    if (sfp === "denied_action_count" && typeof change.new_value === "number" && typeof change.prev_value === "number" && change.new_value < (change.prev_value as number)) {
      return [
        "SCP denied action count decreased — some previously blocked actions may now be allowed.",
        "Review the updated SCP to confirm required deny controls are still present.",
        "Check AWS CloudTrail for who modified the SCP.",
        "ConfigTrace does not mutate AWS Organizations or modify SCPs.",
      ];
    }
    if (sfp === "attached_target_count" && typeof change.new_value === "number" && typeof change.prev_value === "number" && change.new_value < (change.prev_value as number)) {
      return [
        "SCP is now attached to fewer OUs or accounts — some previously guarded targets may now be unprotected.",
        "Confirm the detachment was intentional.",
        "Check AWS CloudTrail for who detached the policy.",
        "ConfigTrace does not mutate AWS Organizations or modify SCP attachments.",
      ];
    }
    return [
      "Confirm the SCP configuration change was authorized.",
      "Review the SCP deny statements to ensure required preventive controls are still present.",
      "ConfigTrace does not mutate AWS Organizations or modify SCPs.",
    ];
  }
  if (rt === "aws_organizations_scp_attachment") {
    if (change.change_type === "removed") {
      return [
        "An SCP was detached from an OU or account — that policy's guardrails no longer apply to the target.",
        "Verify the detachment was intentional and the target still has required SCP coverage.",
        "Check AWS CloudTrail for who detached the policy.",
        "ConfigTrace does not mutate AWS Organizations or modify SCP attachments.",
      ];
    }
    return [
      "Confirm the SCP attachment change was authorized.",
      "ConfigTrace does not mutate AWS Organizations or modify SCP attachments.",
    ];
  }

  // ── M49: CloudWatch Alarms + Observability ─────────────────────────────────
  if (rt === "aws_cloudwatch_metric_alarm") {
    if (change.change_type === "removed") {
      return [
        "A CloudWatch metric alarm was removed — monitoring coverage for this metric may be gone.",
        "Verify the deletion was intentional and that alternative alerting is in place.",
        "Check AWS CloudTrail for who deleted the alarm.",
        "ConfigTrace reads alarm configuration only — metric datapoints are never accessed.",
      ];
    }
    if (change.field_path === "actions_enabled" && change.new_value === false) {
      return [
        "CloudWatch alarm actions are disabled — notifications and auto-remediation will not fire.",
        "Re-enable actions via the CloudWatch console or AWS CLI.",
        "Check CloudTrail to identify who disabled alarm actions.",
        "ConfigTrace does not modify CloudWatch alarm configurations.",
      ];
    }
    if (change.field_path === "alarm_state_value" && String(change.new_value ?? "").toUpperCase() === "ALARM") {
      return [
        "A CloudWatch alarm entered ALARM state — investigate the metric threshold breach.",
        "Review the alarm's metric and threshold configuration in the CloudWatch console.",
        "ConfigTrace reads alarm configuration only; metric datapoints are never accessed.",
      ];
    }
    return [
      "Review the CloudWatch alarm configuration change.",
      "Verify threshold and notification targets are correct.",
      "ConfigTrace reads alarm configuration only — metric datapoints are never accessed.",
    ];
  }

  if (rt === "aws_cloudwatch_composite_alarm") {
    if (change.change_type === "removed") {
      return [
        "A CloudWatch composite alarm was removed — composite alerting coverage may have changed.",
        "Verify the deletion was intentional.",
        "Check AWS CloudTrail for who deleted the alarm.",
        "ConfigTrace does not modify CloudWatch alarm configurations.",
      ];
    }
    if (change.field_path === "actions_enabled" && change.new_value === false) {
      return [
        "CloudWatch composite alarm actions are disabled — notifications will not fire.",
        "Re-enable actions via the CloudWatch console.",
        "ConfigTrace does not modify CloudWatch alarm configurations.",
      ];
    }
    if (change.field_path === "alarm_rule_hash") {
      return [
        "The composite alarm rule expression changed — verify the child alarm set is correct.",
        "ConfigTrace stores the rule as a hash only; the raw expression is not stored.",
        "Check CloudTrail to identify who modified the alarm rule.",
      ];
    }
    return [
      "Review the CloudWatch composite alarm configuration change.",
      "ConfigTrace does not modify CloudWatch alarm configurations.",
    ];
  }

  if (rt === "aws_cloudwatch_log_group") {
    if (change.change_type === "removed") {
      return [
        "A CloudWatch Logs log group was removed — all metric filters and subscription filters for it are gone.",
        "Verify the deletion was intentional.",
        "Check CloudTrail for who deleted the log group.",
        "ConfigTrace reads log group configuration only — log events are never accessed.",
      ];
    }
    if ((change.field_path === "retention_configured" && change.new_value === false) ||
        (change.field_path === "retention_in_days")) {
      return [
        "Log group retention was removed or reduced — older logs will be purged sooner.",
        "Review compliance requirements for log retention periods.",
        "Set an appropriate retention period in the CloudWatch Logs console.",
        "ConfigTrace reads log group configuration only — log events are never accessed.",
      ];
    }
    if (change.field_path === "kms_key_id_present" && change.new_value === false) {
      return [
        "Log group KMS encryption was removed — logs at rest are no longer encrypted with a CMK.",
        "Re-enable KMS encryption if required by your compliance policy.",
        "Check CloudTrail for who removed the encryption key association.",
        "ConfigTrace does not modify log group encryption settings.",
      ];
    }
    return [
      "Review the CloudWatch Logs log group configuration change.",
      "ConfigTrace reads log group configuration only — log events are never accessed.",
    ];
  }

  if (rt === "aws_cloudwatch_metric_filter") {
    if (change.change_type === "removed") {
      return [
        "A CloudWatch Logs metric filter was removed — metrics derived from this log pattern are no longer generated.",
        "Verify any alarms relying on this metric are still valid.",
        "ConfigTrace stores filter patterns as hashes; raw patterns are not stored.",
      ];
    }
    return [
      "Review the metric filter change — alarms relying on the derived metric may be affected.",
      "ConfigTrace stores filter patterns as hashes; raw patterns are not stored.",
    ];
  }

  if (rt === "aws_cloudwatch_subscription_filter") {
    if (change.change_type === "removed") {
      return [
        "A CloudWatch Logs subscription filter was removed — log streaming to the destination has stopped.",
        "Verify the removal was intentional and that log archiving/SIEM ingestion is unaffected.",
        "ConfigTrace reads subscription filter configuration only — log events are never read.",
      ];
    }
    return [
      "Review the subscription filter destination and pattern change.",
      "Verify the destination is authorized and log streaming is working.",
      "ConfigTrace reads subscription filter configuration only — log events are never read.",
    ];
  }

  if (rt === "aws_cloudwatch_metric_stream") {
    if (change.change_type === "removed") {
      return [
        "A CloudWatch metric stream was removed — metric data is no longer being streamed to the destination.",
        "Verify the removal was intentional.",
        "ConfigTrace reads metric stream configuration only — metric datapoints are never accessed.",
      ];
    }
    if (change.field_path === "state" && ["stopped", "disabled"].includes(String(change.new_value ?? "").toLowerCase())) {
      return [
        "A CloudWatch metric stream was stopped — metric streaming to the destination has halted.",
        "Verify this was intentional and re-start the stream if needed.",
        "ConfigTrace reads metric stream configuration only — metric datapoints are never accessed.",
      ];
    }
    return [
      "Review the metric stream configuration change.",
      "ConfigTrace reads metric stream configuration only — metric datapoints are never accessed.",
    ];
  }

  if (rt === "aws_cloudwatch_anomaly_detector") {
    if (change.change_type === "removed") {
      return [
        "A CloudWatch anomaly detector was removed — anomaly detection for this metric/namespace is no longer active.",
        "Verify the removal was intentional.",
        "ConfigTrace reads anomaly detector configuration only.",
      ];
    }
    return [
      "Review the anomaly detector configuration change.",
      "ConfigTrace reads anomaly detector configuration only — anomaly results are never accessed.",
    ];
  }

  // AWS
  if (rt === "aws_account_identity") {
    const fp4 = change.field_path ?? "";
    if (fp4 === "principal_arn") {
      return [
        "Confirm the IAM principal change was intentional.",
        "Verify the new ARN belongs to the expected read-only IAM user or role.",
        "Check AWS CloudTrail for recent IAM key creation or rotation events.",
        "If unauthorized, rotate or disable the new credentials immediately.",
        "Review IAM access logs to confirm no write actions occurred.",
      ];
    }
    if (fp4 === "account_id") {
      return [
        "Confirm this change was intentional — the integration may point at a different AWS account.",
        "Verify the connected IAM credentials belong to the expected account.",
        "Check for accidental key substitution during credential rotation.",
        "Re-connect with the correct credentials if this was unintentional.",
      ];
    }
    return [
      "Confirm the AWS account identity change was intentional.",
      "Verify the IAM credentials belong to the expected read-only user or role.",
      "Check AWS CloudTrail for recent account-level activity.",
    ];
  }
  if (rt === "aws_region") {
    const regionId2 = change.record_identifier;
    if (change.change_type === "removed") {
      return [
        `Confirm that AWS region ${regionId2} was intentionally removed from monitoring.`,
        "Verify no important resources exist in this region that should still be tracked.",
        "Update the integration's selected regions if removal was accidental.",
      ];
    }
    return [
      "Confirm the AWS region monitoring change was intentional.",
      "Verify the new region list reflects your intended infrastructure footprint.",
    ];
  }
  if (rt.startsWith("aws_")) {
    return [
      "Confirm the AWS configuration change was intentional.",
      "Review the AWS IAM Console to verify credentials and permissions are correct.",
      "Check AWS CloudTrail for recent activity.",
    ];
  }

  // Firebase
  if (rt === "firebase_firestore_ruleset") {
    return [
      "Review the active Firestore security ruleset in the Firebase Console.",
      "Confirm public read/write access is intentional — require request.auth for sensitive paths.",
      "Redeploy the previous ruleset if the change was accidental.",
      "Check Firebase audit logs for who deployed the ruleset.",
    ];
  }
  if (rt === "firebase_storage_ruleset") {
    return [
      "Review the active Storage security ruleset in the Firebase Console.",
      "Confirm public read/write access is intentional.",
      "Redeploy the previous ruleset if the change was accidental.",
      "Check Firebase audit logs for who deployed the ruleset.",
    ];
  }
  if (rt === "firebase_auth_config" || rt === "firebase_auth_provider") {
    return [
      "Confirm the Auth configuration change was intentional.",
      "Verify existing users can still sign in after the change.",
      "Check Firebase audit logs for who made the change.",
      "Revert the change in Firebase Console → Authentication if accidental.",
    ];
  }
  if (rt === "firebase_authorized_domain") {
    return [
      "Confirm the authorized domain change was intentional.",
      "Remove unrecognized domains from Firebase Console → Authentication → Settings → Authorized domains.",
      "Verify your app sign-in flows still work correctly.",
    ];
  }
  if (rt.startsWith("firebase_")) {
    return [
      "Confirm this Firebase configuration change was intentional.",
      "Review the affected setting in the Firebase Console.",
      "Verify app functionality is not affected.",
      "Check Firebase audit logs for recent changes.",
    ];
  }

  // Supabase
  if (rt === "supabase_rls_status") {
    return [
      "Confirm RLS should be enabled for this table if it is client-accessible via the API.",
      "Review anon and public role policies in the Supabase Dashboard → Authentication.",
      "Re-enable RLS if it was disabled unintentionally.",
    ];
  }
  if (rt === "supabase_auth_config") {
    return [
      "Confirm Auth settings were changed intentionally.",
      "Verify JWT verification is enabled if it was modified.",
      "Test user authentication flows after the change.",
      "Review the Supabase Dashboard → Authentication → Settings.",
    ];
  }
  if (rt === "supabase_network_restriction") {
    return [
      "Confirm network restriction changes were intentional.",
      "Verify the allowed IP ranges include all expected connection sources.",
      "Re-add restrictions in the Supabase Dashboard if removed accidentally.",
    ];
  }
  if (rt.startsWith("supabase_")) {
    return [
      "Confirm this Supabase configuration change was intentional.",
      "Review the affected setting in the Supabase Dashboard.",
      "Verify database connectivity and auth are functioning.",
    ];
  }

  // Shopify
  if (rt === "shopify_shop_metadata") {
    const fpShop = change.field_path ?? "";
    if (fpShop === "password_protected" && change.new_value === false) {
      return [
        "Confirm that removing storefront password protection was intentional.",
        "Verify your store is ready for public access.",
        "Check the Shopify Admin → Online Store → Preferences for current protection status.",
        "Re-enable password protection in the Shopify Admin if this was accidental.",
      ];
    }
    return [
      "Confirm the Shopify store settings change was intentional.",
      "Review the Shopify Admin → Settings for affected configuration.",
      "Verify storefront behavior is as expected after the change.",
    ];
  }
  if (rt === "shopify_webhook_subscription") {
    const fpWebhook = change.field_path ?? "";
    if (fpWebhook === "address") {
      return [
        "Confirm the webhook delivery URL change was intentional.",
        "Verify the new endpoint URL is under your control.",
        "Check the Shopify Admin → Settings → Notifications for webhook configuration.",
        "Test that events are being delivered to the new endpoint.",
        "Restore the previous URL immediately if this was unauthorized.",
      ];
    }
    if (change.change_type === "removed") {
      return [
        "Confirm the webhook deletion was intentional.",
        "Verify that no integrations relied on events from this subscription.",
        "Re-add the webhook in the Shopify Admin if this was accidental.",
      ];
    }
    return [
      "Confirm the webhook change was intentional.",
      "Verify the delivery URL and subscribed topics are correct.",
      "Test that events are being received by the correct endpoint.",
    ];
  }
  if (rt === "shopify_app_scope_summary") {
    return [
      "Review the Shopify app's permission scopes in the Partners dashboard or Shopify Admin → Apps.",
      "Confirm the scope changes correspond to an authorized app update or install.",
      "Verify no unexpected scopes were added that could allow broader data access.",
      "Revoke and reinstall the app if unauthorized scope changes are suspected.",
    ];
  }
  if (rt.startsWith("shopify_")) {
    return [
      "Confirm this Shopify configuration change was intentional.",
      "Review the Shopify Admin for affected settings.",
      "Verify store integrations and webhooks are functioning correctly.",
    ];
  }

  // Cloudflare DNS
  const recordType = ((change.provider_metadata?.record_type as string | undefined) ?? "").toUpperCase();
  const recordName = ((change.provider_metadata?.record_name as string | undefined) ?? "").toLowerCase();
  const isEmailAuth =
    (recordType === "MX") ||
    (recordType === "TXT" && ["_dmarc", "_domainkey", "spf"].some((kw) => recordName.includes(kw)));

  if (isEmailAuth) {
    return [
      "Confirm this change was intentional.",
      "Test email delivery to verify SPF, DKIM, and DMARC are still valid.",
      "Verify your email provider's DNS configuration is intact.",
      "Check Cloudflare audit logs for who made the change.",
      "Restore the record if this was accidental.",
    ];
  }
  return [
    "Confirm this change was intentional.",
    "Test the affected hostname (dig, nslookup, or browser).",
    "Verify the new target or IP address is correct.",
    "Check Cloudflare audit logs for who made the change.",
    "Roll back the DNS record if this was accidental.",
  ];
}

// ── Provider metadata context ─────────────────────────────────────────────────

const META_DISPLAY_KEYS: Array<{ key: string; label: string }> = [
  { key: "provider",      label: "Provider"      },
  { key: "resource_type", label: "Resource type" },
  { key: "record_type",   label: "Record type"   },
  { key: "record_name",   label: "Record name"   },
  { key: "record_content",label: "Content"       },
  { key: "zone_name",     label: "Zone"          },
  { key: "zone_id",       label: "Zone ID"       },
];

function ProviderMetaRows({
  metadata,
}: {
  metadata: Record<string, unknown> | null | undefined;
}) {
  if (!metadata) return null;

  const known = META_DISPLAY_KEYS.filter(
    (k) => metadata[k.key] !== undefined && metadata[k.key] !== null,
  );

  if (known.length === 0) return null;

  return (
    <div style={{ marginTop: "12px" }}>
      <p
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: "6px",
          fontWeight: 500,
        }}
      >
        Context
      </p>
      {known.map(({ key, label }) => (
        <div
          key={key}
          className="flex items-baseline gap-2"
          style={{ marginBottom: "3px" }}
        >
          <span
            style={{
              width: "96px",
              flexShrink: 0,
              fontSize: "11px",
              color: "#565b6e",
            }}
          >
            {label}
          </span>
          <span
            style={{
              fontSize: "12px",
              color: "#8b90a0",
              fontFamily: "monospace",
            }}
          >
            {String(metadata[key])}
          </span>
        </div>
      ))}
    </div>
  );
}

// ── Snapshot context panel ────────────────────────────────────────────────────

function SnapshotContextPanel({ change }: { change: ChangeDetail }) {
  const hasPrev = Boolean(change.prev_snapshot_id);
  const hasNew  = Boolean(change.new_snapshot_id);

  if (!hasPrev && !hasNew) return null;

  // Try to find the specific record within a snapshot state array.
  function findRecord(
    state: DnsRecord[] | null,
  ): Record<string, unknown> | null {
    if (!state || state.length === 0) return null;

    // 1. Match by provider external_id / record_id
    const extId =
      (change.provider_metadata as Record<string, unknown> | null)
        ?.external_id ?? null;
    if (extId) {
      const hit = state.find(
        (r) => r.record_id === extId || (r as Record<string, unknown>).id === extId,
      );
      if (hit) return hit as Record<string, unknown>;
    }

    // 2. Match by record_identifier against name field
    const hit = state.find((r) => r.name === change.record_identifier);
    if (hit) return hit as Record<string, unknown>;

    return null;
  }

  const prevRecord = findRecord(change.prev_snapshot_state ?? null);
  const newRecord  = findRecord(change.new_snapshot_state ?? null);
  const showRecords = change.change_type === "modified" && (prevRecord || newRecord);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
      {/* Snapshot timestamps + IDs */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "12px",
        }}
      >
        {hasPrev && (
          <div
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              padding: "10px 12px",
            }}
          >
            <p
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                marginBottom: "4px",
              }}
            >
              Before snapshot
            </p>
            <p
              style={{ fontSize: "13px", color: "#e8eaf0", marginBottom: "2px" }}
              title={
                change.prev_snapshot_created_at
                  ? formatAbsoluteTime(change.prev_snapshot_created_at)
                  : undefined
              }
            >
              {change.prev_snapshot_created_at
                ? formatRelativeTime(change.prev_snapshot_created_at)
                : "—"}
            </p>
            {change.prev_snapshot_id && (
              <p
                style={{
                  fontFamily: "monospace",
                  fontSize: "11px",
                  color: "#565b6e",
                }}
              >
                {formatSnapshotHash(change.prev_snapshot_id)}
              </p>
            )}
          </div>
        )}

        {hasNew && (
          <div
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              padding: "10px 12px",
            }}
          >
            <p
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                marginBottom: "4px",
              }}
            >
              After snapshot
            </p>
            <p
              style={{ fontSize: "13px", color: "#e8eaf0", marginBottom: "2px" }}
              title={
                change.new_snapshot_created_at
                  ? formatAbsoluteTime(change.new_snapshot_created_at)
                  : undefined
              }
            >
              {change.new_snapshot_created_at
                ? formatRelativeTime(change.new_snapshot_created_at)
                : "—"}
            </p>
            {change.new_snapshot_id && (
              <p
                style={{
                  fontFamily: "monospace",
                  fontSize: "11px",
                  color: "#565b6e",
                }}
              >
                {formatSnapshotHash(change.new_snapshot_id)}
              </p>
            )}
          </div>
        )}
      </div>

      {/* Specific record in both snapshots — only for "modified" changes */}
      {showRecords && (
        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          <p style={{ fontSize: "12px", color: "#565b6e" }}>
            Record state at each snapshot:
          </p>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "12px",
            }}
          >
            <div>
              <p
                style={{
                  fontSize: "11px",
                  color: "#565b6e",
                  marginBottom: "6px",
                }}
              >
                Before
              </p>
              {prevRecord ? (
                <DnsRecordView record={prevRecord} tint="remove" />
              ) : (
                <p style={{ fontSize: "12px", color: "#565b6e", fontStyle: "italic" }}>
                  Record not found in snapshot.
                </p>
              )}
            </div>
            <div>
              <p
                style={{
                  fontSize: "11px",
                  color: "#565b6e",
                  marginBottom: "6px",
                }}
              >
                After
              </p>
              {newRecord ? (
                <DnsRecordView record={newRecord} tint="add" />
              ) : (
                <p style={{ fontSize: "12px", color: "#565b6e", fontStyle: "italic" }}>
                  Record not found in snapshot.
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Raw / debug section ───────────────────────────────────────────────────────

function RawSection({ change }: { change: ChangeDetail }) {
  const raw = {
    prev_value:        change.prev_value,
    new_value:         change.new_value,
    provider_metadata: change.provider_metadata,
  };

  return (
    <details
      style={{
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        overflow: "hidden",
      }}
    >
      <summary
        style={{
          padding: "10px 14px",
          fontSize: "12px",
          color: "#565b6e",
          cursor: "pointer",
          userSelect: "none",
          background: "#13151a",
          listStyle: "none",
          display: "flex",
          alignItems: "center",
          gap: "6px",
        }}
      >
        <span>▶</span>
        <span>Raw change data</span>
      </summary>
      <div style={{ background: "#0e0f11", padding: "12px 14px" }}>
        <pre
          style={{
            fontFamily: "monospace",
            fontSize: "12px",
            color: "#565b6e",
            margin: 0,
            whiteSpace: "pre-wrap",
            wordBreak: "break-all",
          }}
        >
          {JSON.stringify(raw, null, 2)}
        </pre>
      </div>
    </details>
  );
}

// ── M57.2: Review Panel ───────────────────────────────────────────────────────

const REVIEW_STATUS_LABELS: Record<ReviewStatus, string> = {
  needs_review:  "Needs Review",
  acknowledged:  "Acknowledged",
  expected:      "Expected",
  snoozed:       "Snoozed",
};

const REVIEW_STATUS_COLORS: Record<ReviewStatus, string> = {
  needs_review:  "#f5a623",
  acknowledged:  "#3ccf7e",
  expected:      "#4f80f7",
  snoozed:       "#8b5cf6",
};

function addDays(date: Date, days: number): string {
  const d = new Date(date.getTime() + days * 24 * 60 * 60 * 1000);
  return d.toISOString();
}

interface ReviewPanelProps {
  changeId: string;
  review: ChangeReviewResponse | null;
  onReviewUpdated: (r: ChangeReviewResponse) => void;
}

function ReviewPanel({ changeId, review, onReviewUpdated }: ReviewPanelProps) {
  const { getToken } = useAuth();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Snooze modal state
  const [showSnoozeModal, setShowSnoozeModal] = useState(false);
  const [snoozeUntil, setSnoozeUntil] = useState("");
  const [snoozeReason, setSnoozeReason] = useState("");

  // Note input (for ack/expected/reopen)
  const [showNoteInput, setShowNoteInput] = useState<null | "acknowledge" | "expected" | "reopen">(null);
  const [noteValue, setNoteValue] = useState("");

  const currentStatus: ReviewStatus = review?.review_status ?? "needs_review";

  async function doAcknowledge(note?: string) {
    setBusy(true);
    setErr(null);
    try {
      const token = await getToken();
      const r = await acknowledgeChange(changeId, { note }, token);
      onReviewUpdated(r);
      setShowNoteInput(null);
      setNoteValue("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to acknowledge.");
    } finally {
      setBusy(false);
    }
  }

  async function doMarkExpected(note?: string) {
    setBusy(true);
    setErr(null);
    try {
      const token = await getToken();
      const r = await markChangeExpected(changeId, { note }, token);
      onReviewUpdated(r);
      setShowNoteInput(null);
      setNoteValue("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to mark as expected.");
    } finally {
      setBusy(false);
    }
  }

  async function doSnooze() {
    if (!snoozeUntil) return;
    setBusy(true);
    setErr(null);
    try {
      const token = await getToken();
      const r = await snoozeChange(changeId, { until: snoozeUntil, reason: snoozeReason || undefined }, token);
      onReviewUpdated(r);
      setShowSnoozeModal(false);
      setSnoozeUntil("");
      setSnoozeReason("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to snooze.");
    } finally {
      setBusy(false);
    }
  }

  async function doReopen(note?: string) {
    setBusy(true);
    setErr(null);
    try {
      const token = await getToken();
      const r = await reopenChange(changeId, { note }, token);
      onReviewUpdated(r);
      setShowNoteInput(null);
      setNoteValue("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to reopen.");
    } finally {
      setBusy(false);
    }
  }

  const statusColor = REVIEW_STATUS_COLORS[currentStatus];
  const statusLabel = REVIEW_STATUS_LABELS[currentStatus];

  const isReviewed = currentStatus !== "needs_review";

  const btnBase: React.CSSProperties = {
    background: "none",
    border: "1px solid #2a2d38",
    borderRadius: "5px",
    padding: "5px 12px",
    fontSize: "12px",
    cursor: busy ? "not-allowed" : "pointer",
    fontFamily: "inherit",
    color: "#c4c8d4",
    opacity: busy ? 0.6 : 1,
  };

  const btnPrimary: React.CSSProperties = {
    ...btnBase,
    background: "#1a2a1a",
    border: "1px solid rgba(60,207,126,0.3)",
    color: "#3ccf7e",
  };

  return (
    <section aria-labelledby="section-review">
      <h2
        id="section-review"
        style={{ fontSize: "13px", fontWeight: 500, color: "#c4c8d4", margin: "0 0 10px" }}
      >
        Review
      </h2>

      <div
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "6px",
          padding: "16px",
        }}
      >
        {/* Status row */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "12px" }}>
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "5px",
              background: `${statusColor}18`,
              border: `1px solid ${statusColor}40`,
              borderRadius: "5px",
              padding: "3px 10px",
              fontSize: "11px",
              fontWeight: 600,
              color: statusColor,
              textTransform: "uppercase",
              letterSpacing: "0.07em",
            }}
          >
            {statusLabel}
          </span>

          {review?.reviewed_at && (
            <span style={{ fontSize: "11px", color: "#565b6e" }}>
              {currentStatus === "snoozed" ? "Snoozed" : "Reviewed"}{" "}
              {new Date(review.reviewed_at).toLocaleDateString(undefined, {
                month: "short", day: "numeric", year: "numeric",
              })}
            </span>
          )}
        </div>

        {/* Snooze expiry */}
        {currentStatus === "snoozed" && review?.snoozed_until && (
          <p style={{ fontSize: "12px", color: "#8b5cf6", margin: "0 0 8px" }}>
            Snoozed until{" "}
            <strong>
              {new Date(review.snoozed_until).toLocaleDateString(undefined, {
                month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit",
              })}
            </strong>
            {review.snooze_reason ? ` · "${review.snooze_reason}"` : ""}
          </p>
        )}

        {/* Review note */}
        {review?.review_note && (
          <p
            style={{
              fontSize: "12px",
              color: "#8b90a0",
              fontStyle: "italic",
              margin: "0 0 12px",
              background: "#1a1d28",
              borderRadius: "4px",
              padding: "6px 10px",
              border: "1px solid #2a2d38",
            }}
          >
            &ldquo;{review.review_note}&rdquo;
          </p>
        )}

        {/* Context copy */}
        {!isReviewed && (
          <p style={{ fontSize: "12px", color: "#565b6e", margin: "0 0 12px" }}>
            Record that this change was reviewed by your team.
            Snoozed changes are hidden from review counts until the snooze expires.
          </p>
        )}

        {/* Error */}
        {err && (
          <p style={{ fontSize: "12px", color: "#f87171", margin: "0 0 10px" }}>{err}</p>
        )}

        {/* Inline note input */}
        {showNoteInput && (
          <div style={{ marginBottom: "10px", display: "flex", flexDirection: "column", gap: "6px" }}>
            <textarea
              value={noteValue}
              onChange={(e) => setNoteValue(e.target.value)}
              placeholder="Optional note (max 1000 chars)…"
              maxLength={1000}
              rows={2}
              style={{
                width: "100%",
                background: "#1a1d28",
                border: "1px solid #3a3d4a",
                borderRadius: "5px",
                padding: "6px 10px",
                fontSize: "12px",
                color: "#e2e5ef",
                fontFamily: "inherit",
                resize: "vertical",
                outline: "none",
                boxSizing: "border-box",
              }}
            />
            <div style={{ display: "flex", gap: "8px" }}>
              <button
                style={{ ...btnPrimary }}
                disabled={busy}
                onClick={() => {
                  if (showNoteInput === "acknowledge") doAcknowledge(noteValue || undefined);
                  else if (showNoteInput === "expected") doMarkExpected(noteValue || undefined);
                  else if (showNoteInput === "reopen") doReopen(noteValue || undefined);
                }}
              >
                Confirm
              </button>
              <button
                style={{ ...btnBase }}
                onClick={() => { setShowNoteInput(null); setNoteValue(""); }}
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Snooze modal */}
        {showSnoozeModal && (
          <div
            style={{
              background: "#1a1d28",
              border: "1px solid #3a3d4a",
              borderRadius: "6px",
              padding: "12px",
              marginBottom: "10px",
            }}
          >
            <p style={{ fontSize: "12px", color: "#8b90a0", margin: "0 0 8px" }}>
              Snoozing hides this change from review counts until the selected time.
            </p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginBottom: "8px" }}>
              {([
                ["1 day",   1],
                ["7 days",  7],
                ["30 days", 30],
              ] as const).map(([label, days]) => (
                <button
                  key={days}
                  style={{
                    ...btnBase,
                    background: snoozeUntil === addDays(new Date(), days).slice(0, 16) + ":00.000Z"
                      ? "rgba(139,92,246,0.15)" : "none",
                    borderColor: "rgba(139,92,246,0.35)",
                    color: "#8b5cf6",
                  }}
                  onClick={() => setSnoozeUntil(addDays(new Date(), days))}
                >
                  {label}
                </button>
              ))}
            </div>
            <input
              type="datetime-local"
              value={snoozeUntil ? snoozeUntil.slice(0, 16) : ""}
              onChange={(e) =>
                setSnoozeUntil(e.target.value ? new Date(e.target.value).toISOString() : "")
              }
              style={{
                background: "#1c1e26",
                border: "1px solid #3a3d4a",
                borderRadius: "5px",
                padding: "5px 8px",
                fontSize: "12px",
                color: "#e2e5ef",
                fontFamily: "inherit",
                marginBottom: "8px",
                display: "block",
                width: "100%",
                boxSizing: "border-box",
              }}
            />
            <input
              type="text"
              placeholder="Reason (optional)…"
              value={snoozeReason}
              onChange={(e) => setSnoozeReason(e.target.value)}
              maxLength={1000}
              style={{
                background: "#1c1e26",
                border: "1px solid #3a3d4a",
                borderRadius: "5px",
                padding: "5px 8px",
                fontSize: "12px",
                color: "#e2e5ef",
                fontFamily: "inherit",
                marginBottom: "8px",
                display: "block",
                width: "100%",
                boxSizing: "border-box",
              }}
            />
            <div style={{ display: "flex", gap: "8px" }}>
              <button
                style={{ ...btnBase, borderColor: "rgba(139,92,246,0.35)", color: "#8b5cf6" }}
                disabled={busy || !snoozeUntil}
                onClick={doSnooze}
              >
                Snooze
              </button>
              <button
                style={{ ...btnBase }}
                onClick={() => { setShowSnoozeModal(false); setSnoozeUntil(""); setSnoozeReason(""); }}
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Action buttons */}
        {!showNoteInput && !showSnoozeModal && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
            {currentStatus !== "acknowledged" && (
              <button
                style={{ ...btnBase, borderColor: "rgba(60,207,126,0.3)", color: "#3ccf7e" }}
                disabled={busy}
                onClick={() => { setShowNoteInput("acknowledge"); setNoteValue(""); setErr(null); }}
              >
                ✓ Acknowledge
              </button>
            )}
            {currentStatus !== "expected" && (
              <button
                style={{ ...btnBase, borderColor: "rgba(79,128,247,0.3)", color: "#4f80f7" }}
                disabled={busy}
                onClick={() => { setShowNoteInput("expected"); setNoteValue(""); setErr(null); }}
              >
                ◎ Mark Expected
              </button>
            )}
            {currentStatus !== "snoozed" && (
              <button
                style={{ ...btnBase, borderColor: "rgba(139,92,246,0.3)", color: "#8b5cf6" }}
                disabled={busy}
                onClick={() => { setShowSnoozeModal(true); setErr(null); }}
              >
                ⏸ Snooze
              </button>
            )}
            {isReviewed && (
              <button
                style={{ ...btnBase, color: "#8b90a0" }}
                disabled={busy}
                onClick={() => { setShowNoteInput("reopen"); setNoteValue(""); setErr(null); }}
              >
                ↩ Reopen
              </button>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

// ── Fix plan subsection ───────────────────────────────────────────────────────

const SAFETY_META: Record<
  import("@/lib/remediation").FixPlanSafetyLevel,
  { label: string; color: string; border: string }
> = {
  safe_to_preview:       { label: "Safe to preview",        color: "#22c55e", border: "rgba(34,197,94,0.30)"  },
  requires_human_review: { label: "Requires human review",  color: "#f5a623", border: "rgba(245,166,35,0.30)" },
  not_recommended:       { label: "Not recommended",        color: "#e84040", border: "rgba(232,64,64,0.30)"  },
};

const KIND_LABEL: Record<import("@/lib/remediation").FixPlanKind, string> = {
  command:          "CLI command",
  guided_manual:    "Guided manual fix",
  provider_console: "Provider console",
  not_supported:    "Not supported",
};

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard API unavailable — silently fail
    }
  }

  return (
    <button
      onClick={handleCopy}
      aria-label={copied ? "Copied" : "Copy command to clipboard"}
      style={{
        background: copied ? "rgba(34,197,94,0.12)" : "rgba(255,255,255,0.05)",
        border: `1px solid ${copied ? "rgba(34,197,94,0.3)" : "#3a3d4a"}`,
        borderRadius: "4px",
        color: copied ? "#22c55e" : "#8b90a0",
        cursor: "pointer",
        fontSize: "10px",
        fontFamily: "inherit",
        fontWeight: 500,
        padding: "3px 9px",
        flexShrink: 0,
        transition: "all 0.15s",
        letterSpacing: "0.03em",
      }}
    >
      {copied ? "Copied ✓" : "Copy"}
    </button>
  );
}

function FixPlanSubsection({
  fixPlan,
  dividerColor,
}: {
  fixPlan: FixPlan;
  dividerColor: string;
}) {
  const safety = SAFETY_META[fixPlan.safety_level];

  return (
    <div
      style={{
        marginTop: "14px",
        paddingTop: "14px",
        borderTop: `1px solid ${dividerColor}`,
      }}
    >
      {/* Section header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "8px",
          marginBottom: "8px",
        }}
      >
        <p
          style={{
            fontSize: "11px",
            color: "#565b6e",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            fontWeight: 500,
            margin: 0,
          }}
        >
          Fix plan preview
        </p>
        {/* Safety level badge */}
        <span
          style={{
            fontSize: "10px",
            color: safety.color,
            border: `1px solid ${safety.border}`,
            borderRadius: "4px",
            padding: "1px 6px",
            fontWeight: 600,
            letterSpacing: "0.03em",
          }}
        >
          {safety.label}
        </span>
        {/* Kind badge */}
        <span
          style={{
            fontSize: "10px",
            color: "#8b90a0",
            border: "1px solid #2a2d38",
            borderRadius: "4px",
            padding: "1px 6px",
            fontWeight: 500,
          }}
        >
          {KIND_LABEL[fixPlan.kind]}
        </span>
        {/* Execution mode badge */}
        <span
          style={{
            fontSize: "10px",
            color: "#565b6e",
            border: "1px solid #2a2d38",
            borderRadius: "4px",
            padding: "1px 6px",
          }}
        >
          Manual execution required
        </span>
      </div>

      {/* Title */}
      <p
        style={{
          fontSize: "13px",
          fontWeight: 600,
          color: "#e8eaf0",
          margin: "0 0 6px",
          lineHeight: 1.4,
        }}
      >
        {fixPlan.title}
      </p>

      {/* Summary */}
      <p style={{ fontSize: "13px", color: "#b0b5c4", lineHeight: 1.6, margin: "0 0 10px" }}>
        {fixPlan.summary}
      </p>

      {/* Primary disclaimer */}
      <div
        style={{
          background: "rgba(79,128,247,0.06)",
          border: "1px solid rgba(79,128,247,0.20)",
          borderRadius: "5px",
          padding: "8px 12px",
          marginBottom: "12px",
          fontSize: "11px",
          color: "#8b90a0",
          lineHeight: 1.6,
        }}
      >
        <span style={{ color: "#4f80f7", fontWeight: 600 }}>
          ConfigTrace does not execute this fix.
        </span>{" "}
        Review the command or steps carefully and apply them manually in your provider environment.
      </div>

      {/* Warnings — shown before commands */}
      {fixPlan.warnings && fixPlan.warnings.length > 0 && (
        <div style={{ marginBottom: "12px" }}>
          {fixPlan.warnings.map((w, i) => (
            <div
              key={i}
              style={{
                display: "flex",
                gap: "7px",
                alignItems: "flex-start",
                marginBottom: i < (fixPlan.warnings?.length ?? 0) - 1 ? "5px" : 0,
              }}
            >
              <span aria-hidden="true" style={{ flexShrink: 0, color: "#f5a623", marginTop: "1px" }}>⚠</span>
              <span style={{ fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>{w}</span>
            </div>
          ))}
        </div>
      )}

      {/* Required permissions */}
      {fixPlan.required_permissions && fixPlan.required_permissions.length > 0 && (
        <div style={{ marginBottom: "12px" }}>
          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              fontWeight: 500,
              margin: "0 0 4px",
            }}
          >
            Required permissions
          </p>
          <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {fixPlan.required_permissions.map((p, i) => (
              <li
                key={i}
                style={{
                  fontSize: "12px",
                  color: "#8b90a0",
                  lineHeight: 1.6,
                  display: "flex",
                  gap: "7px",
                  marginBottom: "2px",
                }}
              >
                <span aria-hidden="true" style={{ flexShrink: 0, color: "#565b6e", marginTop: "1px" }}>·</span>
                <span>{p}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Preconditions */}
      {fixPlan.preconditions && fixPlan.preconditions.length > 0 && (
        <div style={{ marginBottom: "12px" }}>
          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              fontWeight: 500,
              margin: "0 0 4px",
            }}
          >
            Before you apply
          </p>
          <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {fixPlan.preconditions.map((pre, i) => (
              <li
                key={i}
                style={{
                  fontSize: "12px",
                  color: "#8b90a0",
                  lineHeight: 1.6,
                  display: "flex",
                  gap: "7px",
                  marginBottom: "2px",
                }}
              >
                <span aria-hidden="true" style={{ flexShrink: 0, color: "#565b6e", marginTop: "2px" }}>□</span>
                <span>{pre}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Command blocks */}
      {fixPlan.commands && fixPlan.commands.length > 0 && (
        <div style={{ marginBottom: "12px" }}>
          {fixPlan.commands.map((cmd, i) => (
            <div key={i} style={{ marginBottom: i < (fixPlan.commands?.length ?? 0) - 1 ? "10px" : 0 }}>
              {/* Command header */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  marginBottom: "4px",
                }}
              >
                <span style={{ fontSize: "11px", color: "#565b6e", fontWeight: 500 }}>
                  {cmd.label}
                </span>
                {fixPlan.copy_enabled && <CopyButton text={cmd.command} />}
              </div>
              {/* Code block */}
              <pre
                style={{
                  background: "#0d0f14",
                  border: "1px solid #2a2d38",
                  borderRadius: "5px",
                  padding: "12px 14px",
                  margin: 0,
                  fontSize: "12px",
                  fontFamily: "ui-monospace, 'Cascadia Code', 'Source Code Pro', Menlo, Consolas, monospace",
                  color: "#b0b5c4",
                  lineHeight: 1.6,
                  overflowX: "auto",
                  whiteSpace: "pre",
                }}
              >
                <code>{cmd.command}</code>
              </pre>
              {/* Placeholder notice */}
              {cmd.requires_values.length > 0 && (
                <p style={{ fontSize: "11px", color: "#565b6e", margin: "4px 0 0", lineHeight: 1.5 }}>
                  Replace before running:{" "}
                  {cmd.requires_values.map((v, j) => (
                    <Fragment key={v}>
                      <code
                        style={{
                          background: "rgba(245,166,35,0.10)",
                          border: "1px solid rgba(245,166,35,0.25)",
                          borderRadius: "3px",
                          padding: "0 4px",
                          fontSize: "10px",
                          color: "#f5a623",
                          fontFamily: "ui-monospace, monospace",
                        }}
                      >
                        {"<"}{v}{">"}
                      </code>
                      {j < cmd.requires_values.length - 1 && " "}
                    </Fragment>
                  ))}
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Guided manual steps (for guided_manual kind) */}
      {fixPlan.manual_steps && fixPlan.manual_steps.length > 0 && (
        <div style={{ marginBottom: "12px" }}>
          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              fontWeight: 500,
              margin: "0 0 4px",
            }}
          >
            {fixPlan.kind === "guided_manual" ? "Manual steps" : "Alternative manual steps"}
          </p>
          <ol style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {fixPlan.manual_steps.map((step, i) => (
              <li
                key={i}
                style={{
                  fontSize: "12px",
                  color: "#8b90a0",
                  lineHeight: 1.6,
                  display: "flex",
                  gap: "7px",
                  marginBottom: i < (fixPlan.manual_steps?.length ?? 0) - 1 ? "3px" : 0,
                }}
              >
                <span
                  aria-hidden="true"
                  style={{
                    flexShrink: 0,
                    width: "16px",
                    fontSize: "11px",
                    color: "#565b6e",
                    fontVariantNumeric: "tabular-nums",
                    marginTop: "2px",
                  }}
                >
                  {i + 1}.
                </span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* Postconditions */}
      {fixPlan.postconditions && fixPlan.postconditions.length > 0 && (
        <div>
          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              fontWeight: 500,
              margin: "0 0 4px",
            }}
          >
            After applying
          </p>
          <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {fixPlan.postconditions.map((post, i) => (
              <li
                key={i}
                style={{
                  fontSize: "12px",
                  color: "#8b90a0",
                  lineHeight: 1.6,
                  display: "flex",
                  gap: "7px",
                  marginBottom: "2px",
                }}
              >
                <span aria-hidden="true" style={{ flexShrink: 0, color: "#22c55e", marginTop: "1px" }}>✓</span>
                <span>{post}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ── Remediation preview subsection ───────────────────────────────────────────

function ConfirmationInput({ phrase }: { phrase: string }) {
  const [value, setValue] = useState("");
  const confirmed = value.trim().toUpperCase() === phrase.toUpperCase();

  return (
    <div>
      {/* Prompt */}
      <p
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          fontWeight: 500,
          margin: "0 0 6px",
        }}
      >
        Confirm preview (non-executing)
      </p>
      <p style={{ fontSize: "12px", color: "#8b90a0", lineHeight: 1.5, margin: "0 0 8px" }}>
        Type{" "}
        <code
          style={{
            background: "rgba(79,128,247,0.10)",
            border: "1px solid rgba(79,128,247,0.25)",
            borderRadius: "3px",
            padding: "0 5px",
            fontSize: "11px",
            color: "#7ba4ff",
            fontFamily: "ui-monospace, monospace",
            letterSpacing: "0.05em",
          }}
        >
          {phrase}
        </code>{" "}
        to acknowledge this preview. No changes will be applied.
      </p>
      <input
        type="text"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder={`Type ${phrase} to confirm`}
        aria-label={`Type ${phrase} to confirm preview`}
        style={{
          width: "100%",
          boxSizing: "border-box",
          background: confirmed ? "rgba(34,197,94,0.06)" : "rgba(255,255,255,0.03)",
          border: `1px solid ${confirmed ? "rgba(34,197,94,0.35)" : "#3a3d4a"}`,
          borderRadius: "5px",
          color: confirmed ? "#22c55e" : "#e8eaf0",
          fontSize: "12px",
          fontFamily: "ui-monospace, monospace",
          letterSpacing: "0.04em",
          padding: "7px 10px",
          outline: "none",
          transition: "border-color 0.15s, background 0.15s",
        }}
      />
      {confirmed && (
        <p
          style={{
            fontSize: "11px",
            color: "#22c55e",
            margin: "6px 0 0",
            display: "flex",
            alignItems: "center",
            gap: "5px",
          }}
        >
          <span aria-hidden="true">✓</span>
          Preview confirmed. No changes were applied.
        </p>
      )}
    </div>
  );
}

function RemediationPreviewSubsection({
  preview,
  dividerColor,
}: {
  preview: RemediationPreview;
  dividerColor: string;
}) {
  return (
    <div
      style={{
        marginTop: "14px",
        paddingTop: "14px",
        borderTop: `1px solid ${dividerColor}`,
      }}
    >
      {/* Section header + badges */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "8px",
          marginBottom: "10px",
        }}
      >
        <p
          style={{
            fontSize: "11px",
            color: "#565b6e",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            fontWeight: 500,
            margin: 0,
          }}
        >
          Remediation preview
        </p>
        <span
          style={{
            fontSize: "10px",
            color: "#4f80f7",
            border: "1px solid rgba(79,128,247,0.30)",
            borderRadius: "4px",
            padding: "1px 6px",
            fontWeight: 600,
            letterSpacing: "0.03em",
          }}
        >
          Dry run only
        </span>
        <span
          style={{
            fontSize: "10px",
            color: "#565b6e",
            border: "1px solid #2a2d38",
            borderRadius: "4px",
            padding: "1px 6px",
            fontWeight: 500,
            letterSpacing: "0.03em",
          }}
        >
          No changes applied
        </span>
        <span
          style={{
            fontSize: "10px",
            color: preview.preview_kind === "exact" ? "#22c55e" : "#8b90a0",
            border: `1px solid ${preview.preview_kind === "exact" ? "rgba(34,197,94,0.30)" : "#2a2d38"}`,
            borderRadius: "4px",
            padding: "1px 6px",
            fontWeight: 500,
            letterSpacing: "0.03em",
          }}
        >
          {preview.preview_kind === "exact" ? "Exact preview" : "Conceptual preview"}
        </span>
      </div>

      {/* Status banner */}
      <div
        style={{
          background: "rgba(79,128,247,0.06)",
          border: "1px solid rgba(79,128,247,0.20)",
          borderRadius: "6px",
          padding: "10px 12px",
          marginBottom: "14px",
        }}
      >
        <p style={{ fontSize: "12px", color: "#b0b5c4", lineHeight: 1.6, margin: 0 }}>
          {preview.summary}
        </p>
      </div>

      {/* Before / After grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "10px",
          marginBottom: "14px",
        }}
      >
        {/* Before column */}
        <div
          style={{
            background: "rgba(232,64,64,0.05)",
            border: "1px solid rgba(232,64,64,0.20)",
            borderRadius: "6px",
            padding: "10px 12px",
          }}
        >
          <p
            style={{
              fontSize: "10px",
              color: "#e84040",
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              fontWeight: 600,
              margin: "0 0 6px",
            }}
          >
            Before
          </p>
          {preview.before.map((item: BeforeAfterItem, i: number) => (
            <div key={i} style={{ marginBottom: i < preview.before.length - 1 ? "6px" : 0 }}>
              <p style={{ fontSize: "10px", color: "#565b6e", margin: "0 0 1px", fontWeight: 500 }}>
                {item.label}
              </p>
              <p style={{ fontSize: "12px", color: "#b0b5c4", margin: 0, lineHeight: 1.5 }}>
                {item.value}
              </p>
            </div>
          ))}
        </div>

        {/* After column */}
        <div
          style={{
            background: "rgba(34,197,94,0.05)",
            border: "1px solid rgba(34,197,94,0.20)",
            borderRadius: "6px",
            padding: "10px 12px",
          }}
        >
          <p
            style={{
              fontSize: "10px",
              color: "#22c55e",
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              fontWeight: 600,
              margin: "0 0 6px",
            }}
          >
            After
          </p>
          {preview.after.map((item: BeforeAfterItem, i: number) => (
            <div key={i} style={{ marginBottom: i < preview.after.length - 1 ? "6px" : 0 }}>
              <p style={{ fontSize: "10px", color: "#565b6e", margin: "0 0 1px", fontWeight: 500 }}>
                {item.label}
              </p>
              <p style={{ fontSize: "12px", color: "#b0b5c4", margin: 0, lineHeight: 1.5 }}>
                {item.value}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Required permissions */}
      {preview.required_permissions.length > 0 && (
        <div style={{ marginBottom: "12px" }}>
          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              fontWeight: 500,
              margin: "0 0 4px",
            }}
          >
            Required permissions
          </p>
          <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {preview.required_permissions.map((perm, i) => (
              <li
                key={i}
                style={{
                  fontSize: "12px",
                  color: "#8b90a0",
                  lineHeight: 1.6,
                  display: "flex",
                  gap: "7px",
                  marginBottom: "2px",
                }}
              >
                <span aria-hidden="true" style={{ flexShrink: 0, color: "#4f80f7" }}>◆</span>
                <code style={{ fontFamily: "ui-monospace, monospace", fontSize: "11px" }}>{perm}</code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Preconditions */}
      {preview.preconditions.length > 0 && (
        <div style={{ marginBottom: "12px" }}>
          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              fontWeight: 500,
              margin: "0 0 4px",
            }}
          >
            Before applying
          </p>
          <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {preview.preconditions.map((pre, i) => (
              <li
                key={i}
                style={{
                  fontSize: "12px",
                  color: "#8b90a0",
                  lineHeight: 1.6,
                  display: "flex",
                  gap: "7px",
                  marginBottom: "2px",
                }}
              >
                <span aria-hidden="true" style={{ flexShrink: 0, color: "#565b6e", marginTop: "1px" }}>□</span>
                <span>{pre}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Warnings */}
      {preview.warnings.length > 0 && (
        <div style={{ marginBottom: "12px" }}>
          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              fontWeight: 500,
              margin: "0 0 4px",
            }}
          >
            Warnings
          </p>
          <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {preview.warnings.map((w, i) => (
              <li
                key={i}
                style={{
                  fontSize: "12px",
                  color: "#8b90a0",
                  lineHeight: 1.6,
                  display: "flex",
                  gap: "7px",
                  marginBottom: "2px",
                }}
              >
                <span aria-hidden="true" style={{ flexShrink: 0, color: "#f5a623", marginTop: "1px" }}>⚠</span>
                <span>{w}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Confirmation phrase input */}
      <div style={{ marginBottom: "12px" }}>
        <ConfirmationInput phrase={preview.confirmation_phrase} />
      </div>

      {/* Audit note */}
      <div
        style={{
          background: "rgba(86,91,110,0.08)",
          border: "1px solid #2a2d38",
          borderRadius: "5px",
          padding: "8px 11px",
          marginBottom: "12px",
        }}
      >
        <p style={{ fontSize: "11px", color: "#565b6e", margin: 0, lineHeight: 1.6, fontStyle: "italic" }}>
          Confirming this preview would create an audit event in ConfigTrace — but no changes are applied to your infrastructure. ConfigTrace is read-only.
        </p>
      </div>

      {/* Validation steps */}
      {preview.validation_steps.length > 0 && (
        <div>
          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              fontWeight: 500,
              margin: "0 0 4px",
            }}
          >
            How to verify after applying
          </p>
          <ol style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {preview.validation_steps.map((step, i) => (
              <li
                key={i}
                style={{
                  fontSize: "12px",
                  color: "#8b90a0",
                  lineHeight: 1.6,
                  display: "flex",
                  gap: "7px",
                  marginBottom: i < preview.validation_steps.length - 1 ? "3px" : 0,
                }}
              >
                <span
                  aria-hidden="true"
                  style={{
                    flexShrink: 0,
                    width: "16px",
                    fontSize: "11px",
                    color: "#565b6e",
                    fontVariantNumeric: "tabular-nums",
                    marginTop: "2px",
                  }}
                >
                  {i + 1}.
                </span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* Provider console link */}
      {preview.provider_console_url && (
        <div style={{ marginTop: "10px" }}>
          <a
            href={preview.provider_console_url}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              fontSize: "12px",
              color: "#4f80f7",
              textDecoration: "none",
            }}
          >
            Open provider console ↗
          </a>
        </div>
      )}
    </div>
  );
}

// ── Remediation section ───────────────────────────────────────────────────────

const CONFIDENCE_COLORS: Record<RemediationGuidance["confidence"], { bg: string; border: string; text: string; label: string }> = {
  high:   { bg: "rgba(34,197,94,0.06)",  border: "rgba(34,197,94,0.22)",  text: "#22c55e", label: "High confidence" },
  medium: { bg: "rgba(245,166,35,0.06)", border: "rgba(245,166,35,0.22)", text: "#f5a623", label: "Medium confidence" },
  low:    { bg: "rgba(86,91,110,0.10)",  border: "#2a2d38",               text: "#8b90a0", label: "Low confidence"    },
};

function RemediationSection({
  guidance,
  fixPlan,
  preview,
}: {
  guidance: RemediationGuidance;
  fixPlan?: FixPlan;
  preview?: RemediationPreview;
}) {
  const conf = CONFIDENCE_COLORS[guidance.confidence];

  return (
    <section aria-labelledby="section-remediation">
      <h2
        id="section-remediation"
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          margin: "0 0 8px",
          fontWeight: 500,
        }}
      >
        Suggested remediation
      </h2>

      <Panel bg={conf.bg} border={conf.border}>
        {/* Header row: title + confidence badge */}
        <div
          style={{
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: "12px",
            marginBottom: "10px",
          }}
        >
          <p
            style={{
              fontSize: "14px",
              fontWeight: 600,
              color: "#e8eaf0",
              margin: 0,
              lineHeight: 1.4,
            }}
          >
            {guidance.title}
          </p>
          <span
            style={{
              flexShrink: 0,
              fontSize: "10px",
              fontWeight: 600,
              color: conf.text,
              background: conf.bg,
              border: `1px solid ${conf.border}`,
              borderRadius: "4px",
              padding: "2px 7px",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              whiteSpace: "nowrap",
            }}
          >
            {conf.label}
          </span>
        </div>

        {/* Summary */}
        <p style={{ fontSize: "13px", color: "#b0b5c4", lineHeight: 1.6, margin: "0 0 14px" }}>
          {guidance.summary}
        </p>

        {/* Why this helps */}
        <div style={{ marginBottom: "14px" }}>
          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              fontWeight: 500,
              margin: "0 0 5px",
            }}
          >
            Why this helps
          </p>
          <p style={{ fontSize: "13px", color: "#8b90a0", lineHeight: 1.6, margin: 0 }}>
            {guidance.why_this_helps}
          </p>
        </div>

        {/* Verify first */}
        {guidance.verify_first.length > 0 && (
          <div style={{ marginBottom: "14px" }}>
            <p
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                fontWeight: 500,
                margin: "0 0 5px",
              }}
            >
              Verify first
            </p>
            <ul style={{ margin: 0, padding: 0, listStyle: "none" }} role="list">
              {guidance.verify_first.map((step, i) => (
                <li
                  key={i}
                  style={{
                    fontSize: "13px",
                    color: "#8b90a0",
                    lineHeight: 1.6,
                    display: "flex",
                    gap: "8px",
                    marginBottom: i < guidance.verify_first.length - 1 ? "4px" : "0",
                  }}
                >
                  <span aria-hidden="true" style={{ flexShrink: 0, color: "#565b6e", marginTop: "1px" }}>□</span>
                  <span>{step}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Manual steps */}
        {guidance.manual_steps.length > 0 && (
          <div style={{ marginBottom: "14px" }}>
            <p
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                fontWeight: 500,
                margin: "0 0 5px",
              }}
            >
              Steps to remediate
            </p>
            <ol style={{ margin: 0, padding: 0, listStyle: "none" }} role="list">
              {guidance.manual_steps.map((step, i) => (
                <li
                  key={i}
                  style={{
                    fontSize: "13px",
                    color: "#8b90a0",
                    lineHeight: 1.6,
                    display: "flex",
                    gap: "8px",
                    marginBottom: i < guidance.manual_steps.length - 1 ? "5px" : "0",
                  }}
                >
                  <span
                    aria-hidden="true"
                    style={{
                      flexShrink: 0,
                      width: "18px",
                      fontSize: "11px",
                      color: "#565b6e",
                      fontVariantNumeric: "tabular-nums",
                      marginTop: "2px",
                    }}
                  >
                    {i + 1}.
                  </span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </div>
        )}

        {/* Validation steps */}
        {guidance.validation_steps.length > 0 && (
          <div style={{ marginBottom: "14px" }}>
            <p
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                fontWeight: 500,
                margin: "0 0 5px",
              }}
            >
              How to confirm it worked
            </p>
            <ul style={{ margin: 0, padding: 0, listStyle: "none" }} role="list">
              {guidance.validation_steps.map((step, i) => (
                <li
                  key={i}
                  style={{
                    fontSize: "13px",
                    color: "#8b90a0",
                    lineHeight: 1.6,
                    display: "flex",
                    gap: "8px",
                    marginBottom: i < guidance.validation_steps.length - 1 ? "4px" : "0",
                  }}
                >
                  <span aria-hidden="true" style={{ flexShrink: 0, color: "#22c55e", marginTop: "1px" }}>✓</span>
                  <span>{step}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Caveats */}
        {guidance.caveats.length > 0 && (
          <div style={{ marginBottom: "14px" }}>
            <p
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                fontWeight: 500,
                margin: "0 0 5px",
              }}
            >
              Caveats
            </p>
            <ul style={{ margin: 0, padding: 0, listStyle: "none" }} role="list">
              {guidance.caveats.map((caveat, i) => (
                <li
                  key={i}
                  style={{
                    fontSize: "12px",
                    color: "#8b90a0",
                    lineHeight: 1.6,
                    display: "flex",
                    gap: "8px",
                    marginBottom: i < guidance.caveats.length - 1 ? "4px" : "0",
                  }}
                >
                  <span aria-hidden="true" style={{ flexShrink: 0, color: "#f5a623", marginTop: "1px" }}>⚠</span>
                  <span>{caveat}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Provider console hint */}
        {guidance.provider_console_hint && (
          <div style={{ marginBottom: "14px" }}>
            <p
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                fontWeight: 500,
                margin: "0 0 5px",
              }}
            >
              Where to make this change
            </p>
            <p style={{ fontSize: "13px", color: "#8b90a0", lineHeight: 1.6, margin: 0 }}>
              {guidance.provider_console_hint}
            </p>
          </div>
        )}

        {/* Docs links */}
        {guidance.docs_links.length > 0 && (
          <div style={{ marginBottom: "14px" }}>
            <p
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                fontWeight: 500,
                margin: "0 0 5px",
              }}
            >
              Reference docs
            </p>
            <ul style={{ margin: 0, padding: 0, listStyle: "none" }} role="list">
              {guidance.docs_links.map((link, i) => (
                <li key={i} style={{ marginBottom: "3px" }}>
                  <a
                    href={link.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      fontSize: "12px",
                      color: "#4f80f7",
                      textDecoration: "none",
                    }}
                  >
                    {link.label} ↗
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* ── Fix plan preview subsection ───────────────────────────── */}
        {fixPlan && <FixPlanSubsection fixPlan={fixPlan} dividerColor={conf.border} />}

        {/* ── Remediation preview subsection ────────────────────────── */}
        {preview && <RemediationPreviewSubsection preview={preview} dividerColor={conf.border} />}

        {/* Footer: disclaimer + status badges */}
        <div
          style={{
            marginTop: "14px",
            paddingTop: "12px",
            borderTop: `1px solid ${conf.border}`,
          }}
        >
          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              lineHeight: 1.6,
              margin: "0 0 8px",
              fontStyle: "italic",
            }}
          >
            This is read-only guidance — ConfigTrace does not modify your infrastructure. Always review the steps in the context of your environment before applying any change.
          </p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
            {(
              [
                { label: "Guidance only",                color: "#8b90a0", border: "#2a2d38" },
                { label: "No write access required",     color: "#22c55e", border: "rgba(34,197,94,0.30)" },
                { label: "One-click fix not enabled yet", color: "#565b6e", border: "#2a2d38" },
              ] as const
            ).map(({ label, color, border }) => (
              <span
                key={label}
                style={{
                  fontSize: "10px",
                  color,
                  border: `1px solid ${border}`,
                  borderRadius: "4px",
                  padding: "2px 7px",
                  fontWeight: 500,
                  letterSpacing: "0.03em",
                }}
              >
                {label}
              </span>
            ))}
          </div>
        </div>
      </Panel>
    </section>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ChangeDetailPage() {
  const params   = useParams();
  const changeId = params.changeId as string;

  const [change,  setChange]  = useState<ChangeDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);
  // M57.2: review state (separate from change so it can be updated without reloading the full change)
  const [review, setReview] = useState<ChangeReviewResponse | null>(null);
  const { getToken, isLoaded } = useAuth();

  useEffect(() => {
    if (!changeId || !isLoaded) return;
    let cancelled = false;

    setLoading(true);
    setError(null);

    (async () => {
      try {
        const token = await getToken();
        const data = await getChange(changeId, token);
        if (!cancelled) {
          setChange(data);
          // Seed review state from the embedded review field (M57.2)
          if (data.review) {
            setReview({
              change_id: data.id,
              review_status: data.review.review_status,
              reviewed_by_user_id: data.review.reviewed_by_user_id,
              reviewed_at: data.review.reviewed_at,
              review_note: data.review.review_note,
              snoozed_until: data.review.snoozed_until,
              snooze_reason: data.review.snooze_reason,
            });
          }
        }
      } catch (err) {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load change.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => { cancelled = true; };
  }, [changeId, isLoaded, getToken]);

  // ── Loading ────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <>
        <PageHeader title="Change Detail" />
        <div className="px-6 py-6">
          <LoadingState />
        </div>
      </>
    );
  }

  // ── Error / 404 ────────────────────────────────────────────────────────

  if (error || !change) {
    const is404 =
      error?.includes("404") ||
      error?.toLowerCase().includes("not found");

    return (
      <>
        <PageHeader title="Change Detail" />
        <div className="px-6 py-6">
          <ErrorState
            message={
              is404
                ? "Change not found. It may belong to a different account or the ID is invalid."
                : (error ?? "An unknown error occurred.")
            }
          />
          <div className="mt-4">
            <Link
              href="/timeline"
              style={{ fontSize: "13px", color: "#4f80f7", textDecoration: "none" }}
            >
              ← Back to Timeline
            </Link>
          </div>
        </div>
      </>
    );
  }

  // ── Render ─────────────────────────────────────────────────────────────

  const riskKey        = (change.risk_level ?? "unknown").toLowerCase();
  const riskBg         = RISK_PANEL_BG[riskKey]     ?? RISK_PANEL_BG.unknown;
  const riskBorder     = RISK_PANEL_BORDER[riskKey] ?? RISK_PANEL_BORDER.unknown;
  const riskTextColor  = RISK_TEXT[riskKey]          ?? RISK_TEXT.unknown;
  const riskLabel      = riskKey.charAt(0).toUpperCase() + riskKey.slice(1);

  // Human-readable title + provider/category metadata from timeline helpers
  const eventTitle    = getTimelineEventTitle(change);
  const provider      = getTimelineProvider(change);
  const category      = getTimelineCategory(change);
  const providerMeta  = getProviderMeta(provider);

  const summary       = getChangeSummary(change);
  const whyItMatters  = getWhyItMatters(change);
  const checks        = getSuggestedChecks(change);
  const remediation   = getRemediationGuidance(change);
  const fixPlan       = getFixPlanForChange(change);
  const preview       = getRemediationPreviewForChange(change, remediation, fixPlan);

  // Non-Cloudflare providers show "Configuration added/removed" instead of "DNS record added/removed"
  const showConfigLabel = provider !== "cloudflare";

  return (
    <>
      <PageHeader
        title={eventTitle}
        description={`${formatRelativeTime(change.created_at)} · ${providerMeta.shortLabel}${category ? ` · ${category}` : ""} · ${changeTypeLabel(change.change_type)}`}
      />

      <div
        className="px-6 pb-10"
        style={{ display: "flex", flexDirection: "column", gap: "20px" }}
      >
        {/* ── Back link ──────────────────────────────────────────────── */}
        <div>
          <Link
            href="/timeline"
            style={{ fontSize: "13px", color: "#565b6e", textDecoration: "none" }}
          >
            ← Timeline
          </Link>
        </div>

        {/* ── Hero card ───────────────────────────────────────────────── */}
        <Panel>
          {/* Risk level label */}
          <p
            style={{
              fontSize: "11px",
              fontWeight: 600,
              color: riskTextColor,
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              margin: "0 0 6px",
            }}
          >
            {riskLabel} risk
          </p>

          {/* Human-readable title */}
          <h1
            style={{
              fontSize: "18px",
              fontWeight: 700,
              color: "#e8eaf0",
              margin: "0 0 10px",
              lineHeight: 1.3,
            }}
          >
            {eventTitle}
          </h1>

          {/* Metadata breadcrumb: detected · provider · category · change type */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "4px",
              fontSize: "12px",
            }}
          >
            <span style={{ color: "#8b90a0" }}>
              Detected {formatRelativeTime(change.created_at)}
            </span>
            <span style={{ color: "#2a2d38", padding: "0 2px" }}>·</span>
            <span style={{ color: providerMeta.color, fontWeight: 600 }}>
              {providerMeta.shortLabel}
            </span>
            {category && (
              <>
                <span style={{ color: "#2a2d38", padding: "0 2px" }}>·</span>
                <span style={{ color: "#8b90a0" }}>{category}</span>
              </>
            )}
            <span style={{ color: "#2a2d38", padding: "0 2px" }}>·</span>
            <span style={{ color: "#8b90a0" }}>{changeTypeLabel(change.change_type)}</span>
          </div>
        </Panel>

        {/* ── Risk summary ────────────────────────────────────────────── */}
        <section aria-labelledby="section-risk">
          <h2
            id="section-risk"
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              margin: "0 0 8px",
              fontWeight: 500,
            }}
          >
            Risk summary
          </h2>
          <Panel bg={riskBg} border={riskBorder}>
            <div style={{ display: "flex", alignItems: "flex-start", gap: "10px" }}>
              <div style={{ flexShrink: 0, paddingTop: "1px" }}>
                <RiskBadge level={change.risk_level} />
              </div>
              <p
                style={{
                  fontSize: "13px",
                  color: change.risk_reason ? "#b0b5c4" : "#565b6e",
                  fontStyle: change.risk_reason ? "normal" : "italic",
                  lineHeight: 1.6,
                  margin: 0,
                }}
              >
                {change.risk_reason ?? (
                  riskKey === "low"
                    ? "This change is currently classified as low risk."
                    : "Review this change to confirm it was intentional."
                )}
              </p>
            </div>

            {/* Compact context row */}
            <div
              style={{
                marginTop: "12px",
                paddingTop: "10px",
                borderTop: `1px solid ${riskBorder}`,
                display: "flex",
                flexWrap: "wrap",
                gap: "6px 24px",
              }}
            >
              <MetaRow label="Provider">
                <span style={{ color: providerMeta.color, fontWeight: 500 }}>
                  {providerMeta.label}
                </span>
              </MetaRow>
              <MetaRow label="Change type">
                {changeTypeLabel(change.change_type)}
              </MetaRow>
              {change.field_path && (
                <MetaRow label="Field">
                  <span className="font-mono" style={{ fontSize: "12px" }}>
                    {change.field_path}
                  </span>
                </MetaRow>
              )}
              <MetaRow label="Detected">
                <span
                  title={formatAbsoluteTime(change.created_at)}
                  style={{ fontSize: "12px" }}
                >
                  {formatRelativeTime(change.created_at)}
                </span>
              </MetaRow>
            </div>
          </Panel>
        </section>

        {/* ── What changed ────────────────────────────────────────────── */}
        <section aria-labelledby="section-what-changed">
          <h2
            id="section-what-changed"
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              margin: "0 0 8px",
              fontWeight: 500,
            }}
          >
            What changed
          </h2>
          <Panel>
            <p
              style={{
                fontSize: "13px",
                color: "#b0b5c4",
                lineHeight: 1.6,
                margin: 0,
              }}
            >
              {summary}
            </p>
          </Panel>
        </section>

        {/* ── Why it matters ──────────────────────────────────────────── */}
        {whyItMatters && (
          <section aria-labelledby="section-why-matters">
            <h2
              id="section-why-matters"
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                margin: "0 0 8px",
                fontWeight: 500,
              }}
            >
              Why it matters
            </h2>
            <Panel>
              <p
                style={{
                  fontSize: "13px",
                  color: "#b0b5c4",
                  lineHeight: 1.6,
                  margin: 0,
                }}
              >
                {whyItMatters}
              </p>
            </Panel>
          </section>
        )}

        {/* ── What to check ────────────────────────────────────────────── */}
        {checks.length > 0 && (
          <section aria-labelledby="section-checks">
            <h2
              id="section-checks"
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                margin: "0 0 8px",
                fontWeight: 500,
              }}
            >
              What to check
            </h2>
            <Panel bg={riskBg} border={riskBorder}>
              <ul
                style={{ margin: 0, padding: 0, listStyle: "none" }}
                role="list"
              >
                {checks.map((check, i) => (
                  <li
                    key={i}
                    style={{
                      fontSize: "13px",
                      color: "#8b90a0",
                      lineHeight: 1.6,
                      display: "flex",
                      gap: "8px",
                      marginBottom: i < checks.length - 1 ? "6px" : "0",
                    }}
                  >
                    <span
                      aria-hidden="true"
                      style={{ flexShrink: 0, color: "#565b6e", marginTop: "1px" }}
                    >
                      →
                    </span>
                    <span>{check}</span>
                  </li>
                ))}
              </ul>
            </Panel>
          </section>
        )}

        {/* ── Suggested remediation ───────────────────────────────────── */}
        {remediation.available && (
          <RemediationSection
            guidance={remediation}
            fixPlan={fixPlan.available ? fixPlan : undefined}
            preview={preview.available ? preview : undefined}
          />
        )}

        {/* ── Raw configuration diff ──────────────────────────────────── */}
        <section aria-labelledby="section-diff">
          <h2
            id="section-diff"
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              margin: "0 0 8px",
              fontWeight: 500,
            }}
          >
            {change.change_type === "modified"
              ? "Raw configuration diff"
              : change.change_type === "added"
              ? (showConfigLabel ? "Configuration added" : "DNS record added")
              : (showConfigLabel ? "Configuration removed" : "DNS record removed")}
          </h2>
          <Panel>
            {change.change_type === "modified" ? (
              <ModifiedDiffPanel change={change} />
            ) : (
              <AddedRemovedPanel change={change} isGitHub={showConfigLabel} />
            )}
          </Panel>
        </section>

        {/* ── Snapshot context ────────────────────────────────────────── */}
        {(change.prev_snapshot_id || change.new_snapshot_id) && (
          <section aria-labelledby="section-snapshot">
            <h2
              id="section-snapshot"
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                margin: "0 0 8px",
                fontWeight: 500,
              }}
            >
              Snapshot context
            </h2>
            <SnapshotContextPanel change={change} />
          </section>
        )}

        {/* ── Context metadata ────────────────────────────────────────── */}
        <section aria-labelledby="section-context">
          <h2
            id="section-context"
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              margin: "0 0 8px",
              fontWeight: 500,
            }}
          >
            Context
          </h2>
          <Panel>
            <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
              <MetaRow label="Provider">
                <span style={{ color: providerMeta.color, fontWeight: 500 }}>
                  {providerMeta.label}
                </span>
              </MetaRow>
              {category && (
                <MetaRow label="Category">{category}</MetaRow>
              )}
              <MetaRow label="Change type">
                {changeTypeLabel(change.change_type)}
              </MetaRow>
              {change.field_path && (
                <MetaRow label="Field">
                  <span className="font-mono" style={{ fontSize: "12px" }}>
                    {change.field_path}
                  </span>
                </MetaRow>
              )}
              <MetaRow label="Record">
                <span
                  className="font-mono"
                  style={{ fontSize: "12px", wordBreak: "break-all" }}
                >
                  {change.record_identifier}
                </span>
              </MetaRow>
              <MetaRow label="Detected">
                <span
                  title={formatAbsoluteTime(change.created_at)}
                  style={{ fontSize: "12px" }}
                >
                  {formatRelativeTime(change.created_at)}{" "}
                  <span style={{ color: "#565b6e" }}>
                    ({formatAbsoluteTime(change.created_at)})
                  </span>
                </span>
              </MetaRow>
              <MetaRow label="Risk level">
                <RiskBadge level={change.risk_level} />
              </MetaRow>
              <MetaRow label="Resource">
                <Link
                  href={`/resources/${change.resource_id}`}
                  style={{ color: "#4f80f7", fontSize: "12px", textDecoration: "none" }}
                >
                  View resource →
                </Link>
              </MetaRow>
            </div>

            <ProviderMetaRows metadata={change.provider_metadata} />
          </Panel>
        </section>

        {/* ── Review panel (M57.2) ─────────────────────────────────────── */}
        <ReviewPanel
          changeId={change.id}
          review={review}
          onReviewUpdated={setReview}
        />

        {/* ── Technical details (collapsed) ────────────────────────────── */}
        <div>
          <details
            style={{
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              overflow: "hidden",
            }}
          >
            <summary
              style={{
                padding: "10px 14px",
                fontSize: "12px",
                color: "#565b6e",
                cursor: "pointer",
                userSelect: "none",
                background: "#13151a",
                listStyle: "none",
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              <span aria-hidden="true">▶</span>
              <span>Technical details</span>
            </summary>
            <div style={{ background: "#0e0f11", padding: "14px 16px" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                {[
                  { label: "Change ID",       value: String(change.id) },
                  { label: "Resource ID",     value: change.resource_id },
                  { label: "Integration ID",  value: change.integration_id },
                  ...(change.prev_snapshot_id
                    ? [{ label: "Before snapshot", value: change.prev_snapshot_id }]
                    : []),
                  ...(change.new_snapshot_id
                    ? [{ label: "After snapshot",  value: change.new_snapshot_id }]
                    : []),
                ].map(({ label, value }) => (
                  <div key={label} className="flex items-baseline gap-3">
                    <span
                      style={{
                        width: "120px",
                        flexShrink: 0,
                        fontSize: "11px",
                        color: "#565b6e",
                        textTransform: "uppercase",
                        letterSpacing: "0.06em",
                      }}
                    >
                      {label}
                    </span>
                    <span
                      className="font-mono"
                      style={{ fontSize: "11px", color: "#565b6e", wordBreak: "break-all" }}
                    >
                      {value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </details>
        </div>

        {/* ── Raw change data (collapsed) ─────────────────────────────── */}
        <div>
          <RawSection change={change} />
        </div>
      </div>
    </>
  );
}
