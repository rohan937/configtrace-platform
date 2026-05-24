"use client";

import { useParams } from "next/navigation";
import { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import type { ChangeDetail, DnsRecord } from "@/types";
import { getChange } from "@/lib/api";
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

/** "Cloudflare DNS" | "GitHub repo configuration" | "Vercel project configuration" | "Stripe account configuration" | "AWS account configuration" */
function getProviderLabel(change: ChangeDetail): string {
  const rt = (
    (change.provider_metadata?.record_type as string | undefined) ?? ""
  ).toLowerCase();
  if (rt.startsWith("github_")) return "GitHub repo configuration";
  if (rt.startsWith("vercel_")) return "Vercel project configuration";
  if (rt.startsWith("stripe_")) return "Stripe account configuration";
  if (rt.startsWith("aws_"))    return "AWS account configuration";
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

  if (rt.startsWith("aws_")) {
    return `An AWS configuration record changed (${rt}).`;
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

/** Suggested next steps for high/critical changes. Returns [] for low/medium. */
function getSuggestedChecks(change: ChangeDetail): string[] {
  const riskKey = (change.risk_level ?? "").toLowerCase();
  if (riskKey !== "high" && riskKey !== "critical") return [];

  const rt = (
    (change.provider_metadata?.record_type as string | undefined) ?? ""
  ).toLowerCase();

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

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ChangeDetailPage() {
  const params   = useParams();
  const changeId = params.changeId as string;

  const [change,  setChange]  = useState<ChangeDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);
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
        if (!cancelled) setChange(data);
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

  const riskKey       = (change.risk_level ?? "unknown").toLowerCase();
  const riskBg        = RISK_PANEL_BG[riskKey]     ?? RISK_PANEL_BG.unknown;
  const riskBorder    = RISK_PANEL_BORDER[riskKey] ?? RISK_PANEL_BORDER.unknown;
  const providerLabel = getProviderLabel(change);
  const summary       = getChangeSummary(change);
  const checks        = getSuggestedChecks(change);
  const isGitHub      = providerLabel === "GitHub repo configuration";
  const isVercel      = providerLabel === "Vercel project configuration";
  const isStripe      = providerLabel === "Stripe account configuration";
  const isAWS         = providerLabel === "AWS account configuration";

  return (
    <>
      <PageHeader
        title={change.record_identifier}
        description={`${changeTypeLabel(change.change_type)}${change.field_path ? ` · ${change.field_path}` : ""}`}
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

        {/* ── Change header ───────────────────────────────────────────── */}
        <Panel>
          {/* Top row: identifier + risk badge */}
          <div
            className="flex items-start justify-between gap-4"
            style={{ marginBottom: "12px" }}
          >
            <span
              className="font-mono"
              style={{ fontSize: "15px", color: "#e8eaf0", fontWeight: 600, wordBreak: "break-all" }}
            >
              {change.record_identifier}
            </span>
            <div style={{ flexShrink: 0 }}>
              <RiskBadge level={change.risk_level} />
            </div>
          </div>

          {/* Provider label pill */}
          <div style={{ marginBottom: "10px" }}>
            <span
              style={{
                display: "inline-block",
                fontSize: "11px",
                color: "#8b90a0",
                background: "#1c1e26",
                border: "1px solid #2a2d38",
                borderRadius: "4px",
                padding: "2px 8px",
                letterSpacing: "0.03em",
              }}
            >
              {providerLabel}
            </span>
          </div>

          {/* Metadata rows */}
          <MetaRow label="Change type">
            <span
              className="uppercase tracking-wider"
              style={{ fontSize: "11px", color: "#b0b5c4" }}
            >
              {changeTypeLabel(change.change_type)}
            </span>
          </MetaRow>

          {change.field_path && (
            <MetaRow label="Field">
              <span className="font-mono" style={{ color: "#b0b5c4", fontSize: "12px" }}>
                {change.field_path}
              </span>
            </MetaRow>
          )}

          <MetaRow label="Detected">
            <span
              title={formatAbsoluteTime(change.created_at)}
              style={{ color: "#8b90a0", fontSize: "12px" }}
            >
              {formatRelativeTime(change.created_at)}{" "}
              <span style={{ color: "#565b6e" }}>
                ({formatAbsoluteTime(change.created_at)})
              </span>
            </span>
          </MetaRow>
        </Panel>

        {/* ── Summary card ────────────────────────────────────────────── */}
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

        {/* ── Risk explanation ────────────────────────────────────────── */}
        <div>
          <SectionLabel>Risk explanation</SectionLabel>
          <Panel bg={riskBg} border={riskBorder}>
            <div className="flex items-start gap-3" style={{ marginBottom: checks.length > 0 ? "14px" : "0" }}>
              <div style={{ flexShrink: 0, paddingTop: "2px" }}>
                <RiskBadge level={change.risk_level} />
              </div>
              <p
                style={{
                  fontSize: "13px",
                  color: change.risk_reason ? "#b0b5c4" : "#565b6e",
                  lineHeight: 1.6,
                  fontStyle: change.risk_reason ? "normal" : "italic",
                }}
              >
                {change.risk_reason ?? "No risk reason recorded."}
              </p>
            </div>

            {/* Suggested checks for high/critical */}
            {checks.length > 0 && (
              <div
                style={{
                  borderTop: `1px solid ${riskBorder}`,
                  paddingTop: "12px",
                  marginTop: "4px",
                }}
              >
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
                  Suggested checks
                </p>
                <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
                  {checks.map((check, i) => (
                    <li
                      key={i}
                      style={{
                        fontSize: "13px",
                        color: "#8b90a0",
                        lineHeight: 1.6,
                        display: "flex",
                        gap: "8px",
                        marginBottom: "4px",
                      }}
                    >
                      <span style={{ flexShrink: 0, color: "#565b6e" }}>•</span>
                      <span>{check}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <ProviderMetaRows metadata={change.provider_metadata} />
          </Panel>
        </div>

        {/* ── Field-level diff ────────────────────────────────────────── */}
        <div>
          <SectionLabel>
            {change.change_type === "modified"
              ? "What changed"
              : change.change_type === "added"
              ? (isGitHub || isVercel || isStripe || isAWS) ? "Configuration added" : "DNS record added"
              : (isGitHub || isVercel || isStripe || isAWS) ? "Configuration removed" : "DNS record removed"}
          </SectionLabel>

          <Panel>
            {change.change_type === "modified" ? (
              <ModifiedDiffPanel change={change} />
            ) : (
              <AddedRemovedPanel change={change} isGitHub={isGitHub || isVercel || isStripe || isAWS} />
            )}
          </Panel>
        </div>

        {/* ── Snapshot context ────────────────────────────────────────── */}
        {(change.prev_snapshot_id || change.new_snapshot_id) && (
          <div>
            <SectionLabel>Snapshot context</SectionLabel>
            <SnapshotContextPanel change={change} />
          </div>
        )}

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
              <span>▶</span>
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

        {/* ── Raw / debug ─────────────────────────────────────────────── */}
        <div>
          <RawSection change={change} />
        </div>
      </div>
    </>
  );
}
