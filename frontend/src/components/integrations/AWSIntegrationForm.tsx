"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface AWSIntegrationFormProps {
  /** Called after a successful integration creation so the parent can refresh. */
  onCreated: () => void;
  /** Called when the user dismisses / cancels the form. */
  onCancel: () => void;
}

const INPUT_STYLE: React.CSSProperties = {
  width: "100%",
  background: "#1c1e26",
  border: "1px solid #2a2d38",
  borderRadius: "6px",
  color: "#e8eaf0",
  fontSize: "13px",
  padding: "8px 10px",
  outline: "none",
  fontFamily: "inherit",
};

const LABEL_STYLE: React.CSSProperties = {
  display: "block",
  fontSize: "11px",
  color: "#8b90a0",
  textTransform: "uppercase",
  letterSpacing: "0.06em",
  marginBottom: "6px",
};

const HELPER_STYLE: React.CSSProperties = {
  fontSize: "12px",
  color: "#565b6e",
  marginTop: "5px",
};

// Common AWS regions grouped by geography
const AWS_REGIONS = [
  // US
  { value: "us-east-1",      label: "US East (N. Virginia)"     },
  { value: "us-east-2",      label: "US East (Ohio)"            },
  { value: "us-west-1",      label: "US West (N. California)"   },
  { value: "us-west-2",      label: "US West (Oregon)"          },
  // Europe
  { value: "eu-west-1",      label: "Europe (Ireland)"          },
  { value: "eu-west-2",      label: "Europe (London)"           },
  { value: "eu-west-3",      label: "Europe (Paris)"            },
  { value: "eu-central-1",   label: "Europe (Frankfurt)"        },
  { value: "eu-north-1",     label: "Europe (Stockholm)"        },
  { value: "eu-south-1",     label: "Europe (Milan)"            },
  // Asia-Pacific
  { value: "ap-east-1",      label: "Asia Pacific (Hong Kong)"  },
  { value: "ap-south-1",     label: "Asia Pacific (Mumbai)"     },
  { value: "ap-southeast-1", label: "Asia Pacific (Singapore)"  },
  { value: "ap-southeast-2", label: "Asia Pacific (Sydney)"     },
  { value: "ap-northeast-1", label: "Asia Pacific (Tokyo)"      },
  { value: "ap-northeast-2", label: "Asia Pacific (Seoul)"      },
  { value: "ap-northeast-3", label: "Asia Pacific (Osaka)"      },
  // Canada
  { value: "ca-central-1",   label: "Canada (Central)"          },
  // South America
  { value: "sa-east-1",      label: "South America (São Paulo)" },
  // Middle East / Africa
  { value: "me-south-1",     label: "Middle East (Bahrain)"     },
  { value: "af-south-1",     label: "Africa (Cape Town)"        },
];

/**
 * Inline form for connecting an AWS account integration.
 *
 * Credentials are sent to the backend once and immediately cleared from
 * state on success. They are never logged, never stored in localStorage or
 * sessionStorage, and never rendered after submission.
 *
 * SECURITY: Only account-level identity and region metadata is monitored.
 * ConfigTrace uses read-only IAM credentials. It never performs write actions
 * or accesses customer data, billing details, or sensitive resource contents.
 */
export default function AWSIntegrationForm({
  onCreated,
  onCancel,
}: AWSIntegrationFormProps) {
  const [displayName, setDisplayName]         = useState("");
  const [accessKeyId, setAccessKeyId]         = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
  const [defaultRegion, setDefaultRegion]     = useState("us-east-1");
  const [selectedRegions, setSelectedRegions] = useState<string[]>(["us-east-1"]);
  const [submitting, setSubmitting]           = useState(false);
  const [error, setError]                     = useState<string | null>(null);
  const [successMsg, setSuccessMsg]           = useState<string | null>(null);
  const { getToken } = useAuth();

  function toggleRegion(region: string) {
    setSelectedRegions((prev) =>
      prev.includes(region)
        ? prev.length > 1
          ? prev.filter((r) => r !== region)
          : prev  // Must keep at least one
        : [...prev, region],
    );
  }

  // When the default region changes, ensure it's in the selected list.
  function handleDefaultRegionChange(region: string) {
    setDefaultRegion(region);
    setSelectedRegions((prev) =>
      prev.includes(region) ? prev : [...prev, region],
    );
  }

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim()) {
      setError("Display name is required.");
      return;
    }
    if (!accessKeyId.trim()) {
      setError("AWS Access Key ID is required.");
      return;
    }
    if (!secretAccessKey.trim()) {
      setError("AWS Secret Access Key is required.");
      return;
    }
    if (selectedRegions.length === 0) {
      setError("Select at least one region to monitor.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider: "aws",
          display_name: displayName.trim(),
          aws_access_key_id: accessKeyId,          // sent once; cleared below
          aws_secret_access_key: secretAccessKey,  // sent once; cleared below
          aws_default_region: defaultRegion,
          aws_selected_regions: selectedRegions,
        },
        token,
      );

      // Clear sensitive fields immediately — do not keep them in state.
      setAccessKeyId("");
      setSecretAccessKey("");
      setSuccessMsg("AWS account connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your credentials and try again.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      style={{
        background: "#1c1e26",
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        padding: "20px 24px",
        marginBottom: "24px",
      }}
    >
      {/* Section heading */}
      <div
        style={{
          fontSize: "11px",
          color: "#8b90a0",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: "16px",
        }}
      >
        Connect AWS Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

          {/* Display name */}
          <div>
            <label htmlFor="aws-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="aws-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production AWS"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* AWS Access Key ID */}
          <div>
            <label htmlFor="aws-access-key-id" style={LABEL_STYLE}>
              AWS Access Key ID
            </label>
            <input
              id="aws-access-key-id"
              type="text"
              value={accessKeyId}
              onChange={(e) => setAccessKeyId(e.target.value)}
              placeholder="AKIAIOSFODNN7EXAMPLE"
              disabled={submitting}
              autoComplete="off"
              style={{
                ...INPUT_STYLE,
                fontFamily: "monospace",
                opacity: submitting ? 0.6 : 1,
              }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              The access key ID for a dedicated read-only IAM user or role.
              Starts with <code style={{ fontSize: "11px" }}>AKIA</code>.
            </p>
          </div>

          {/* AWS Secret Access Key */}
          <div>
            <label htmlFor="aws-secret-access-key" style={LABEL_STYLE}>
              AWS Secret Access Key
            </label>
            <input
              id="aws-secret-access-key"
              type="password"
              value={secretAccessKey}
              onChange={(e) => setSecretAccessKey(e.target.value)}
              placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
              disabled={submitting}
              autoComplete="new-password"
              style={{
                ...INPUT_STYLE,
                fontFamily: "monospace",
                opacity: submitting ? 0.6 : 1,
              }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            />
            <p style={HELPER_STYLE}>
              The secret key for your IAM user. Encrypted before storage and
              never returned in any API response.
            </p>
          </div>

          {/* IAM permissions note */}
          <div
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: "4px",
              padding: "10px 12px",
              fontSize: "11px",
              color: "#565b6e",
              lineHeight: 1.75,
            }}
          >
            <span style={{ color: "#8b90a0", display: "block", marginBottom: "6px", fontWeight: 500 }}>
              Recommended: create a dedicated read-only IAM user for ConfigTrace
            </span>

            {/* Required */}
            <span style={{ color: "#6b7080" }}>
              ✓ sts:GetCallerIdentity — Read{" "}
              <span style={{ color: "#4a5060", fontStyle: "italic" }}>(required)</span>
            </span>
            <br />

            {/* EC2 / VPC — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              EC2 / VPC network monitoring — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#565b6e" }}>○ ec2:DescribeRegions</span>
            <br />
            <span style={{ color: "#565b6e" }}>○ ec2:DescribeSecurityGroups &nbsp;○ ec2:DescribeSecurityGroupRules</span>
            <br />
            <span style={{ color: "#565b6e" }}>○ ec2:DescribeVpcs &nbsp;○ ec2:DescribeSubnets &nbsp;○ ec2:DescribeRouteTables</span>
            <br />
            <span style={{ color: "#565b6e" }}>○ ec2:DescribeInternetGateways &nbsp;○ ec2:DescribeNatGateways</span>
            <br />
            <span style={{ color: "#565b6e" }}>○ ec2:DescribeNetworkAcls &nbsp;○ ec2:DescribeVpcEndpoints</span>
            <br />

            {/* S3 — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              S3 monitoring — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ s3:ListAllMyBuckets &nbsp;○ s3:GetBucketLocation &nbsp;○ s3:GetPublicAccessBlock
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ s3:GetBucketPolicy &nbsp;○ s3:GetBucketPolicyStatus &nbsp;○ s3:GetBucketAcl
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ s3:GetEncryptionConfiguration &nbsp;○ s3:GetBucketVersioning &nbsp;○ s3:GetBucketLogging
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ s3:GetLifecycleConfiguration &nbsp;○ s3:GetBucketTagging
            </span>
            <br />

            {/* IAM — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              IAM monitoring — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ iam:GetAccountSummary &nbsp;○ iam:GetAccountPasswordPolicy
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ iam:ListUsers &nbsp;○ iam:GetUser &nbsp;○ iam:ListAccessKeys &nbsp;○ iam:GetAccessKeyLastUsed
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ iam:ListMFADevices &nbsp;○ iam:ListUserPolicies &nbsp;○ iam:GetUserPolicy &nbsp;○ iam:ListAttachedUserPolicies
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ iam:ListGroups &nbsp;○ iam:GetGroup &nbsp;○ iam:ListGroupPolicies &nbsp;○ iam:GetGroupPolicy &nbsp;○ iam:ListAttachedGroupPolicies
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ iam:ListRoles &nbsp;○ iam:GetRole &nbsp;○ iam:ListRolePolicies &nbsp;○ iam:GetRolePolicy &nbsp;○ iam:ListAttachedRolePolicies
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ iam:ListPolicies &nbsp;○ iam:GetPolicy &nbsp;○ iam:GetPolicyVersion &nbsp;○ iam:ListPolicyVersions
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ iam:ListOpenIDConnectProviders &nbsp;○ iam:GetOpenIDConnectProvider
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ iam:ListSAMLProviders &nbsp;○ iam:GetSAMLProvider
            </span>
            <br />

            {/* Route53 — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              Route53 DNS monitoring — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ route53:ListHostedZones &nbsp;○ route53:ListResourceRecordSets
            </span>
            <br />

            {/* CloudFront — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              CloudFront CDN monitoring — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ cloudfront:ListDistributions
            </span>
            <br />

            {/* Secrets Manager — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              Secrets Manager metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ secretsmanager:ListSecrets &nbsp;○ secretsmanager:DescribeSecret
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ secretsmanager:ListSecretVersionIds &nbsp;○ secretsmanager:GetResourcePolicy
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls GetSecretValue. Secret values are never read or stored.
            </span>
            <br />

            {/* SSM — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              SSM Parameter Store metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ ssm:DescribeParameters
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls GetParameter, GetParameters, or GetParameterHistory.
              Parameter values are never read or stored.
            </span>
            <br />

            {/* RDS — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              RDS database metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ rds:DescribeDBInstances &nbsp;○ rds:DescribeDBClusters
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ rds:DescribeDBSubnetGroups &nbsp;○ rds:DescribeDBSnapshots
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ rds:DescribeDBClusterSnapshots &nbsp;○ rds:ListTagsForResource
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never connects to databases or reads database content, passwords,
              or credentials. Only configuration metadata is collected.
            </span>
            <br />

            {/* Lambda — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              Lambda metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ lambda:ListFunctions &nbsp;○ lambda:GetFunctionConfiguration
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ lambda:ListAliases &nbsp;○ lambda:ListVersionsByFunction
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ lambda:ListEventSourceMappings &nbsp;○ lambda:GetEventSourceMapping
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ lambda:ListFunctionUrlConfigs &nbsp;○ lambda:GetFunctionUrlConfig
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ lambda:ListTags
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never invokes Lambda functions or downloads function code.
              Environment variable values are never read or stored — only key names are collected.
            </span>
            <br />

            {/* API Gateway — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              API Gateway metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ apigateway:GET (read-only) — REST APIs, stages, resources, methods, integrations
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ apigateway:GET (read-only) — HTTP/WebSocket APIs, routes, authorizers, integrations
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never reads API traffic, invokes endpoints, or accesses request or response contents.
              Stage variable values are never read or stored — only key names are collected.
            </span>
            <br />

            {/* ELB — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              Elastic Load Balancing metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ elasticloadbalancing:DescribeLoadBalancers &nbsp;○ elasticloadbalancing:DescribeListeners
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ elasticloadbalancing:DescribeRules &nbsp;○ elasticloadbalancing:DescribeTargetGroups
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ elasticloadbalancing:DescribeTargetHealth &nbsp;○ elasticloadbalancing:DescribeLoadBalancerAttributes
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ elasticloadbalancing:DescribeTargetGroupAttributes &nbsp;○ elasticloadbalancing:DescribeTags
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never reads load balancer access logs or request traffic.
              Only configuration metadata and target health counts are collected.
            </span>
            <br />

            {/* WAF — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              WAFv2 metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ wafv2:ListWebACLs &nbsp;○ wafv2:GetWebACL
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ wafv2:ListResourcesForWebACL &nbsp;○ wafv2:GetLoggingConfiguration &nbsp;○ wafv2:ListTagsForResource
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never reads sampled requests or request traffic.
              Only Web ACL configuration metadata (rule counts, default action, associations) is collected.
            </span>
            <br />

            {/* CloudTrail — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              CloudTrail posture metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ cloudtrail:DescribeTrails &nbsp;○ cloudtrail:GetTrailStatus
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ cloudtrail:GetEventSelectors &nbsp;○ cloudtrail:GetInsightSelectors
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ cloudtrail:ListEventDataStores &nbsp;○ cloudtrail:GetEventDataStore &nbsp;○ cloudtrail:ListTags
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls cloudtrail:LookupEvents and never reads CloudTrail log objects from S3.
              Only trail posture configuration is collected (logging status, validation, KMS presence).
              Event payloads, request parameters, and user identity data are never accessed or stored.
            </span>
            <br />

            {/* GuardDuty — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              GuardDuty posture metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ guardduty:ListDetectors &nbsp;○ guardduty:GetDetector
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ guardduty:ListPublishingDestinations &nbsp;○ guardduty:DescribePublishingDestination
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ guardduty:ListMembers &nbsp;○ guardduty:GetAdministratorAccount &nbsp;○ guardduty:ListTagsForResource
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls guardduty:GetFindings.
              Finding details, severity, evidence, and remediation data are never accessed or stored.
              Only detector posture (enabled status, protection features, publishing frequency) is collected.
            </span>
            <br />

            {/* Security Hub — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              Security Hub posture metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ securityhub:DescribeHub &nbsp;○ securityhub:GetEnabledStandards
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ securityhub:ListEnabledProductsForImport &nbsp;○ securityhub:ListFindingAggregators &nbsp;○ securityhub:GetFindingAggregator
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ securityhub:ListTagsForResource
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls securityhub:GetFindings.
              Finding details, evidence, and remediation data are never accessed or stored.
              Only hub posture (enabled status, standards subscriptions, aggregator configuration) is collected.
            </span>
            <br />

            {/* ECS — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              ECS cluster/service/task configuration metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ ecs:ListClusters &nbsp;○ ecs:DescribeClusters &nbsp;○ ecs:ListServices
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ ecs:DescribeServices &nbsp;○ ecs:DescribeTaskDefinition
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls logs:GetLogEvents.
              ECS task logs, container output, environment variable values, and secret values are never read or stored.
              Only cluster posture, service configuration, and task definition structure metadata is collected.
            </span>
            <br />

            {/* EKS — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              EKS cluster/node group/add-on configuration metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ eks:ListClusters &nbsp;○ eks:DescribeCluster &nbsp;○ eks:ListNodegroups &nbsp;○ eks:DescribeNodegroup
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ eks:ListFargateProfiles &nbsp;○ eks:DescribeFargateProfile &nbsp;○ eks:ListAddons &nbsp;○ eks:DescribeAddon
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls the Kubernetes API.
              Kubernetes pods, Secrets, ConfigMaps, events, and logs are never accessed or stored.
              Only EKS control-plane configuration and posture metadata is collected.
            </span>
            <br />

            {/* ECR — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              ECR repository and registry scanning metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ ecr:DescribeRepositories &nbsp;○ ecr:GetRepositoryPolicy
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ ecr:GetLifecyclePolicy &nbsp;○ ecr:GetRegistryScanningConfiguration
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls ecr:GetAuthorizationToken and never pulls container images.
              Image layers, manifests, and vulnerability scan findings are never accessed or stored.
              Only repository policy posture and scanning configuration metadata is collected.
            </span>
            <br />

            {/* EventBridge — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              EventBridge event bus, rule, target, and archive metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ events:ListEventBuses &nbsp;○ events:DescribeEventBus &nbsp;○ events:ListRules
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ events:ListTargetsByRule &nbsp;○ events:ListArchives &nbsp;○ events:DescribeArchive &nbsp;○ events:ListTagsForResource
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls events:PutEvents.
              EventBridge event payloads and event content are never read or stored.
              Only bus policy posture, rule state, target routing, and archive configuration metadata is collected.
            </span>
            <br />

            {/* SQS — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              SQS queue configuration metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ sqs:ListQueues &nbsp;○ sqs:GetQueueAttributes &nbsp;○ sqs:ListQueueTags
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls sqs:ReceiveMessage, sqs:SendMessage, sqs:DeleteMessage, or sqs:PurgeQueue.
              SQS message bodies and queue contents are never read or stored.
              Only queue configuration, policy posture, and encryption metadata is collected.
            </span>
            <br />

            {/* SNS — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              SNS topic and subscription metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ sns:ListTopics &nbsp;○ sns:GetTopicAttributes &nbsp;○ sns:ListSubscriptionsByTopic
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ sns:GetSubscriptionAttributes &nbsp;○ sns:ListTagsForResource
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls sns:Publish, sns:Subscribe, or sns:Unsubscribe.
              Notification contents and message bodies are never read or stored.
              Subscription endpoints are hashed for privacy; raw email/phone/URL values are never stored.
              Only topic policy posture, subscription protocol counts, and encryption metadata is collected.
            </span>
            <br />

            {/* KMS — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              KMS key and alias metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ kms:ListKeys &nbsp;○ kms:DescribeKey &nbsp;○ kms:GetKeyRotationStatus
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ kms:GetKeyPolicy &nbsp;○ kms:ListResourceTags &nbsp;○ kms:ListAliases
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls kms:Decrypt, kms:Encrypt, kms:GenerateDataKey, or any cryptographic operation.
              Key policy content is evaluated for posture only; raw policy JSON is not stored.
              Only key metadata, rotation status, and alias mappings are collected.
            </span>
            <br />

            {/* Backup — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              AWS Backup vault, plan, selection, and recovery point metadata — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ backup:ListBackupVaults &nbsp;○ backup:DescribeBackupVault &nbsp;○ backup:ListRecoveryPointsByBackupVault
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ backup:ListBackupPlans &nbsp;○ backup:GetBackupPlan &nbsp;○ backup:ListBackupSelections &nbsp;○ backup:GetBackupSelection &nbsp;○ backup:ListTags
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never starts backup jobs, restores backups, deletes recovery points, or reads protected resource contents.
              Only vault lock/encryption posture, plan rule structure, and recovery point metadata is collected.
            </span>
            <br />

            {/* Organizations — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              AWS Organizations and SCP posture — all optional, skipped if unavailable (management account or delegated admin required):
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ organizations:DescribeOrganization &nbsp;○ organizations:ListRoots &nbsp;○ organizations:ListAccounts
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ organizations:ListPolicies &nbsp;○ organizations:DescribePolicy &nbsp;○ organizations:ListTargetsForPolicy
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ organizations:ListOrganizationalUnitsForParent &nbsp;○ organizations:ListChildren &nbsp;○ organizations:ListPoliciesForTarget
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never creates, modifies, deletes, attaches, or detaches SCPs or OUs.
              SCP policy content is summarized for posture (allow/deny counts, denied actions); raw policy JSON is not stored.
              Only organization structure, account membership, and SCP attachment posture is collected.
            </span>
            <br />

            {/* CloudWatch — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              CloudWatch alarms, dashboards, metric streams, and anomaly detectors — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ cloudwatch:DescribeAlarms &nbsp;○ cloudwatch:DescribeAnomalyDetectors &nbsp;○ cloudwatch:ListTagsForResource
            </span>
            <br />
            <span style={{ color: "#3a3d4a" }}>
              ○ cloudwatch:ListDashboards &nbsp;○ cloudwatch:GetDashboard &nbsp;○ cloudwatch:ListMetricStreams &nbsp;○ cloudwatch:GetMetricStream
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls GetMetricData, GetMetricStatistics, or any metric datapoint API.
              Alarm action ARNs are type-summarized; raw values are not stored.
              Dashboard body is stored as a hash only; widget content is never stored.
            </span>
            <br />

            {/* CloudWatch Logs — optional */}
            <span style={{ color: "#4a5060", display: "block", marginTop: "6px", marginBottom: "2px", fontStyle: "italic" }}>
              CloudWatch Logs log groups, metric filters, and subscription filters — all optional, skipped if unavailable:
            </span>
            <span style={{ color: "#3a3d4a" }}>
              ○ logs:DescribeLogGroups &nbsp;○ logs:DescribeMetricFilters &nbsp;○ logs:DescribeSubscriptionFilters &nbsp;○ logs:ListTagsLogGroup
            </span>
            <br />
            <span style={{ color: "#565b6e", fontSize: "11px", fontStyle: "italic" }}>
              ConfigTrace never calls GetLogEvents, FilterLogEvents, StartQuery, or GetQueryResults.
              Log event contents are never accessed. Filter patterns are stored as hashes only.
              Subscription filter destination ARNs are type-summarized and hashed; raw values are not stored.
            </span>
            <br />

            <span style={{ color: "#3a3d4a", marginTop: "8px", display: "block" }}>
              ConfigTrace performs read-only operations only. It never modifies, deletes, or creates
              any AWS resource. Customer data, billing, and secrets are never accessed.
            </span>
          </div>

          {/* Default region */}
          <div>
            <label htmlFor="aws-default-region" style={LABEL_STYLE}>
              Default Region
            </label>
            <select
              id="aws-default-region"
              value={defaultRegion}
              onChange={(e) => handleDefaultRegionChange(e.target.value)}
              disabled={submitting}
              style={{
                ...INPUT_STYLE,
                cursor: submitting ? "not-allowed" : "pointer",
                opacity: submitting ? 0.6 : 1,
              }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#4f80f7"; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = "#2a2d38"; }}
            >
              {AWS_REGIONS.map((r) => (
                <option key={r.value} value={r.value} style={{ background: "#1c1e26" }}>
                  {r.label} ({r.value})
                </option>
              ))}
            </select>
            <p style={HELPER_STYLE}>
              Primary region for API calls (STS validation, EC2 region discovery).
            </p>
          </div>

          {/* Selected regions */}
          <div>
            <span style={LABEL_STYLE}>
              Regions to Monitor
            </span>
            <p style={{ ...HELPER_STYLE, marginTop: 0, marginBottom: "10px" }}>
              Select the AWS regions ConfigTrace should scan. At least one is required.
            </p>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))",
                gap: "6px",
              }}
            >
              {AWS_REGIONS.map((r) => {
                const checked = selectedRegions.includes(r.value);
                return (
                  <label
                    key={r.value}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                      padding: "6px 8px",
                      borderRadius: "5px",
                      border: `1px solid ${checked ? "rgba(79,128,247,0.35)" : "#2a2d38"}`,
                      background: checked ? "rgba(79,128,247,0.06)" : "#13151a",
                      cursor: submitting ? "not-allowed" : "pointer",
                      fontSize: "12px",
                      color: checked ? "#b0b5c4" : "#565b6e",
                      opacity: submitting ? 0.6 : 1,
                      userSelect: "none",
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleRegion(r.value)}
                      disabled={submitting || (checked && selectedRegions.length === 1)}
                      style={{ accentColor: "#4f80f7" }}
                    />
                    <span style={{ fontFamily: "monospace", fontSize: "11px", color: "#8b90a0", flexShrink: 0 }}>
                      {r.value}
                    </span>
                    <span style={{ fontSize: "11px" }}>{r.label}</span>
                  </label>
                );
              })}
            </div>
            <p style={{ ...HELPER_STYLE, marginTop: "8px" }}>
              {selectedRegions.length} region{selectedRegions.length === 1 ? "" : "s"} selected.
              The last selected region cannot be deselected.
            </p>
          </div>

          {/* Inline error */}
          {error && (
            <p style={{ fontSize: "13px", color: "#e84040", margin: 0 }}>
              {error}
            </p>
          )}

          {/* Inline success */}
          {successMsg && (
            <p style={{ fontSize: "13px", color: "#3ccf7e", margin: 0 }}>
              {successMsg}
            </p>
          )}

          {/* Buttons */}
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <button
              type="submit"
              disabled={submitting}
              style={{
                background: submitting ? "#2a3050" : "#4f80f7",
                color: "#ffffff",
                border: "none",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 500,
                cursor: submitting ? "not-allowed" : "pointer",
                opacity: submitting ? 0.7 : 1,
                fontFamily: "inherit",
              }}
            >
              {submitting ? "Validating…" : "Connect AWS"}
            </button>

            <button
              type="button"
              onClick={onCancel}
              disabled={submitting}
              style={{
                background: "transparent",
                color: "#8b90a0",
                border: "1px solid #2a2d38",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                cursor: submitting ? "not-allowed" : "pointer",
                fontFamily: "inherit",
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
