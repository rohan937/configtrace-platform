"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@clerk/nextjs";
import type { Integration } from "@/types";
import { getIntegrations } from "@/lib/api";
import { getDisplayStatus } from "@/lib/integrationStatus";
import { usePollingRefresh } from "@/hooks/usePollingRefresh";
import PageHeader from "@/components/common/PageHeader";
import IntegrationList from "@/components/integrations/IntegrationList";
import CloudflareIntegrationForm from "@/components/integrations/CloudflareIntegrationForm";
import GitHubIntegrationForm from "@/components/integrations/GitHubIntegrationForm";
import GitHubAppConnectCard from "@/components/integrations/GitHubAppConnectCard";
import VercelIntegrationForm from "@/components/integrations/VercelIntegrationForm";
import StripeIntegrationForm from "@/components/integrations/StripeIntegrationForm";
import AWSIntegrationForm from "@/components/integrations/AWSIntegrationForm";
import FirebaseIntegrationForm from "@/components/integrations/FirebaseIntegrationForm";
import SupabaseIntegrationForm from "@/components/integrations/SupabaseIntegrationForm";
import ShopifyIntegrationForm from "@/components/integrations/ShopifyIntegrationForm";
// ── M82-pre.1 — credential connect forms ──────────────────────────────────────
import AzureIntegrationForm from "@/components/integrations/AzureIntegrationForm";
import GoogleCloudIntegrationForm from "@/components/integrations/GoogleCloudIntegrationForm";
import TwilioIntegrationForm from "@/components/integrations/TwilioIntegrationForm";
import SendGridIntegrationForm from "@/components/integrations/SendGridIntegrationForm";
import Auth0IntegrationForm from "@/components/integrations/Auth0IntegrationForm";
// ── M82A — Datadog drift provider foundation ───────────────────────────────────
import DatadogIntegrationForm from "@/components/integrations/DatadogIntegrationForm";
// ── M83A — Clerk drift provider foundation ─────────────────────────────────────
import ClerkIntegrationForm from "@/components/integrations/ClerkIntegrationForm";
// ── M84A — PagerDuty drift provider foundation ───────────────────────────────
import PagerDutyIntegrationForm from "@/components/integrations/PagerDutyIntegrationForm";
// ── M85A — Linear drift provider foundation ──────────────────────────────────
import LinearIntegrationForm from "@/components/integrations/LinearIntegrationForm";
// ── M86A — Jira drift provider foundation ────────────────────────────────────
import JiraIntegrationForm from "@/components/integrations/JiraIntegrationForm";
// ── M87A — GitLab drift provider foundation ───────────────────────────────────
import GitLabIntegrationForm from "@/components/integrations/GitLabIntegrationForm";
// ── M88A — Terraform Cloud drift provider foundation ──────────────────────────
import TerraformCloudIntegrationForm from "@/components/integrations/TerraformCloudIntegrationForm";
import KubernetesIntegrationForm from "@/components/integrations/KubernetesIntegrationForm";
import OktaIntegrationForm from "@/components/integrations/OktaIntegrationForm";
import EntraIntegrationForm from "@/components/integrations/EntraIntegrationForm";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import {
  PROVIDERS,
  PROVIDER_IDS,
  SECURITY_PREVIEW_PROVIDER_IDS,
} from "@/lib/providers";
import type { ProviderId } from "@/lib/providers";

type Provider = ProviderId;
// GitHub sub-modes: "app" = recommended GitHub App flow, "pat" = advanced PAT flow
type GitHubMode = "app" | "pat";

// ── Category display labels ───────────────────────────────────────────────────

const CATEGORY_LABELS: Record<string, string> = {
  cdn_dns:        "CDN · DNS",
  developer:      "Developer tools",
  hosting:        "Hosting",
  payments:       "Payments",
  cloud:          "Cloud infrastructure",
  backend:        "App backend",
  commerce:       "Commerce",
  // M82-pre — security-preview categories.
  communications: "Communications",
  identity:       "Identity",
  // M82A — Datadog observability category.
  observability:  "Observability",
  // M84A — PagerDuty incident_management category.
  incident_management: "Incident management",
  // M85A — Linear devops category.
  devops: "Developer tools · Project management",
};

// M82-pre — fast lookup for security-preview providers.
const SECURITY_PREVIEW_SET = new Set<ProviderId>(SECURITY_PREVIEW_PROVIDER_IDS);

// Providers where a trust / data-minimisation note is shown on the card.
// All providers show a trust note so users know what ConfigTrace does and doesn't access.
const SHOW_TRUST_NOTE = new Set<ProviderId>(PROVIDER_IDS);

// ── SetupSteps ────────────────────────────────────────────────────────────────

interface StepDef {
  heading: string;
  body: React.ReactNode;
}

function SetupSteps({ steps }: { steps: StepDef[] }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
      {steps.map((step, idx) => (
        <div key={idx} style={{ display: "flex", gap: "12px", alignItems: "flex-start" }}>
          <span
            style={{
              flexShrink: 0,
              width: "18px",
              height: "18px",
              borderRadius: "50%",
              background: "#1e2030",
              border: "1px solid #3a3d4a",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: "10px",
              color: "#565b6e",
              fontWeight: 700,
              marginTop: "1px",
            }}
          >
            {idx + 1}
          </span>
          <p style={{ margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
            <span style={{ color: "#e8eaf0" }}>{step.heading}</span>{" "}
            {step.body}
          </p>
        </div>
      ))}
    </div>
  );
}

// ── Provider card ─────────────────────────────────────────────────────────────

interface ProviderCounts {
  /** Rows where the latest sync succeeded (or never ran). Backend status active. */
  healthy: number;
  /** Rows where backend status is active but the latest sync failed (any category). */
  failing: number;
  /** Rows where backend status is needs_reconnect. */
  needsReconnect: number;
}

function ProviderCard({
  providerId,
  counts,
  onConnect,
}: {
  providerId: ProviderId;
  counts: ProviderCounts;
  onConnect: (p: Provider) => void;
}) {
  const meta       = PROVIDERS[providerId];
  // M59.15: "connected" for card-styling purposes means any row exists.
  // The headline pill tracks healthy only; failing/needsReconnect surface
  // as separate sub-pills so the dashboard never overstates green health.
  const totalRows = counts.healthy + counts.failing + counts.needsReconnect;
  const connected = totalRows > 0;
  const catLabel   = CATEGORY_LABELS[meta.category] ?? meta.category;
  // M82-pre — security-preview providers have a complete security arc but
  // no credential connect UI yet. Their CTA routes to /security/cases.
  const isSecurityPreview = SECURITY_PREVIEW_SET.has(providerId);

  return (
    <div
      style={{
        background: "#13151a",
        border: `1px solid ${connected ? meta.borderColor : "#2a2d38"}`,
        borderRadius: "6px",
        padding: "16px",
        display: "flex",
        flexDirection: "column",
        gap: "10px",
      }}
    >
      {/* Header: name + category + connected count */}
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: "8px",
        }}
      >
        <div>
          <p style={{ margin: 0, fontSize: "14px", fontWeight: 600, color: meta.color }}>
            {meta.label}
          </p>
          <p style={{ margin: "3px 0 0", fontSize: "10px", color: "#565b6e", letterSpacing: "0.04em" }}>
            {catLabel}
          </p>
        </div>
        {connected && (
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "flex-end",
              gap: "2px",
              flexShrink: 0,
            }}
            aria-label={
              `${counts.healthy} healthy, ${counts.failing} failing, ` +
              `${counts.needsReconnect} need reconnect`
            }
          >
            {counts.healthy > 0 && (
              <span style={{ fontSize: "11px", color: "#3ccf7e", fontWeight: 500 }}>
                ✓ {counts.healthy} healthy
              </span>
            )}
            {counts.failing > 0 && (
              <span style={{ fontSize: "11px", color: "#f5a623", fontWeight: 500 }}>
                ⚠ {counts.failing} failing
              </span>
            )}
            {counts.needsReconnect > 0 && (
              <span style={{ fontSize: "11px", color: "#f5a623", fontWeight: 500 }}>
                ↻ {counts.needsReconnect} reconnect
              </span>
            )}
          </div>
        )}
      </div>

      {/* Short description */}
      <p style={{ margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.5 }}>
        {meta.description}
      </p>

      {/* Monitored surfaces — up to 4 bullets */}
      <div style={{ display: "flex", flexDirection: "column", gap: "3px" }}>
        {meta.monitoredSurfaces.slice(0, 4).map((surface, i) => (
          <span key={i} style={{ fontSize: "11px", color: "#565b6e", lineHeight: 1.4 }}>
            · {surface}
          </span>
        ))}
        {meta.monitoredSurfaces.length > 4 && (
          <span style={{ fontSize: "11px", color: "#3a3d4a" }}>
            + {meta.monitoredSurfaces.length - 4} more surface{meta.monitoredSurfaces.length - 4 !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {/* Trust / data-minimisation note — sensitive providers only */}
      {SHOW_TRUST_NOTE.has(providerId) && (
        <p style={{ margin: 0, fontSize: "11px", color: "#3a3d4a", lineHeight: 1.5 }}>
          {meta.trustNote}
        </p>
      )}

      {/* CTA button — M82-pre: security-preview providers show a
          "Security preview" CTA that routes to /security/cases (where the
          demo lives) instead of opening a connect form. */}
      {isSecurityPreview ? (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: "6px",
            marginTop: "2px",
          }}
        >
          <span
            style={{
              alignSelf: "flex-start",
              fontSize: "10px",
              color: "#8b90a0",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
            }}
            aria-label={`${meta.label} security preview`}
          >
            Security preview · Credential UI pending
          </span>
          <button
            onClick={() => onConnect(providerId)}
            aria-label={`Open ${meta.label} security demo`}
            style={{
              alignSelf: "flex-start",
              background: meta.bgColor,
              color: meta.color,
              border: `1px solid ${meta.borderColor}`,
              borderRadius: "5px",
              padding: "5px 14px",
              fontSize: "12px",
              fontWeight: 500,
              cursor: "pointer",
              fontFamily: "inherit",
            }}
          >
            View security demo
          </button>
        </div>
      ) : (
        <button
          onClick={() => onConnect(providerId)}
          aria-label={
            connected
              ? `Add another ${meta.label} integration`
              : `Connect ${meta.label}`
          }
          style={{
            alignSelf: "flex-start",
            background: connected ? "transparent" : meta.bgColor,
            color: meta.color,
            border: `1px solid ${meta.borderColor}`,
            borderRadius: "5px",
            padding: "5px 14px",
            fontSize: "12px",
            fontWeight: 500,
            cursor: "pointer",
            fontFamily: "inherit",
            marginTop: "2px",
          }}
        >
          {connected ? "Add another" : "Connect"}
        </button>
      )}
    </div>
  );
}

// ── Provider setup guide (step-by-step instructions per provider) ─────────────
//
// Previously this content was gated on total === 0 && !showForm.
// Now it always appears in the form panel so users see the steps whenever
// they are actually filling in the form — first use or subsequent connections.

function ProviderSetupGuide({ provider, githubMode }: { provider: Provider; githubMode: GitHubMode }) {
  if (provider === "cloudflare") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect Cloudflare DNS
        </p>
        <SetupSteps steps={[
          {
            heading: "Create a scoped API token.",
            body: <>In the Cloudflare dashboard → My Profile → API Tokens → Create Token.
              Use the <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Edit zone DNS</code> template,
              then restrict permissions to <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Zone → DNS → Read</code> and scope it to a specific zone only.</>,
          },
          {
            heading: "Find your Zone ID.",
            body: <>Cloudflare dashboard → select your domain → Overview page → scroll to the right sidebar. It&apos;s a 32-character hex string.</>,
          },
          {
            heading: "Connect below.",
            body: <>Paste both into the form. ConfigTrace validates the token against the live Cloudflare API before saving.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          Your token is encrypted before storage and never returned in any API response.
          ConfigTrace only requests read-only access — it cannot modify your DNS records.
        </p>
      </>
    );
  }

  if (provider === "github") {
    // GitHub App flow has its own self-contained UI; show PAT steps only for PAT mode
    if (githubMode === "app") {
      return (
        <p style={{ margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
          The GitHub App flow authorises ConfigTrace via an OAuth installation — no token needed.
          Click <strong style={{ color: "#e8eaf0" }}>Authorise with GitHub</strong> below and follow the prompts.
          To use a Personal Access Token instead, click the advanced link under the connect button.
        </p>
      );
    }
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a GitHub repository (Personal Access Token)
        </p>
        <SetupSteps steps={[
          {
            heading: "Create a fine-grained Personal Access Token.",
            body: <>GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token.
              Set the resource owner, choose &ldquo;Only select repositories&rdquo;, and pick your repository.</>,
          },
          {
            heading: "Grant the minimum required permissions.",
            body: <>Under Repository permissions set:
              {" "}<code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Metadata: Read</code>,
              {" "}<code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Administration: Read</code>,
              {" "}<code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Secrets: Read</code>,
              {" "}<code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Variables: Read</code>,
              {" "}<code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Environments: Read</code>.
              Leave all other permissions at &ldquo;No access&rdquo;.</>,
          },
          {
            heading: "Connect below.",
            body: <>Enter the repository owner, repository name, and paste the token. ConfigTrace validates access before saving.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          Your token is encrypted before storage and never returned in any API response.
          ConfigTrace uses read-only permissions — it cannot modify your repository.
        </p>
      </>
    );
  }

  if (provider === "vercel") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a Vercel project
        </p>
        <SetupSteps steps={[
          {
            heading: "Create a Vercel API token.",
            body: <>vercel.com → Settings → Tokens → Create. Give it a descriptive name and set an expiry. Copy the token — it won&apos;t be shown again.</>,
          },
          {
            heading: "Find your Project ID.",
            body: <>vercel.com → select your project → Settings → General → Project ID. It looks like <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>prj_xxxxxxxxxxxx</code>.</>,
          },
          {
            heading: "Connect below.",
            body: <>Paste both into the form. ConfigTrace validates the token before saving. Environment variable values are never stored — only key names and targets.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          Your token is encrypted before storage and never returned in any API response.
          ConfigTrace uses read-only access — it cannot modify your project or deployments.
        </p>
      </>
    );
  }

  if (provider === "stripe") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a Stripe account
        </p>
        <SetupSteps steps={[
          {
            heading: "Create a restricted API key.",
            body: <>dashboard.stripe.com → Developers → API keys → Create restricted key.
              Grant read-only access to: <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Account</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Webhook endpoints</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Payment method configurations</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Payment method domains</code>,{" "}
              and <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Billing portal configurations</code>.</>,
          },
          {
            heading: "Copy the key.",
            body: <>The key starts with <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>rk_live_</code> or <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>rk_test_</code>.
              Copy it — it won&apos;t be shown in full again after creation.</>,
          },
          {
            heading: "Connect below.",
            body: <>Paste the key into the form. ConfigTrace validates access against your Stripe account before saving.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          Your key is encrypted before storage and never returned in any API response.
          ConfigTrace uses read-only access — it never accesses customer data, payment history,
          or webhook signing secrets.
        </p>
      </>
    );
  }

  if (provider === "aws") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect an AWS account
        </p>
        <SetupSteps steps={[
          {
            heading: "Create a dedicated IAM user for ConfigTrace.",
            body: <>AWS Console → IAM → Users → Create user. Name it something like{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>configtrace-readonly</code>.
              Do not grant console access — programmatic access only.</>,
          },
          {
            heading: "Attach a read-only inline policy.",
            body: <>Grant the following read-only permissions.
              Required: <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>sts:GetCallerIdentity</code>.{" "}
              Optional (for S3 monitoring):{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>s3:ListAllMyBuckets</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>s3:GetBucketLocation</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>s3:GetBucketPublicAccessBlock</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>s3:GetBucketPolicy</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>s3:GetBucketPolicyStatus</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>s3:GetBucketAcl</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>s3:GetEncryptionConfiguration</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>s3:GetBucketVersioning</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>s3:GetBucketLogging</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>s3:GetLifecycleConfiguration</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>s3:GetBucketTagging</code>.{" "}
              Also optional: <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>ec2:DescribeRegions</code> for region discovery.
              Missing optional permissions are recorded as warnings — they do not fail the sync.</>,
          },
          {
            heading: "Create an access key.",
            body: <>IAM → select the user → Security credentials → Create access key → Application running outside AWS.
              Copy the Access Key ID and Secret Access Key — the secret is shown only once.</>,
          },
          {
            heading: "Connect below.",
            body: <>Paste both credentials, choose your default region, and select the regions to monitor.
              ConfigTrace validates via STS before saving.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          Credentials are encrypted before storage and never returned in any API response.
          ConfigTrace uses read-only access only — it never modifies, deletes, or creates
          any AWS resource, and never accesses billing, customer, or secret data.
        </p>
      </>
    );
  }

  if (provider === "firebase") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a Firebase project
        </p>
        <SetupSteps steps={[
          {
            heading: "Open Firebase Console → Project settings.",
            body: <>console.firebase.google.com → select your project → ⚙️ gear icon → Project settings → Service accounts tab.</>,
          },
          {
            heading: "Generate a new private key.",
            body: <>Click &ldquo;Generate new private key&rdquo; → confirm. A{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>.json</code> file
              will download. This file contains the service account credentials ConfigTrace
              uses to read your project configuration.</>,
          },
          {
            heading: "Connect below.",
            body: <>Open the downloaded JSON file in a text editor, select all, and paste it
              into the form. ConfigTrace validates access before saving. The{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>private_key</code>{" "}
              is encrypted before storage and is never returned in any API response.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace monitors Firebase configuration metadata and rules only. It does not
          read Firestore documents, Storage file contents, Auth user data, or Secret Manager values.
        </p>
      </>
    );
  }

  if (provider === "supabase") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a Supabase project
        </p>
        <SetupSteps steps={[
          {
            heading: "Generate a Management API access token.",
            body: <>Go to{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>
                supabase.com/dashboard/account/tokens
              </code>{" "}
              → &ldquo;Generate new token&rdquo;. Copy the token immediately — it will not
              be shown again.</>,
          },
          {
            heading: "Find your project reference.",
            body: <>In the Supabase dashboard, open your project. The project reference is the
              20-character string in the URL:{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>
                supabase.com/dashboard/project/&lt;ref&gt;
              </code>
            </>,
          },
          {
            heading: "Connect below.",
            body: <>Enter the access token and project reference. ConfigTrace validates access
              before saving. The token is encrypted before storage and never returned in
              any API response.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace monitors Supabase configuration, RLS/policy metadata, and Storage bucket
          metadata only. It does not read table rows, Storage file contents, Auth user data,
          or Edge Function source code.
        </p>
      </>
    );
  }

  if (provider === "shopify") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a Shopify store
        </p>
        <SetupSteps steps={[
          {
            heading: "Open your Shopify admin → Apps → Develop apps.",
            body: <>In your Shopify admin, navigate to{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>
                Apps → Develop apps
              </code>
              . If not visible, enable app development in your store settings first.</>,
          },
          {
            heading: "Create a custom app and configure API scopes.",
            body: <>Click &ldquo;Create an app&rdquo;, name it (e.g. &ldquo;ConfigTrace&rdquo;),
              then open the &ldquo;Configuration&rdquo; tab. Under Admin API access scopes,
              grant read access to: <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>
                read_content, read_shipping, read_themes
              </code> (or at minimum no scopes if the store only needs webhook/shop metadata
              monitoring). Do not grant write permissions or order/customer data access.</>,
          },
          {
            heading: "Install the app and copy the access token.",
            body: <>Click &ldquo;Install app&rdquo; → &ldquo;Install&rdquo;. On the next screen,
              reveal and copy the Admin API access token (starts with{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>shpat_</code>
              ). Store it securely — it will not be shown again.</>,
          },
          {
            heading: "Connect below.",
            body: <>Enter your shop domain and the access token. ConfigTrace validates access
              before saving. The token is encrypted before storage and never returned in
              any API response.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace monitors store configuration metadata, webhook subscriptions, and store
          policies only. It does not read orders, customers, payment data, transaction records,
          gift cards, or storefront theme files.
        </p>
      </>
    );
  }

  // ── M82-pre.1 — credential connect setup guides ────────────────────────────

  if (provider === "azure") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect an Azure subscription
        </p>
        <SetupSteps steps={[
          {
            heading: "Register a service principal.",
            body: <>Azure portal → Microsoft Entra ID → App registrations → New registration.
              Note the <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Application (client) ID</code> and{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Directory (tenant) ID</code>.</>,
          },
          {
            heading: "Create a client secret.",
            body: <>Certificates &amp; secrets → New client secret. Copy the value immediately —
              Azure shows it only once.</>,
          },
          {
            heading: "Grant read-only access.",
            body: <>Subscription → Access control (IAM) → Add role assignment → assign{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Reader</code> to the service principal.</>,
          },
          {
            heading: "Connect below.",
            body: <>Paste the tenant ID, client ID, client secret, and subscription ID into the form.
              The secret is encrypted before storage and never returned in any API response.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace stores Azure credentials encrypted and uses them only to read selected
          configuration metadata. It does not store client secrets, access tokens, private keys,
          raw policies, or customer data in findings.
        </p>
      </>
    );
  }

  if (provider === "google_cloud") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a Google Cloud project
        </p>
        <SetupSteps steps={[
          {
            heading: "Create a read-only service account.",
            body: <>Google Cloud Console → IAM &amp; Admin → Service Accounts → Create service account.
              Grant <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Viewer</code> at the project level,
              plus <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Security Reviewer</code> if you
              want IAM-policy posture findings.</>,
          },
          {
            heading: "Download a JSON key.",
            body: <>Service account → Keys → Add key → Create new key → JSON. The JSON includes
              the private_key — store it securely.</>,
          },
          {
            heading: "Connect below.",
            body: <>Paste the full JSON into the form. The entire JSON (including the private_key)
              is stored encrypted and never returned in any API response.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace stores Google Cloud credentials encrypted and uses them only to read selected
          configuration metadata. It does not store private keys, OAuth tokens, principal emails,
          raw IAM payloads, secret payloads, or customer data in findings.
        </p>
      </>
    );
  }

  if (provider === "twilio") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a Twilio account
        </p>
        <SetupSteps steps={[
          {
            heading: "Find your Account SID and Auth Token.",
            body: <>twilio.com/console → Account → API keys &amp; tokens. The Live Account SID and
              Live Auth Token are at the top of the page.</>,
          },
          {
            heading: "Connect below.",
            body: <>Paste both into the form. The auth token is encrypted before storage and
              never returned in any API response.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace stores Twilio credentials encrypted and uses them only to read selected
          account configuration metadata. It does not store auth tokens, API secret values,
          message bodies, call recordings, phone-message content, customer phone data, or
          customer PII in findings.
        </p>
      </>
    );
  }

  if (provider === "sendgrid") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a SendGrid account
        </p>
        <SetupSteps steps={[
          {
            heading: "Create a restricted API key.",
            body: <>SendGrid Console → Settings → API Keys → Create API Key → Restricted Access.
              Grant read-only on API Keys, Sender Authentication, Mail Settings, Tracking
              Settings, and Event Webhooks.</>,
          },
          {
            heading: "Connect below.",
            body: <>Paste the API key into the form. It is encrypted before storage and never
              returned in any API response.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace stores SendGrid credentials encrypted and uses them only to read selected
          mail configuration metadata. It does not store API key values, email content, recipient
          data, raw event payloads, webhook secrets, or customer PII in findings.
        </p>
      </>
    );
  }

  if (provider === "auth0") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect an Auth0 tenant
        </p>
        <SetupSteps steps={[
          {
            heading: "Pick an authentication mode.",
            body: <>Recommended: <strong style={{ color: "#b0b5c4" }}>client credentials</strong>.
              Auth0 Dashboard → Applications → Create Application → Machine-to-Machine →
              authorise it against the <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Auth0 Management API</code>.</>,
          },
          {
            heading: "Grant minimal read scopes.",
            body: <>Authorize read-only scopes such as{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>read:tenant_settings</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>read:clients</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>read:connections</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>read:resource_servers</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>read:rules</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>read:actions</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>read:guardian_factors</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>read:custom_domains</code>.</>,
          },
          {
            heading: "Connect below.",
            body: <>Paste the tenant domain plus either the M2M client ID + secret, or a Management
              API token for direct-token mode. All secrets are encrypted before storage and never
              returned in any API response.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace stores Auth0 credentials encrypted and uses them only to read selected
          tenant/application configuration metadata. It does not store client secrets, management
          tokens, access tokens, refresh tokens, ID tokens, JWTs, user emails, user IDs, login
          history, IP addresses, sessions, raw callback URLs, raw Auth0 logs, rule/action code,
          or customer PII in findings.
        </p>
      </>
    );
  }

  // ── M82A — Datadog setup guide ─────────────────────────────────────────────

  if (provider === "datadog") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a Datadog account
        </p>
        <SetupSteps steps={[
          {
            heading: "Create an API key.",
            body: <>Datadog → Organization Settings → API Keys → New Key. Give it a descriptive
              name such as &ldquo;ConfigTrace read&rdquo;. Copy the key immediately — it is shown only once.</>,
          },
          {
            heading: "Create an Application key.",
            body: <>Datadog → Organization Settings → Application Keys → New Application Key.
              Use a scoped key limited to{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>monitors_read</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>dashboards_read</code>,{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>api_keys_read</code>{" "}
              when possible. Copy the value immediately.</>,
          },
          {
            heading: "Select your Datadog site and connect below.",
            body: <>Choose the region that matches your Datadog account URL. Both keys are
              encrypted before storage and never returned in any API response.</>,
          },
        ]} />
        <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace stores Datadog credentials encrypted and uses them only to read selected
          configuration metadata. It does not store API key values, application key values,
          OAuth tokens, webhook secrets, raw monitor queries, raw dashboard JSON, logs, traces,
          metric values, incident text, emails, destination handles, customer data, or PII in
          findings.
        </p>
      </>
    );
  }

  // ── M83A — Clerk setup guide ───────────────────────────────────────────────

  if (provider === "clerk") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a Clerk instance
        </p>
        <SetupSteps steps={[
          {
            heading: "Create a Backend API secret key.",
            body: <>Clerk Dashboard → Configure → API Keys → Secret keys → Add secret key.
              Give it a descriptive name such as &ldquo;ConfigTrace read&rdquo;. Copy the key
              immediately — it is shown only once.</>,
          },
          {
            heading: "Use a read-only key scope.",
            body: <>Clerk secret keys with the default scope can read configuration. If your Clerk
              plan supports scoped keys, limit permissions to configuration reads only —
              no write access, no user data access, no session access.</>,
          },
          {
            heading: "Enter the secret key below.",
            body: <>Paste the secret key (sk_live_* or sk_test_*) in the form below.
              The Frontend API URL is optional and not required for configuration drift snapshots.</>,
          },
        ]} />
        <p style={{ margin: "12px 0 0", fontSize: "12px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace stores Clerk credentials encrypted and uses them only to read selected
          configuration metadata. It does not store secret key values, session tokens, JWTs,
          OAuth tokens, webhook secrets, raw redirect URLs, raw callback URLs, user emails,
          user IDs, phone numbers, names, organization member identities, session history,
          login history, IP addresses, user agents, customer data, or PII in findings.
        </p>
      </>
    );
  }

  // ── M84A — PagerDuty setup guide ──────────────────────────────────────────

  if (provider === "pagerduty") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a PagerDuty account
        </p>
        <SetupSteps steps={[
          {
            heading: "Create a read-only API token.",
            body: <>PagerDuty → Integrations → API Access Keys → Create New API Key.
              Give it a descriptive name such as &ldquo;ConfigTrace read&rdquo;. Copy the token
              immediately — it is shown only once.</>,
          },
          {
            heading: "Use read-only access.",
            body: <>The token only needs read access to services, escalation policies, schedules,
              and related configuration surfaces. No write permissions are required. ConfigTrace
              never triggers incidents or modifies on-call schedules.</>,
          },
          {
            heading: "Enter the API token below.",
            body: <>Paste the API token in the form below. It is stored encrypted and never
              returned in any API response.</>,
          },
        ]} />
        <p style={{ margin: "12px 0 0", fontSize: "12px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace stores PagerDuty credentials encrypted and uses them only to read selected
          configuration metadata. It does not store API token values, routing keys, integration
          keys, webhook secrets, delivery URLs, user emails, user names, phone numbers, contact
          methods, on-call user identities, responder identities, incident payloads, alert
          payloads, or customer PII in findings.
        </p>
      </>
    );
  }

  // ── M85A — Linear setup guide ─────────────────────────────────────────────

  if (provider === "linear") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a Linear workspace
        </p>
        <SetupSteps steps={[
          {
            heading: "Sign in to your Linear account.",
            body: <>Go to <strong style={{ color: "#e8eaf0" }}>linear.app</strong> and sign in
              to the workspace you want to connect.</>,
          },
          {
            heading: "Navigate to Settings → API.",
            body: <>Click your profile picture in the top-left corner and select
              &ldquo;API&rdquo;, or go to <strong style={{ color: "#e8eaf0" }}>Settings → API</strong>.</>,
          },
          {
            heading: "Click Create new API key.",
            body: <>Give it a descriptive label such as &ldquo;ConfigTrace read&rdquo;.
              Copy the API key — it will only be shown once.</>,
          },
          {
            heading: "Paste it in the field below.",
            body: <>The key is stored encrypted and never returned in any API response.</>,
          },
        ]} />
        <p style={{ margin: "12px 0 0", fontSize: "12px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace uses a read-only API key to snapshot configuration metadata only. It does
          not read issue content, comments, attachments, user emails, member identities, or
          customer data.
        </p>
      </>
    );
  }

  // ── M88A — Terraform Cloud setup guide ────────────────────────────────────

  if (provider === "terraform_cloud") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a Terraform Cloud organization
        </p>
        <SetupSteps steps={[
          {
            heading: "Sign in to Terraform Cloud.",
            body: <>Go to <strong style={{ color: "#e8eaf0" }}>app.terraform.io</strong> and sign in
              to the organization you want to connect.</>,
          },
          {
            heading: "Create an API token.",
            body: <>Open <strong style={{ color: "#e8eaf0" }}>User Settings → Tokens</strong>{" "}
              (or a team token under your organization settings) and click &ldquo;Create an API
              token&rdquo;. Copy the token — it is only shown once.</>,
          },
          {
            heading: "Enter your organization name.",
            body: <>This is your organization&apos;s URL slug (e.g.{" "}
              <strong style={{ color: "#e8eaf0" }}>app.terraform.io/app/your-org</strong>{" "}
              → enter <strong style={{ color: "#e8eaf0" }}>your-org</strong>). It is used only as
              an API path parameter and never stored in configuration records.</>,
          },
          {
            heading: "Optional: enter your Terraform Enterprise URL.",
            body: <>Leave blank for Terraform Cloud. For Terraform Enterprise or self-managed,
              enter your instance base URL.</>,
          },
        ]} />
        <p style={{ margin: "12px 0 0", fontSize: "12px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace uses a read-only token to snapshot configuration metadata only. It does
          not store organization names, workspace names, variable names or values, state file
          contents, plan/apply logs, VCS URLs, team names, user emails, or customer
          infrastructure data. Terraform Cloud drift snapshots and risk classification are in
          foundation stage. Security rules planned next.
        </p>
      </>
    );
  }

  // ── M87A — GitLab setup guide ──────────────────────────────────────────────

  if (provider === "gitlab") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a GitLab instance
        </p>
        <SetupSteps steps={[
          {
            heading: "Sign in to your GitLab account.",
            body: <>Go to <strong style={{ color: "#e8eaf0" }}>gitlab.com</strong> (or your
              self-managed instance) and sign in.</>,
          },
          {
            heading: "Create a personal access token.",
            body: <>Open <strong style={{ color: "#e8eaf0" }}>User Settings → Access Tokens</strong>{" "}
              and click &ldquo;Add new token&rdquo;. Select the{" "}
              <strong style={{ color: "#e8eaf0" }}>read_api</strong> scope. Copy the token — it is
              only shown once.</>,
          },
          {
            heading: "Paste the token in the field below.",
            body: <>The token is stored encrypted and never returned in any API response.</>,
          },
          {
            heading: "Optional: enter your self-managed GitLab URL.",
            body: <>Leave blank to connect to gitlab.com. For self-managed GitLab, enter your
              instance base URL.</>,
          },
        ]} />
        <p style={{ margin: "12px 0 0", fontSize: "12px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace uses a read-only token to snapshot configuration metadata only. It does
          not read project names, branch names, issue titles, MR content, CI variable values,
          deploy key material, webhook URLs, user emails, or customer data.
          GitLab drift snapshots and risk classification are in foundation stage.
          Security rules planned next.
        </p>
      </>
    );
  }

  // ── M86A — Jira setup guide ───────────────────────────────────────────────

  if (provider === "jira") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a Jira site
        </p>
        <SetupSteps steps={[
          {
            heading: "Sign in to your Atlassian account.",
            body: <>Go to <strong style={{ color: "#e8eaf0" }}>your-org.atlassian.net</strong> and
              sign in to the site you want to connect.</>,
          },
          {
            heading: "Create an API token.",
            body: <>Open <strong style={{ color: "#e8eaf0" }}>id.atlassian.com → Security → API
              tokens</strong> and click &ldquo;Create API token&rdquo;. Copy it — it is only shown once.</>,
          },
          {
            heading: "Enter your site URL and email.",
            body: <>Use your full site URL (e.g. https://your-org.atlassian.net) and the email
              tied to the token.</>,
          },
          {
            heading: "Paste the token in the field below.",
            body: <>The token is stored encrypted and never returned in any API response.</>,
          },
        ]} />
        <p style={{ margin: "12px 0 0", fontSize: "12px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace uses a read-only API token to snapshot configuration metadata only. It does
          not read issue keys, issue content, comments, attachments, user emails, account IDs, or
          customer data.
        </p>
      </>
    );
  }

  // ── Kubernetes message 9 — public launch setup guide ─────────────────────

  if (provider === "kubernetes") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect a Kubernetes cluster
        </p>
        <SetupSteps steps={[
          {
            heading: "Create a dedicated read-only ServiceAccount.",
            body: <>Do not use a cluster-admin kubeconfig. Apply a{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>ClusterRole</code> that
              grants only <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>get</code>/
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>list</code> on workload,
              RBAC, networking, and admission resources — never{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>secrets</code> or{" "}
              <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>configmaps</code>. The
              full minimum manifest is shown in the security notice below the form.</>,
          },
          {
            heading: "Generate a kubeconfig for that identity.",
            body: <>Bind the ServiceAccount to a kubeconfig using a long-lived token or your
              cluster&apos;s standard credential-issuance flow. &lsquo;exec&rsquo; and
              &lsquo;auth-provider&rsquo; authentication entries are not supported and are
              rejected at connection time.</>,
          },
          {
            heading: "Paste the kubeconfig below.",
            body: <>Optionally set a context — leave it blank to use the kubeconfig&apos;s
              current context. ConfigTrace validates the kubeconfig, checks cluster
              reachability, and resolves cluster identity before saving.</>,
          },
        ]} />
        <p style={{ margin: "12px 0 0", fontSize: "12px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace stores your kubeconfig encrypted and uses it only to read cluster
          configuration metadata. It does not read Secret or ConfigMap contents, exec into or
          attach to Pods, read Pod logs, port-forward, or create ServiceAccount tokens. Coverage
          may be partial if some API groups are not readable by the supplied credential.
        </p>
      </>
    );
  }

  // ── Okta message 8 — public launch setup guide ────────────────────────────

  if (provider === "okta") {
    return (
      <>
        <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
          How to connect an Okta org
        </p>
        <SetupSteps steps={[
          {
            heading: "Create a dedicated read-only admin account.",
            body: <>Do not generate the token from a Super Admin account. Assign the
              built-in <strong style={{ color: "#e8eaf0" }}>Read-Only Administrator</strong> role
              (or a custom admin role with equivalent read access to Users, Groups,
              Applications, Authentication Policies, and Administrator Role assignments)
              to a dedicated service-account admin.</>,
          },
          {
            heading: "Generate an API token from that account.",
            body: <>Sign in as that admin and open{" "}
              <strong style={{ color: "#e8eaf0" }}>Security → API → Tokens</strong> in the
              Okta Admin Console, then create a new token. Copy it — it is only shown once.
              Okta API tokens inherit the exact permissions of the account that created
              them; there is no separate scoping mechanism.</>,
          },
          {
            heading: "Enter your org URL and paste the token below.",
            body: <>Use your full org base URL (e.g. https://example.okta.com), including
              a custom domain if you use one. ConfigTrace validates the token and org
              reachability before saving.</>,
          },
        ]} />
        <p style={{ margin: "12px 0 0", fontSize: "12px", color: "#3a3d4a", lineHeight: 1.6 }}>
          ConfigTrace stores your Okta API token encrypted and uses it only to read org
          configuration metadata. It does not store passwords, password hashes, recovery
          answers, MFA secrets, OTP seeds, session/refresh/access tokens, private keys, or
          System Log payloads. Coverage may be partial if some API families are not readable
          by the supplied credential's admin role — connection diagnostics are shown after
          the first sync.
        </p>
      </>
    );
  }

  return null;
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [total, setTotal]               = useState<number>(0);
  const [loading, setLoading]           = useState(true);
  const [error, setError]               = useState<string | null>(null);
  const [showForm, setShowForm]         = useState(false);
  const [selectedProvider, setSelectedProvider] = useState<Provider>("cloudflare");
  const [githubMode, setGithubMode]     = useState<GitHubMode>("app");
  const { getToken, isLoaded }          = useAuth();
  const router                          = useRouter();

  const fetchIntegrations = useCallback(async () => {
    setError(null);
    try {
      const token = await getToken();
      const data  = await getIntegrations(token);
      setIntegrations(data.integrations);
      setTotal(data.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load integrations.");
    } finally {
      setLoading(false);
    }
  }, [getToken]);

  useEffect(() => {
    if (!isLoaded) return;
    fetchIntegrations();
  }, [isLoaded, fetchIntegrations]);

  const { refresh: manualRefresh, lastUpdatedAt } = usePollingRefresh({
    callback: fetchIntegrations,
    intervalMs: 30_000,
    enabled: !loading && error === null && isLoaded,
  });

  // ── Derived state ─────────────────────────────────────────────────────────

  /** Per-provider count breakdown (healthy / failing / needs reconnect).
   *
   * M59.15: the dashboard headline must distinguish "this integration is
   * working right now" from "this integration exists but its last sync
   * failed" from "this integration's credentials are gone".  Each bucket
   * is rendered as a distinct sub-pill on the provider card.
   */
  const integrationCountByProvider = useMemo(() => {
    const map = new Map<string, ProviderCounts>();
    for (const i of integrations) {
      const cur = map.get(i.provider) ?? {
        healthy: 0,
        failing: 0,
        needsReconnect: 0,
      };
      const d = getDisplayStatus(i);
      if (d === "needs_reconnect") cur.needsReconnect += 1;
      else if (d === "needs_attention" || d === "degraded") cur.failing += 1;
      else if (d === "active") cur.healthy += 1;
      // paused / deleted / unknown intentionally do not bump any count.
      map.set(i.provider, cur);
    }
    return map;
  }, [integrations]);

  // ── Handlers ─────────────────────────────────────────────────────────────

  function handleConnect(p: Provider) {
    // M82-pre — security-preview providers (azure, google_cloud, twilio,
    // sendgrid, auth0) have a complete security arc but no credential
    // connect form yet. Route them to /security/cases (where the demo card
    // lives) instead of opening a credential form.
    if (SECURITY_PREVIEW_SET.has(p)) {
      router.push("/security/cases");
      return;
    }
    setSelectedProvider(p);
    if (p === "github") setGithubMode("app");
    setShowForm(true);
  }

  function handleCreated() {
    setShowForm(false);
    fetchIntegrations();
  }

  function handleCancel() {
    setShowForm(false);
  }

  function formatElapsed(since: Date | null): string {
    if (!since) return "";
    const s = Math.round((Date.now() - since.getTime()) / 1000);
    if (s < 5)  return "just now";
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s / 60);
    return `${m}m ago`;
  }

  // ── Provider form renderer ────────────────────────────────────────────────

  function renderProviderForm() {
    if (selectedProvider === "cloudflare") {
      return <CloudflareIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    if (selectedProvider === "vercel") {
      return <VercelIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    if (selectedProvider === "stripe") {
      return <StripeIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    if (selectedProvider === "aws") {
      return <AWSIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    if (selectedProvider === "firebase") {
      return <FirebaseIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    if (selectedProvider === "supabase") {
      return <SupabaseIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    if (selectedProvider === "shopify") {
      return <ShopifyIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    // ── M82-pre.1 — credential connect forms ──────────────────────────────
    if (selectedProvider === "azure") {
      return <AzureIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    if (selectedProvider === "google_cloud") {
      return <GoogleCloudIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    if (selectedProvider === "twilio") {
      return <TwilioIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    if (selectedProvider === "sendgrid") {
      return <SendGridIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    if (selectedProvider === "auth0") {
      return <Auth0IntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    // ── M82A — Datadog ─────────────────────────────────────────────────────
    if (selectedProvider === "datadog") {
      return <DatadogIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    // ── M83A — Clerk ────────────────────────────────────────────────────────
    if (selectedProvider === "clerk") {
      return <ClerkIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    // ── M84A — PagerDuty ─────────────────────────────────────────────────────
    if (selectedProvider === "pagerduty") {
      return <PagerDutyIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    // ── M85A — Linear ─────────────────────────────────────────────────────────
    if (selectedProvider === "linear") {
      return <LinearIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    // ── M86A — Jira ─────────────────────────────────────────────────────────────
    if (selectedProvider === "jira") {
      return <JiraIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    // ── M87A — GitLab ────────────────────────────────────────────────────────────
    if (selectedProvider === "gitlab") {
      return <GitLabIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    // ── M88A — Terraform Cloud ───────────────────────────────────────────────────
    if (selectedProvider === "terraform_cloud") {
      return <TerraformCloudIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    // ── Kubernetes message 9 — public launch ─────────────────────────────────────
    if (selectedProvider === "kubernetes") {
      return <KubernetesIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    // ── Okta message 8 — public launch ───────────────────────────────────────────
    if (selectedProvider === "okta") {
      return <OktaIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    // ── Microsoft Entra ID message 8 — public launch ──────────────────────────────
    if (selectedProvider === "entra") {
      return <EntraIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />;
    }
    // GitHub — two sub-modes
    if (githubMode === "app") {
      return (
        <div>
          <GitHubAppConnectCard onCancel={handleCancel} />
          <div style={{ marginTop: "-12px", marginBottom: "24px" }}>
            <button
              onClick={() => setGithubMode("pat")}
              style={{
                background: "transparent",
                border: "none",
                color: "#565b6e",
                fontSize: "12px",
                cursor: "pointer",
                fontFamily: "inherit",
                padding: 0,
                textDecoration: "underline",
              }}
            >
              Advanced: use a Personal Access Token instead →
            </button>
          </div>
        </div>
      );
    }
    return (
      <div>
        <div style={{ marginBottom: "12px" }}>
          <button
            onClick={() => setGithubMode("app")}
            style={{
              background: "transparent",
              border: "none",
              color: "#4f80f7",
              fontSize: "12px",
              cursor: "pointer",
              fontFamily: "inherit",
              padding: 0,
            }}
          >
            ← Back to GitHub App (recommended)
          </button>
        </div>
        <GitHubIntegrationForm onCreated={handleCreated} onCancel={handleCancel} />
      </div>
    );
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <>
      <PageHeader
        title="Integrations"
        description="Connect your stack to monitor configuration drift across cloud, app backend, payments, DNS, repos, and deployments."
      />

      <div className="px-6 py-6">

        {/* ── Global trust line ─────────────────────────────────────────── */}
        <p
          style={{
            fontSize: "12px",
            color: "#565b6e",
            marginBottom: "24px",
            lineHeight: 1.6,
            borderLeft: "2px solid #2a2d38",
            paddingLeft: "10px",
          }}
        >
          ConfigTrace tracks configuration metadata and security posture. It does not read
          customer data, secret values, table rows, documents, or file contents.
        </p>

        {/* ── First-connection guidance ──────────────────────────────────── */}
        {!loading && !error && total === 0 && !showForm && (
          <div
            role="note"
            style={{
              background: "rgba(79,128,247,0.06)",
              border: "1px solid rgba(79,128,247,0.20)",
              borderRadius: "8px",
              padding: "14px 18px",
              marginBottom: "20px",
            }}
          >
            <p
              style={{
                margin: "0 0 6px",
                fontSize: "14px",
                fontWeight: 600,
                color: "#e8eaf0",
              }}
            >
              Connect your first provider
            </p>
            <p
              style={{
                margin: "0 0 10px",
                fontSize: "13px",
                color: "#8b90a0",
                lineHeight: 1.6,
              }}
            >
              Choose a provider below. The first sync establishes a baseline snapshot —
              no changes are flagged on that run. From the second sync onwards, ConfigTrace
              shows exactly what changed and rates each change by risk level.
            </p>
            <p style={{ margin: 0, fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
              <strong style={{ color: "#b0b5c4" }}>Good starting points:</strong>
              {" "}GitHub (branch protection · secrets), Cloudflare (DNS drift), or Vercel (env vars · domains).
            </p>
          </div>
        )}

        {/* ── Marketplace grid OR form panel ────────────────────────────── */}
        {!showForm ? (
          /* ── Provider marketplace ───────────────────────────────────── */
          <div style={{ marginBottom: "32px" }}>
            <p
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                marginBottom: "14px",
              }}
            >
              Available providers
            </p>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(3, 1fr)",
                gap: "12px",
              }}
            >
              {(PROVIDER_IDS as Provider[]).map((pid) => (
                <ProviderCard
                  key={pid}
                  providerId={pid}
                  counts={
                    integrationCountByProvider.get(pid) ?? {
                      healthy: 0,
                      failing: 0,
                      needsReconnect: 0,
                    }
                  }
                  onConnect={handleConnect}
                />
              ))}
            </div>
          </div>
        ) : (
          /* ── Form panel ──────────────────────────────────────────────── */
          <div style={{ marginBottom: "32px" }}>
            {/* Form panel header */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "14px",
                marginBottom: "20px",
              }}
            >
              <button
                onClick={handleCancel}
                aria-label="Back to provider list"
                style={{
                  background: "transparent",
                  border: "1px solid #2a2d38",
                  borderRadius: "5px",
                  color: "#8b90a0",
                  fontSize: "12px",
                  cursor: "pointer",
                  fontFamily: "inherit",
                  padding: "4px 10px",
                }}
                onMouseOver={(e) => {
                  (e.currentTarget as HTMLButtonElement).style.color = "#e8eaf0";
                }}
                onMouseOut={(e) => {
                  (e.currentTarget as HTMLButtonElement).style.color = "#8b90a0";
                }}
              >
                ← Back
              </button>
              <span
                style={{
                  fontSize: "15px",
                  fontWeight: 600,
                  color: PROVIDERS[selectedProvider].color,
                }}
              >
                Connect {PROVIDERS[selectedProvider].label}
              </span>
            </div>

            {/* Setup guide */}
            <div
              style={{
                background: "#13151a",
                border: "1px solid #2a2d38",
                borderRadius: "6px",
                padding: "18px 20px",
                marginBottom: "20px",
              }}
            >
              <ProviderSetupGuide provider={selectedProvider} githubMode={githubMode} />
            </div>

            {/* Provider form */}
            {renderProviderForm()}

            {/* Billing limit note */}
            <p
              style={{
                marginTop: "14px",
                fontSize: "11px",
                color: "#565b6e",
                lineHeight: 1.6,
              }}
            >
              If integration creation is blocked, you may have reached your plan&apos;s integration
              limit.{" "}
              <Link
                href="/settings/workspace/billing"
                style={{ color: "#4f80f7", textDecoration: "none" }}
              >
                View billing and plan →
              </Link>
            </p>
          </div>
        )}

        {/* ── Connected integrations header ─────────────────────────────── */}
        {!loading && !error && total > 0 && (
          <div
            className="mb-4 flex flex-wrap items-center justify-between"
            style={{ gap: "10px", fontSize: "12px", color: "#8b90a0" }}
          >
            <div className="flex flex-wrap items-center" style={{ gap: "10px" }}>
              <span>
                {total} integration{total === 1 ? "" : "s"} connected
              </span>
              <span style={{ color: "#3a3d4a" }}>·</span>
              <span title="Celery Beat fires every 5 minutes; each integration uses its own configured interval (5–60 min, default 60)">
                Scheduled sync: configured
              </span>
              <span style={{ color: "#3a3d4a" }}>·</span>
              <span
                style={{ color: "#565b6e" }}
                title="Requires RESEND_API_KEY and ALERTS_FROM_EMAIL configured"
              >
                Email alerts: high-risk and critical changes only
              </span>
            </div>
            <div className="flex items-center gap-2">
              {lastUpdatedAt && (
                <span style={{ fontSize: "11px", color: "#3a3d4a" }}>
                  Updated {formatElapsed(lastUpdatedAt)}
                </span>
              )}
              <button
                onClick={manualRefresh}
                aria-label="Refresh integrations"
                title="Refresh integrations"
                style={{
                  background: "transparent",
                  border: "1px solid #2a2d38",
                  borderRadius: "6px",
                  color: "#565b6e",
                  fontSize: "11px",
                  padding: "3px 8px",
                  cursor: "pointer",
                  fontFamily: "inherit",
                }}
              >
                ↻
              </button>
            </div>
          </div>
        )}

        {/* ── Content: loading / error / integration list ───────────────── */}
        {loading && <LoadingState />}
        {!loading && error && (
          <div>
            <ErrorState message={error} />
            <div className="flex justify-center mt-4">
              <button
                onClick={fetchIntegrations}
                style={{
                  background: "transparent",
                  border: "1px solid #4f80f7",
                  color: "#4f80f7",
                  borderRadius: "6px",
                  padding: "6px 14px",
                  fontSize: "13px",
                  cursor: "pointer",
                  fontFamily: "inherit",
                }}
              >
                Retry
              </button>
            </div>
          </div>
        )}
        {!loading && !error && (
          <IntegrationList
            integrations={integrations}
            onSyncComplete={fetchIntegrations}
            onManagementComplete={fetchIntegrations}
          />
        )}
      </div>
    </>
  );
}
