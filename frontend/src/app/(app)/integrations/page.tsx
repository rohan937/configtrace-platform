"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
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
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { PROVIDERS, PROVIDER_IDS } from "@/lib/providers";
import type { ProviderId } from "@/lib/providers";

type Provider = ProviderId;
// GitHub sub-modes: "app" = recommended GitHub App flow, "pat" = advanced PAT flow
type GitHubMode = "app" | "pat";

// ── Category display labels ───────────────────────────────────────────────────

const CATEGORY_LABELS: Record<string, string> = {
  cdn_dns:   "CDN · DNS",
  developer: "Developer tools",
  hosting:   "Hosting",
  payments:  "Payments",
  cloud:     "Cloud infrastructure",
  backend:   "App backend",
  commerce:  "Commerce",
};

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

      {/* CTA button */}
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
