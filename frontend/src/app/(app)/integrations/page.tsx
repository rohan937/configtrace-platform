"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import type { Integration } from "@/types";
import { getIntegrations } from "@/lib/api";
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
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";

type Provider = "cloudflare" | "github" | "vercel" | "stripe" | "aws" | "firebase" | "supabase";
// GitHub sub-modes: "app" = recommended GitHub App flow, "pat" = advanced PAT flow
type GitHubMode = "app" | "pat";

// ── SetupSteps helper component ───────────────────────────────────────────────

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

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState<Provider>("cloudflare");
  // GitHub sub-mode: "app" = GitHub App (default), "pat" = PAT (advanced)
  const [githubMode, setGithubMode] = useState<GitHubMode>("app");
  const { getToken, isLoaded } = useAuth();

  const fetchIntegrations = useCallback(async () => {
    setError(null);

    try {
      const token = await getToken();
      const data = await getIntegrations(token);
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

  // Polling — 30s, pauses when tab is hidden, resumes on visibility.
  const { refresh: manualRefresh, lastUpdatedAt } = usePollingRefresh({
    callback: fetchIntegrations,
    intervalMs: 30_000,
    enabled: !loading && error === null && isLoaded,
  });

  function handleCreated() {
    // Hide the form and refresh the list.
    setShowForm(false);
    fetchIntegrations();
  }

  function formatElapsed(since: Date | null): string {
    if (!since) return "";
    const s = Math.round((Date.now() - since.getTime()) / 1000);
    if (s < 5) return "just now";
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s / 60);
    return `${m}m ago`;
  }

  return (
    <>
      <PageHeader
        title="Integrations"
        description="Connect Cloudflare, GitHub, Vercel, Stripe, and AWS — trigger syncs and monitor configuration drift."
      />

      <div className="px-6 py-6">
        {/* ── First-time setup guide ────────────────────────────────────── */}
        {/* Shown before the user connects their first integration. Gives them
            enough context to choose a provider and gather credentials. */}
        {!loading && !error && total === 0 && !showForm && (
          <div
            className="mb-6"
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              padding: "20px 24px",
            }}
          >
            {/* Provider tabs */}
            <div style={{ display: "flex", gap: "8px", marginBottom: "18px" }}>
              {(["cloudflare", "github", "vercel", "stripe", "aws", "firebase", "supabase"] as Provider[]).map((p) => (
                <button
                  key={p}
                  onClick={() => setSelectedProvider(p)}
                  style={{
                    padding: "4px 12px",
                    borderRadius: "6px",
                    border: "1px solid",
                    fontSize: "11px",
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    cursor: "pointer",
                    fontFamily: "inherit",
                    fontWeight: selectedProvider === p ? 600 : 400,
                    background: selectedProvider === p ? "rgba(79,128,247,0.12)" : "#1c1e26",
                    color: selectedProvider === p ? "#4f80f7" : "#8b90a0",
                    borderColor: selectedProvider === p ? "rgba(79,128,247,0.35)" : "#2a2d38",
                  }}
                >
                  {p === "cloudflare" ? "Cloudflare" : p === "github" ? "GitHub" : p === "vercel" ? "Vercel" : p === "stripe" ? "Stripe" : p === "aws" ? "AWS" : p === "firebase" ? "Firebase" : "Supabase"}
                </button>
              ))}
            </div>

            {/* Cloudflare guide */}
            {selectedProvider === "cloudflare" && (
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
            )}

            {/* GitHub guide */}
            {selectedProvider === "github" && (
              <>
                <p style={{ margin: "0 0 14px", fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>
                  How to connect a GitHub repository
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
                      {" "}<code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Variables: Read</code>.
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
            )}

            {/* Vercel guide */}
            {selectedProvider === "vercel" && (
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
            )}

            {/* Stripe guide */}
            {selectedProvider === "stripe" && (
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
                      and <code style={{ fontFamily: "monospace", color: "#b0b5c4" }}>Payment method domains</code>.</>,
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
            )}

            {/* AWS guide */}
            {selectedProvider === "aws" && (
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
            )}

            {/* Firebase guide */}
            {selectedProvider === "firebase" && (
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
                  ConfigTrace uses read-only access only — it never modifies your Firebase project.
                  Firestore documents, Storage file contents, Auth user data, and Secret Manager
                  values are NEVER fetched or stored.
                </p>
              </>
            )}

            {/* Supabase guide */}
            {selectedProvider === "supabase" && (
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
                  ConfigTrace uses read-only access only — it never modifies your Supabase project.
                  Database row data, Auth user PII, Edge Function source code, secret values,
                  and Storage file contents are NEVER fetched or stored.
                </p>
              </>
            )}
          </div>
        )}

        {/* ── Connect form (toggle) ─────────────────────────────────────── */}
        {!showForm ? (
          <div className="mb-6" style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <button
              onClick={() => { setSelectedProvider("cloudflare"); setShowForm(true); }}
              style={{
                background: "#4f80f7",
                color: "#ffffff",
                border: "none",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 500,
                cursor: "pointer",
                fontFamily: "inherit",
              }}
            >
              Add Cloudflare Integration
            </button>
            <button
              onClick={() => { setSelectedProvider("github"); setGithubMode("app"); setShowForm(true); }}
              style={{
                background: "#1e2030",
                color: "#b0b5c4",
                border: "1px solid #3a3d4a",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 500,
                cursor: "pointer",
                fontFamily: "inherit",
              }}
            >
              Add GitHub Integration
            </button>
            <button
              onClick={() => { setSelectedProvider("vercel"); setShowForm(true); }}
              style={{
                background: "#1e2030",
                color: "#b0b5c4",
                border: "1px solid #3a3d4a",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 500,
                cursor: "pointer",
                fontFamily: "inherit",
              }}
            >
              Add Vercel Integration
            </button>
            <button
              onClick={() => { setSelectedProvider("stripe"); setShowForm(true); }}
              style={{
                background: "#1e2030",
                color: "#b0b5c4",
                border: "1px solid #3a3d4a",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 500,
                cursor: "pointer",
                fontFamily: "inherit",
              }}
            >
              Add Stripe Integration
            </button>
            <button
              onClick={() => { setSelectedProvider("aws"); setShowForm(true); }}
              style={{
                background: "#1e2030",
                color: "#b0b5c4",
                border: "1px solid #3a3d4a",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 500,
                cursor: "pointer",
                fontFamily: "inherit",
              }}
            >
              Add AWS Integration
            </button>
            <button
              onClick={() => { setSelectedProvider("firebase"); setShowForm(true); }}
              style={{
                background: "#1e2030",
                color: "#b0b5c4",
                border: "1px solid #3a3d4a",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 500,
                cursor: "pointer",
                fontFamily: "inherit",
              }}
            >
              Add Firebase Integration
            </button>
            <button
              onClick={() => { setSelectedProvider("supabase"); setShowForm(true); }}
              style={{
                background: "#1e2030",
                color: "#b0b5c4",
                border: "1px solid #3a3d4a",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 500,
                cursor: "pointer",
                fontFamily: "inherit",
              }}
            >
              Add Supabase Integration
            </button>
          </div>
        ) : selectedProvider === "cloudflare" ? (
          <CloudflareIntegrationForm
            onCreated={handleCreated}
            onCancel={() => setShowForm(false)}
          />
        ) : selectedProvider === "vercel" ? (
          <VercelIntegrationForm
            onCreated={handleCreated}
            onCancel={() => setShowForm(false)}
          />
        ) : selectedProvider === "stripe" ? (
          <StripeIntegrationForm
            onCreated={handleCreated}
            onCancel={() => setShowForm(false)}
          />
        ) : selectedProvider === "aws" ? (
          <AWSIntegrationForm
            onCreated={handleCreated}
            onCancel={() => setShowForm(false)}
          />
        ) : selectedProvider === "firebase" ? (
          <FirebaseIntegrationForm
            onCreated={handleCreated}
            onCancel={() => setShowForm(false)}
          />
        ) : selectedProvider === "supabase" ? (
          <SupabaseIntegrationForm
            onCreated={handleCreated}
            onCancel={() => setShowForm(false)}
          />
        ) : githubMode === "app" ? (
          /* GitHub App flow (recommended) */
          <div>
            <GitHubAppConnectCard onCancel={() => setShowForm(false)} />
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
        ) : (
          /* PAT flow (advanced) */
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
            <GitHubIntegrationForm
              onCreated={handleCreated}
              onCancel={() => setShowForm(false)}
            />
          </div>
        )}

        {/* ── Integration count + scheduled-sync notice ─────────────────── */}
        {/* The hourly-sync hint appears only when at least one integration
            exists — for empty-state users the setup guide above covers context. */}
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
                Scheduled sync: active
              </span>
              <span style={{ color: "#3a3d4a" }}>·</span>
              <span style={{ color: "#565b6e" }} title="Requires RESEND_API_KEY and ALERTS_FROM_EMAIL configured in Render">
                Email alerts: high-risk and critical changes only
              </span>
            </div>
            {/* Auto-refresh indicator */}
            <div className="flex items-center gap-2">
              {lastUpdatedAt && (
                <span style={{ fontSize: "11px", color: "#3a3d4a" }}>
                  Updated {formatElapsed(lastUpdatedAt)}
                </span>
              )}
              <button
                onClick={manualRefresh}
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

        {/* ── Content ───────────────────────────────────────────────────── */}
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
