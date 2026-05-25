"use client";

import { useRouter } from "next/navigation";
import PageHeader from "@/components/common/PageHeader";
import { PROVIDERS, PROVIDER_IDS } from "@/lib/providers";

// ── Per-provider "does not read" lists ────────────────────────────────────────
// Complements the monitoredSurfaces in providers.ts with honest "never" lists.

const DOES_NOT_READ: Record<string, string[]> = {
  aws: [
    "S3 object contents or bucket data",
    "Database row data (RDS, DynamoDB)",
    "Lambda function source code",
    "Secret values from Secrets Manager or Parameter Store",
    "CloudWatch log event contents",
    "Application data of any kind",
  ],
  firebase: [
    "Firestore documents or collection data",
    "Firebase Storage file contents",
    "Auth user PII or credentials",
    "Cloud Functions source code",
    "Secret values",
  ],
  supabase: [
    "Database rows or table data",
    "Auth user PII or session tokens",
    "Edge Function source code",
    "Secret values or API keys",
    "Storage file contents",
  ],
  stripe: [
    "Card numbers or bank account details",
    "Customer payment method secrets",
    "Transaction history or customer PII",
    "Stripe secret API keys (name metadata only, never values)",
  ],
  github: [
    "Secret values (name and last-updated only, never values)",
    "Source code, commit contents, or file contents",
    "Pull request bodies or issue text",
    "Private repository contents beyond settings",
  ],
  cloudflare: [
    "Traffic content or request/response data",
    "Web Analytics metrics",
    "Worker function source code",
    "Origin application or server data",
  ],
  vercel: [
    "Environment variable values (key names only)",
    "Deployment logs or build output",
    "Function source code or build artifacts",
    "Application data",
  ],
};

// ── Section component ─────────────────────────────────────────────────────────

function ProviderSection({ pid }: { pid: string }) {
  const meta       = PROVIDERS[pid as keyof typeof PROVIDERS];
  if (!meta) return null;
  const doesNotRead = DOES_NOT_READ[pid] ?? [];

  return (
    <section
      aria-labelledby={`da-provider-${pid}`}
      style={{
        background: "#13151a",
        border: "1px solid #2a2d38",
        borderRadius: "8px",
        marginBottom: "14px",
        overflow: "hidden",
      }}
    >
      {/* Provider header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "10px",
          padding: "11px 18px",
          borderBottom: "1px solid #2a2d38",
          background: "#0f1117",
        }}
      >
        <span
          aria-hidden="true"
          style={{
            flexShrink: 0,
            display: "inline-block",
            width: "8px",
            height: "8px",
            borderRadius: "50%",
            background: meta.color,
          }}
        />
        <h2
          id={`da-provider-${pid}`}
          style={{
            margin: 0,
            fontSize: "13px",
            fontWeight: 600,
            color: meta.color,
          }}
        >
          {meta.label}
        </h2>
        <span
          style={{
            marginLeft: "auto",
            fontSize: "10px",
            color: "#565b6e",
            fontStyle: "italic",
            letterSpacing: "0.03em",
          }}
        >
          Read-only access
        </span>
      </div>

      {/* Two columns: Reads / Does not read */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "0",
          padding: "14px 0",
        }}
      >
        {/* Reads */}
        <div
          style={{
            padding: "0 18px",
            borderRight: "1px solid #1e2030",
          }}
        >
          <p
            style={{
              margin: "0 0 8px",
              fontSize: "10px",
              fontWeight: 600,
              color: "#3ccf7e",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
            }}
          >
            Reads
          </p>
          <ul role="list" style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {meta.monitoredSurfaces.map((surface) => (
              <li
                key={surface}
                style={{
                  fontSize: "12px",
                  color: "#c4c8d4",
                  padding: "3px 0 3px 16px",
                  position: "relative",
                  lineHeight: 1.55,
                }}
              >
                <span
                  aria-hidden="true"
                  style={{ position: "absolute", left: 0, top: "3px", color: "#3ccf7e", fontSize: "11px" }}
                >
                  ✓
                </span>
                {surface}
              </li>
            ))}
          </ul>
        </div>

        {/* Does not read */}
        <div style={{ padding: "0 18px" }}>
          <p
            style={{
              margin: "0 0 8px",
              fontSize: "10px",
              fontWeight: 600,
              color: "#f87171",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
            }}
          >
            Does not read
          </p>
          <ul role="list" style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {doesNotRead.map((item) => (
              <li
                key={item}
                style={{
                  fontSize: "12px",
                  color: "#8b90a0",
                  padding: "3px 0 3px 16px",
                  position: "relative",
                  lineHeight: 1.55,
                }}
              >
                <span
                  aria-hidden="true"
                  style={{ position: "absolute", left: 0, top: "3px", color: "#f87171", fontSize: "11px" }}
                >
                  ✕
                </span>
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function DataAccessPage() {
  const router = useRouter();

  return (
    <>
      <PageHeader
        title="Data Access & Permissions"
        description="ConfigTrace monitors configuration metadata and security posture. It does not read customer data."
      />

      <div className="px-6 pb-8" style={{ maxWidth: "760px" }}>
        {/* Back link */}
        <button
          onClick={() => router.back()}
          aria-label="Back to Workspace"
          style={{
            background: "none",
            border: "none",
            color: "#8b90a0",
            cursor: "pointer",
            fontSize: "13px",
            padding: "0 0 20px 0",
            display: "flex",
            alignItems: "center",
            gap: "6px",
            fontFamily: "inherit",
          }}
        >
          ← Back to Workspace
        </button>

        {/* Intro callout */}
        <div
          role="note"
          style={{
            background: "rgba(79,128,247,0.06)",
            border: "1px solid rgba(79,128,247,0.20)",
            borderRadius: "8px",
            padding: "14px 18px",
            marginBottom: "24px",
          }}
        >
          <p style={{ margin: 0, fontSize: "13px", color: "#c4c8d4", lineHeight: 1.7 }}>
            ConfigTrace uses <strong style={{ color: "#e8eaf0" }}>read-only</strong> API access to
            snapshot your provider configuration. It never writes to your providers, never reads
            customer data, and never stores secret values in plaintext.
          </p>
        </div>

        {/* Provider sections */}
        {PROVIDER_IDS.map((pid) => (
          <ProviderSection key={pid} pid={pid} />
        ))}

        {/* Footer note */}
        <p
          style={{
            fontSize: "12px",
            color: "#565b6e",
            lineHeight: 1.7,
            marginTop: "8px",
          }}
        >
          Access is enforced by read-only IAM policies, fine-grained PATs, and restricted API keys.
          Credentials are encrypted at rest and never returned in API responses.{" "}
          <button
            onClick={() => router.push("/settings/workspace/members")}
            style={{
              background: "none",
              border: "none",
              color: "#4f80f7",
              cursor: "pointer",
              fontSize: "12px",
              padding: 0,
              fontFamily: "inherit",
            }}
          >
            Manage team access →
          </button>
        </p>
      </div>
    </>
  );
}
