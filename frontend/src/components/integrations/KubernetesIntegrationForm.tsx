"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";
import type { IntegrationCreateRequest } from "@/types";

interface KubernetesIntegrationFormProps {
  onCreated: () => void;
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
  boxSizing: "border-box",
};

const TEXTAREA_STYLE: React.CSSProperties = {
  ...INPUT_STYLE,
  fontFamily: "monospace",
  fontSize: "11px",
  lineHeight: 1.5,
  resize: "vertical",
  minHeight: "160px",
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

/**
 * Inline form for connecting a Kubernetes cluster.
 *
 * The kubeconfig content is sent to the backend once and immediately cleared
 * from state on success. It is never logged, never stored in localStorage or
 * sessionStorage, and never rendered after submission — after a successful
 * connect only "Kubeconfig configured" is shown, never the content itself.
 *
 * SECURITY: only configuration metadata is monitored. Secret and ConfigMap
 * contents, Pod exec/attach/logs/port-forward, and ServiceAccount token
 * creation are never accessed. 'exec' and 'auth-provider' kubeconfig auth
 * entries are rejected at connection time — ConfigTrace never executes an
 * external auth plugin.
 */
export default function KubernetesIntegrationForm({
  onCreated,
  onCancel,
}: KubernetesIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [kubeconfig, setKubeconfig] = useState("");
  const [context, setContext] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const { getToken } = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim()) {
      setError("Display name is required.");
      return;
    }
    if (!kubeconfig.trim()) {
      setError("Kubeconfig content is required.");
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      const payload: IntegrationCreateRequest = {
        provider: "kubernetes",
        display_name: displayName.trim(),
        kubeconfig: kubeconfig,  // sent once; cleared below
      };
      if (context.trim()) {
        payload.context = context.trim();
      }
      await createIntegration(payload, token);

      // Clear the sensitive field immediately — do not keep it in state.
      setKubeconfig("");
      setSuccessMsg("Kubeconfig configured. Kubernetes cluster connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your kubeconfig and try again."
      );
    } finally {
      setSubmitting(false);
    }
  }

  const canSubmit = !!displayName.trim() && !!kubeconfig.trim();

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
      <div
        style={{
          fontSize: "11px",
          color: "#8b90a0",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: "16px",
        }}
      >
        Connect Kubernetes Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Display name */}
          <div>
            <label htmlFor="kubernetes-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="kubernetes-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Cluster"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise later.
            </p>
          </div>

          {/* Security notice + minimum RBAC guidance */}
          <div
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: "4px",
              padding: "10px 12px",
              fontSize: "11px",
              color: "#6b7080",
              lineHeight: 1.75,
            }}
          >
            <span style={{ color: "#8b90a0", display: "block", marginBottom: "4px", fontWeight: 500 }}>
              Use a dedicated read-only Kubernetes identity for ConfigTrace.
              Do not provide cluster-admin credentials.
            </span>
            Grant a <code style={{ fontSize: "10px" }}>ClusterRole</code> with{" "}
            <code style={{ fontSize: "10px" }}>get</code>/<code style={{ fontSize: "10px" }}>list</code>{" "}
            only on: namespaces, pods, services, serviceaccounts, resourcequotas,
            limitranges, deployments, statefulsets, daemonsets, jobs, cronjobs,
            roles, clusterroles, rolebindings, clusterrolebindings, ingresses,
            networkpolicies, validatingwebhookconfigurations,
            mutatingwebhookconfigurations, and (if installed) the Gateway API
            gateways/httproutes.
            <br />
            <span style={{ color: "#3a3d4a", marginTop: "4px", display: "block" }}>
              Never grant access to secrets, configmaps, pods/exec, pods/attach,
              pods/log, pods/portforward, or serviceaccounts/token — ConfigTrace
              never requests or uses them.
            </span>
          </div>

          {/* Kubeconfig */}
          <div>
            <label htmlFor="kubernetes-kubeconfig" style={LABEL_STYLE}>
              Kubeconfig
              <span
                style={{
                  marginLeft: "6px",
                  background: "rgba(79,128,247,0.15)",
                  color: "#4f80f7",
                  borderRadius: "3px",
                  padding: "1px 5px",
                  fontSize: "9px",
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  verticalAlign: "middle",
                }}
              >
                Encrypted at rest
              </span>
            </label>
            <textarea
              id="kubernetes-kubeconfig"
              value={kubeconfig}
              onChange={(e) => setKubeconfig(e.target.value)}
              placeholder={`apiVersion: v1\nkind: Config\nclusters:\n  ...`}
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{ ...TEXTAREA_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Paste the full contents of the kubeconfig for the cluster to
              monitor. Never echoed back after saving — only &ldquo;Kubeconfig
              configured&rdquo; is shown once connected.
            </p>
          </div>

          {/* Context (optional) */}
          <div>
            <label htmlFor="kubernetes-context" style={LABEL_STYLE}>
              Context{" "}
              <span style={{ color: "#3a3d4a", fontWeight: 400 }}>(optional)</span>
            </label>
            <input
              id="kubernetes-context"
              type="text"
              value={context}
              onChange={(e) => setContext(e.target.value)}
              placeholder="Leave blank to use the kubeconfig's current context"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
            />
            <p style={HELPER_STYLE}>
              Leave blank to use the kubeconfig&apos;s current context. If set, the
              context must exist in the kubeconfig.
            </p>
          </div>

          {/* Error / success */}
          {error && (
            <p style={{ margin: 0, fontSize: "13px", color: "#f87171" }}>{error}</p>
          )}
          {successMsg && (
            <p style={{ margin: 0, fontSize: "13px", color: "#4ade80" }}>{successMsg}</p>
          )}

          {/* Actions */}
          <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
            <button
              type="button"
              onClick={onCancel}
              disabled={submitting}
              style={{
                background: "none",
                border: "1px solid #2a2d38",
                borderRadius: "6px",
                color: "#8b90a0",
                fontSize: "13px",
                padding: "7px 16px",
                cursor: "pointer",
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !canSubmit}
              style={{
                background: "#326CE5",
                border: "none",
                borderRadius: "6px",
                color: "#fff",
                fontSize: "13px",
                fontWeight: 600,
                padding: "7px 16px",
                cursor: submitting ? "not-allowed" : "pointer",
                opacity: submitting ? 0.7 : 1,
              }}
            >
              {submitting ? "Validating…" : "Connect Kubernetes"}
            </button>
          </div>
        </div>
      </form>

      <p
        style={{
          margin: "16px 0 0",
          fontSize: "11px",
          color: "#3a3d4a",
          lineHeight: 1.6,
        }}
      >
        ConfigTrace stores your kubeconfig encrypted and uses it only to read
        cluster configuration metadata. It does not store kubeconfig contents,
        bearer tokens, client certificates or keys, and it never reads Secret
        or ConfigMap contents, execs into or attaches to a Pod, reads Pod
        logs, port-forwards, or creates ServiceAccount tokens. Coverage may be
        partial if some API groups are not readable by the supplied
        credential — connection diagnostics are shown after validation.
      </p>
    </div>
  );
}
