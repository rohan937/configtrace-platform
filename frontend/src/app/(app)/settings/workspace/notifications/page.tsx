"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import {
  getNotificationSettings,
  updateNotificationSettings,
  sendTestNotification,
} from "@/lib/api";
import type {
  WorkspaceNotificationSettings,
  NotifyRiskLevel,
} from "@/types";
import PageHeader from "@/components/common/PageHeader";

// ── Inline banners ─────────────────────────────────────────────────────────────

function ErrorBanner({ message }: { message: string }) {
  return (
    <div
      role="alert"
      style={{
        background: "#2a1a1a",
        border: "1px solid #7a2a2a",
        borderRadius: "6px",
        padding: "10px 14px",
        color: "#f87171",
        fontSize: "13px",
        marginBottom: "16px",
      }}
    >
      {message}
    </div>
  );
}

function SuccessBanner({ message }: { message: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        background: "#1a2a1a",
        border: "1px solid #2a5a2a",
        borderRadius: "6px",
        padding: "10px 14px",
        color: "#4ade80",
        fontSize: "13px",
        marginBottom: "16px",
      }}
    >
      {message}
    </div>
  );
}

// ── Section card wrapper ───────────────────────────────────────────────────────

function SectionCard({
  title,
  accentColor,
  children,
}: {
  title: string;
  accentColor: string;
  children: React.ReactNode;
}) {
  return (
    <section
      style={{
        background: "#13151a",
        border: "1px solid #2a2d38",
        borderRadius: "8px",
        padding: "20px",
        marginBottom: "20px",
      }}
    >
      <h2
        style={{
          fontSize: "13px",
          fontWeight: 600,
          color: accentColor,
          margin: "0 0 16px",
          textTransform: "uppercase",
          letterSpacing: "0.04em",
        }}
      >
        {title}
      </h2>
      {children}
    </section>
  );
}

// ── Toggle ─────────────────────────────────────────────────────────────────────

function Toggle({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <label
      style={{
        display: "flex",
        alignItems: "center",
        gap: "10px",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1,
        userSelect: "none",
      }}
    >
      <div
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => !disabled && onChange(!checked)}
        style={{
          width: "36px",
          height: "20px",
          borderRadius: "10px",
          background: checked ? "#8b5cf6" : "#2a2d38",
          position: "relative",
          transition: "background 0.15s",
          flexShrink: 0,
        }}
      >
        <div
          style={{
            position: "absolute",
            top: "3px",
            left: checked ? "19px" : "3px",
            width: "14px",
            height: "14px",
            borderRadius: "50%",
            background: "#fff",
            transition: "left 0.15s",
          }}
        />
      </div>
      <span style={{ fontSize: "13px", color: "#c4c8d4" }}>{label}</span>
    </label>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function NotificationsSettingsPage() {
  const { getToken } = useAuth();
  const { selectedWorkspace } = useWorkspace();

  const [settings, setSettings] =
    useState<WorkspaceNotificationSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  // Editable field state — initialised from settings on load.
  const [slackEnabled, setSlackEnabled] = useState(false);
  const [slackUrl, setSlackUrl] = useState("");
  const [webhookEnabled, setWebhookEnabled] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState("");
  const [riskLevel, setRiskLevel] = useState<NotifyRiskLevel>("high_and_critical");

  // ── Load settings ──────────────────────────────────────────────────────────
  const loadSettings = useCallback(async () => {
    if (!selectedWorkspace) return;
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const data = await getNotificationSettings(selectedWorkspace.id, token);
      setSettings(data);
      setSlackEnabled(data.slack_enabled);
      setWebhookEnabled(data.webhook_enabled);
      setRiskLevel(data.notify_on_risk_level);
      // Don't pre-fill URL inputs — user must enter new URL to change.
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load settings.");
    } finally {
      setLoading(false);
    }
  }, [selectedWorkspace, getToken]);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  // ── Save ───────────────────────────────────────────────────────────────────
  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedWorkspace) return;
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const token = await getToken();
      const body: Parameters<typeof updateNotificationSettings>[1] = {
        notify_on_risk_level: riskLevel,
        slack_enabled: slackEnabled,
        webhook_enabled: webhookEnabled,
      };
      // Only send URL fields when the user typed something.
      if (slackUrl !== "") body.slack_webhook_url = slackUrl;
      if (webhookUrl !== "") body.webhook_url = webhookUrl;

      const updated = await updateNotificationSettings(
        selectedWorkspace.id,
        body,
        token,
      );
      setSettings(updated);
      setSlackEnabled(updated.slack_enabled);
      setWebhookEnabled(updated.webhook_enabled);
      setRiskLevel(updated.notify_on_risk_level);
      // Clear URL inputs after save (masked form is shown from settings).
      setSlackUrl("");
      setWebhookUrl("");
      setSuccess("Notification settings saved.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save settings.");
    } finally {
      setSaving(false);
    }
  }

  // ── Clear URL helper ───────────────────────────────────────────────────────
  async function handleClearUrl(channel: "slack" | "webhook") {
    if (!selectedWorkspace) return;
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const token = await getToken();
      const body =
        channel === "slack"
          ? { slack_webhook_url: "", slack_enabled: false }
          : { webhook_url: "", webhook_enabled: false };
      const updated = await updateNotificationSettings(
        selectedWorkspace.id,
        body,
        token,
      );
      setSettings(updated);
      setSlackEnabled(updated.slack_enabled);
      setWebhookEnabled(updated.webhook_enabled);
      if (channel === "slack") setSlackUrl("");
      else setWebhookUrl("");
      setSuccess(`${channel === "slack" ? "Slack" : "Webhook"} URL cleared.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to clear URL.");
    } finally {
      setSaving(false);
    }
  }

  // ── Test ───────────────────────────────────────────────────────────────────
  async function handleTest() {
    if (!selectedWorkspace) return;
    setTesting(true);
    setError(null);
    setSuccess(null);
    try {
      const token = await getToken();
      const result = await sendTestNotification(selectedWorkspace.id, token);
      if (result.slack_sent || result.webhook_sent) {
        const sent = [
          result.slack_sent ? "Slack" : null,
          result.webhook_sent ? "Webhook" : null,
        ]
          .filter(Boolean)
          .join(" and ");
        setSuccess(`Test sent via ${sent}.`);
      } else if (result.error) {
        setError(`Test notification failed: ${result.error}`);
      } else {
        setSuccess("No channels are currently enabled. Enable a channel and save first.");
      }
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to send test notification.",
      );
    } finally {
      setTesting(false);
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────
  if (!selectedWorkspace) {
    return (
      <>
        <PageHeader
          title="Notifications"
          description="Configure Slack and webhook alerts for configuration drift."
        />
        <div className="px-6">
          <p style={{ fontSize: "13px", color: "#565b6e" }}>
            No workspace selected.
          </p>
        </div>
      </>
    );
  }

  if (loading) {
    return (
      <>
        <PageHeader
          title="Notifications"
          description="Configure Slack and webhook alerts for configuration drift."
        />
        <div className="px-6">
          <p style={{ fontSize: "13px", color: "#565b6e" }}>Loading…</p>
        </div>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Notifications"
        description="Get alerted in Slack or via webhook when risky configuration changes are detected."
      />

      <form onSubmit={handleSave}>
        <div className="px-6 pb-8" style={{ maxWidth: "680px" }}>
          {error && <ErrorBanner message={error} />}
          {success && <SuccessBanner message={success} />}

          {/* ── Risk level filter ──────────────────────────────────────── */}
          <SectionCard title="Alert threshold" accentColor="#8b5cf6">
            <p
              style={{
                fontSize: "13px",
                color: "#8b90a0",
                margin: "0 0 12px",
                lineHeight: 1.6,
              }}
            >
              Choose which risk levels trigger a notification. This applies to
              both Slack and webhook channels.
            </p>
            <select
              value={riskLevel}
              onChange={(e) => setRiskLevel(e.target.value as NotifyRiskLevel)}
              aria-label="Notification risk threshold"
              style={{
                background: "#1a1d28",
                border: "1px solid #3a3d4a",
                borderRadius: "5px",
                padding: "7px 10px",
                fontSize: "13px",
                color: "#e2e5ef",
                fontFamily: "inherit",
                width: "100%",
                maxWidth: "320px",
                cursor: "pointer",
              }}
            >
              <option value="critical_only">Critical only</option>
              <option value="high_and_critical">High + Critical (recommended)</option>
              <option value="medium_and_above">Medium, High + Critical</option>
            </select>
          </SectionCard>

          {/* ── Slack ──────────────────────────────────────────────────── */}
          <SectionCard title="Slack" accentColor="#4a9eff">
            <div style={{ marginBottom: "14px" }}>
              <Toggle
                checked={slackEnabled}
                onChange={setSlackEnabled}
                label="Send Slack notifications"
                disabled={
                  !slackEnabled && !settings?.slack_webhook_url_masked && slackUrl === ""
                }
              />
            </div>

            {settings?.slack_webhook_url_masked && (
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  marginBottom: "12px",
                  background: "#1a1d28",
                  border: "1px solid #2a2d38",
                  borderRadius: "5px",
                  padding: "7px 12px",
                }}
              >
                <span style={{ fontSize: "12px", color: "#565b6e", flexShrink: 0 }}>
                  Current URL:
                </span>
                <span
                  style={{
                    fontSize: "12px",
                    color: "#8b90a0",
                    fontFamily: "var(--font-mono, monospace)",
                    flex: 1,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {settings.slack_webhook_url_masked}
                </span>
                <button
                  type="button"
                  onClick={() => handleClearUrl("slack")}
                  disabled={saving}
                  style={{
                    fontSize: "11px",
                    color: "#f87171",
                    background: "none",
                    border: "none",
                    cursor: saving ? "not-allowed" : "pointer",
                    padding: "0",
                    fontFamily: "inherit",
                    flexShrink: 0,
                  }}
                >
                  Clear
                </button>
              </div>
            )}

            <div style={{ marginBottom: "8px" }}>
              <label
                htmlFor="slack-url"
                style={{
                  display: "block",
                  fontSize: "12px",
                  color: "#565b6e",
                  marginBottom: "6px",
                }}
              >
                {settings?.slack_webhook_url_masked
                  ? "Replace webhook URL"
                  : "Slack incoming webhook URL"}
              </label>
              <input
                id="slack-url"
                type="url"
                value={slackUrl}
                onChange={(e) => setSlackUrl(e.target.value)}
                placeholder="https://hooks.slack.com/services/T.../B.../..."
                autoComplete="off"
                style={{
                  width: "100%",
                  background: "#1a1d28",
                  border: "1px solid #3a3d4a",
                  borderRadius: "5px",
                  padding: "7px 10px",
                  fontSize: "13px",
                  color: "#e2e5ef",
                  fontFamily: "inherit",
                  boxSizing: "border-box",
                }}
              />
              <p
                style={{
                  fontSize: "11px",
                  color: "#565b6e",
                  margin: "5px 0 0",
                  lineHeight: 1.5,
                }}
              >
                Create an incoming webhook in your Slack app and paste the URL.
                Must start with{" "}
                <code style={{ fontFamily: "monospace" }}>
                  https://hooks.slack.com/services/
                </code>
              </p>
            </div>
          </SectionCard>

          {/* ── Generic webhook ────────────────────────────────────────── */}
          <SectionCard title="Webhook" accentColor="#22c55e">
            <div style={{ marginBottom: "14px" }}>
              <Toggle
                checked={webhookEnabled}
                onChange={setWebhookEnabled}
                label="Send webhook notifications"
                disabled={
                  !webhookEnabled &&
                  !settings?.webhook_url_masked &&
                  webhookUrl === ""
                }
              />
            </div>

            {settings?.webhook_url_masked && (
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  marginBottom: "12px",
                  background: "#1a1d28",
                  border: "1px solid #2a2d38",
                  borderRadius: "5px",
                  padding: "7px 12px",
                }}
              >
                <span style={{ fontSize: "12px", color: "#565b6e", flexShrink: 0 }}>
                  Current URL:
                </span>
                <span
                  style={{
                    fontSize: "12px",
                    color: "#8b90a0",
                    fontFamily: "var(--font-mono, monospace)",
                    flex: 1,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {settings.webhook_url_masked}
                </span>
                <button
                  type="button"
                  onClick={() => handleClearUrl("webhook")}
                  disabled={saving}
                  style={{
                    fontSize: "11px",
                    color: "#f87171",
                    background: "none",
                    border: "none",
                    cursor: saving ? "not-allowed" : "pointer",
                    padding: "0",
                    fontFamily: "inherit",
                    flexShrink: 0,
                  }}
                >
                  Clear
                </button>
              </div>
            )}

            <div style={{ marginBottom: "8px" }}>
              <label
                htmlFor="webhook-url"
                style={{
                  display: "block",
                  fontSize: "12px",
                  color: "#565b6e",
                  marginBottom: "6px",
                }}
              >
                {settings?.webhook_url_masked
                  ? "Replace webhook URL"
                  : "Webhook URL"}
              </label>
              <input
                id="webhook-url"
                type="url"
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                placeholder="https://your-service.example.com/webhook"
                autoComplete="off"
                style={{
                  width: "100%",
                  background: "#1a1d28",
                  border: "1px solid #3a3d4a",
                  borderRadius: "5px",
                  padding: "7px 10px",
                  fontSize: "13px",
                  color: "#e2e5ef",
                  fontFamily: "inherit",
                  boxSizing: "border-box",
                }}
              />
              <p
                style={{
                  fontSize: "11px",
                  color: "#565b6e",
                  margin: "5px 0 0",
                  lineHeight: 1.5,
                }}
              >
                ConfigTrace will POST a JSON payload to this URL when qualifying
                changes are detected. Must be{" "}
                <code style={{ fontFamily: "monospace" }}>https://</code>.
                Private/local addresses are not allowed.
              </p>
            </div>

            <details
              style={{
                fontSize: "12px",
                color: "#565b6e",
                marginTop: "10px",
              }}
            >
              <summary
                style={{
                  cursor: "pointer",
                  color: "#8b90a0",
                  userSelect: "none",
                }}
              >
                View example payload
              </summary>
              <pre
                style={{
                  marginTop: "8px",
                  background: "#0e1018",
                  border: "1px solid #2a2d38",
                  borderRadius: "5px",
                  padding: "10px",
                  fontSize: "11px",
                  color: "#8b90a0",
                  overflowX: "auto",
                  lineHeight: 1.5,
                }}
              >
                {JSON.stringify(
                  {
                    event: "config_drift_alert",
                    workspace_id: "uuid",
                    integration_id: "uuid",
                    integration_name: "My AWS",
                    provider: "aws",
                    sync_run_id: "uuid",
                    change_count: 1,
                    highest_risk: "critical",
                    changes: [
                      {
                        id: "uuid",
                        risk_level: "critical",
                        change_type: "added",
                        record_identifier: "sg-abc123",
                        field_path: "inbound_rules[0]",
                        risk_reason: "Port 22 opened to 0.0.0.0/0",
                      },
                    ],
                    app_url: "https://app.configtrace.org",
                    timestamp: "2026-05-25T12:00:00Z",
                  },
                  null,
                  2,
                )}
              </pre>
            </details>
          </SectionCard>

          {/* ── Actions ────────────────────────────────────────────────── */}
          <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            <button
              type="submit"
              disabled={saving}
              style={{
                background: "#8b5cf6",
                color: "#fff",
                border: "none",
                borderRadius: "6px",
                padding: "8px 20px",
                fontSize: "13px",
                cursor: saving ? "not-allowed" : "pointer",
                opacity: saving ? 0.7 : 1,
                fontFamily: "inherit",
              }}
            >
              {saving ? "Saving…" : "Save settings"}
            </button>

            <button
              type="button"
              onClick={handleTest}
              disabled={testing || saving}
              style={{
                background: "none",
                color: "#8b90a0",
                border: "1px solid #2a2d38",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                cursor: testing || saving ? "not-allowed" : "pointer",
                opacity: testing ? 0.7 : 1,
                fontFamily: "inherit",
              }}
            >
              {testing ? "Sending test…" : "Send test notification"}
            </button>
          </div>

          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              marginTop: "12px",
              lineHeight: 1.5,
            }}
          >
            Notifications are sent in addition to email alerts. They use the same
            risk-level filter you set above. ConfigTrace monitors configuration
            metadata only — no customer data is included in notifications.
          </p>
        </div>
      </form>
    </>
  );
}
