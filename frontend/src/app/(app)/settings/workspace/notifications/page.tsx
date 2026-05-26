"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import {
  getNotificationSettings,
  updateNotificationSettings,
  sendTestNotification,
  getSlackInstallUrl,
  listSlackChannels,
  updateSlackChannel,
  sendSlackAppTest,
  disconnectSlackApp,
  getPushPublicKey,
  subscribePush,
  listPushSubscriptions,
  deletePushSubscription,
  testPushNotifications,
} from "@/lib/api";
import type {
  WorkspaceNotificationSettings,
  NotifyRiskLevel,
  SlackChannel,
  PushMinRiskLevel,
  PushSubscriptionResponse,
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
  badge,
  children,
}: {
  title: string;
  accentColor: string;
  badge?: string;
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
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          marginBottom: "16px",
        }}
      >
        <h2
          style={{
            fontSize: "13px",
            fontWeight: 600,
            color: accentColor,
            margin: 0,
            textTransform: "uppercase",
            letterSpacing: "0.04em",
          }}
        >
          {title}
        </h2>
        {badge && (
          <span
            style={{
              fontSize: "10px",
              fontWeight: 600,
              color: "#4ade80",
              background: "#1a3a1a",
              border: "1px solid #2a5a2a",
              borderRadius: "4px",
              padding: "1px 6px",
              textTransform: "uppercase",
              letterSpacing: "0.04em",
            }}
          >
            {badge}
          </span>
        )}
      </div>
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

// ── Slack App card ─────────────────────────────────────────────────────────────

function SlackAppCard({
  settings,
  workspaceId: _workspaceId,
  onUpdate,
}: {
  settings: WorkspaceNotificationSettings | null;
  workspaceId: string;
  onUpdate: (msg: string) => void;
}) {
  const { getToken } = useAuth();
  const { selectedWorkspace } = useWorkspace();
  const [installing, setInstalling] = useState(false);
  const [loadingChannels, setLoadingChannels] = useState(false);
  const [channels, setChannels] = useState<SlackChannel[]>([]);
  const [selectedChannel, setSelectedChannel] = useState<string>("");
  const [savingChannel, setSavingChannel] = useState(false);
  const [testing, setTesting] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isInstalled = settings?.slack_app_installed ?? false;
  const isEnabled = settings?.slack_app_enabled ?? false;
  const hasChannel = !!(settings?.slack_channel_id);

  // Check for install success/error from URL params (after OAuth redirect).
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const installStatus = params.get("slack_install");
    if (installStatus === "success") {
      onUpdate("Slack App installed successfully. Select a channel to activate notifications.");
      // Remove query param without re-render loop.
      const url = new URL(window.location.href);
      url.searchParams.delete("slack_install");
      window.history.replaceState({}, "", url.toString());
    } else if (installStatus === "error") {
      const reason = params.get("reason") ?? "unknown";
      setError(`Slack App installation failed (${reason}). Please try again.`);
      const url = new URL(window.location.href);
      url.searchParams.delete("slack_install");
      url.searchParams.delete("reason");
      window.history.replaceState({}, "", url.toString());
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  async function handleInstall() {
    if (!selectedWorkspace) return;
    setInstalling(true);
    setError(null);
    try {
      const token = await getToken();
      const { install_url } = await getSlackInstallUrl(selectedWorkspace.id, token);
      // Redirect to Slack's OAuth page in the same tab.
      window.location.href = install_url;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to get install URL.");
      setInstalling(false);
    }
  }

  async function handleLoadChannels() {
    if (!selectedWorkspace) return;
    setLoadingChannels(true);
    setError(null);
    try {
      const token = await getToken();
      const { channels: ch } = await listSlackChannels(selectedWorkspace.id, token);
      setChannels(ch);
      if (settings?.slack_channel_id) {
        setSelectedChannel(settings.slack_channel_id);
      } else if (ch.length > 0) {
        setSelectedChannel(ch[0].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load channels.");
    } finally {
      setLoadingChannels(false);
    }
  }

  async function handleSaveChannel() {
    if (!selectedWorkspace || !selectedChannel) return;
    setSavingChannel(true);
    setError(null);
    try {
      const token = await getToken();
      const ch = channels.find((c) => c.id === selectedChannel);
      await updateSlackChannel(
        selectedWorkspace.id,
        selectedChannel,
        ch?.name ?? "",
        token,
      );
      onUpdate("Slack channel saved. Alerts will be delivered to this channel.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save channel.");
    } finally {
      setSavingChannel(false);
    }
  }

  async function handleTest() {
    if (!selectedWorkspace) return;
    setTesting(true);
    setError(null);
    try {
      const token = await getToken();
      const result = await sendSlackAppTest(selectedWorkspace.id, token);
      if (result.slack_sent) {
        onUpdate("Test message sent successfully via Slack App.");
      } else {
        setError(result.error ?? "Test failed. Check channel permissions.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Test failed.");
    } finally {
      setTesting(false);
    }
  }

  async function handleDisconnect() {
    if (!selectedWorkspace) return;
    if (
      !window.confirm(
        "Disconnect the Slack App? Existing webhook configuration is unaffected.",
      )
    )
      return;
    setDisconnecting(true);
    setError(null);
    try {
      const token = await getToken();
      await disconnectSlackApp(selectedWorkspace.id, token);
      onUpdate("Slack App disconnected.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to disconnect.");
    } finally {
      setDisconnecting(false);
    }
  }

  return (
    <>
      {error && <ErrorBanner message={error} />}

      {!isInstalled ? (
        /* ── Not installed ── */
        <div>
          <p
            style={{
              fontSize: "13px",
              color: "#8b90a0",
              margin: "0 0 14px",
              lineHeight: 1.6,
            }}
          >
            Install the ConfigTrace Slack App to deliver alerts directly to any
            channel in your Slack workspace. The app requires{" "}
            <code style={{ fontFamily: "monospace", fontSize: "12px" }}>
              chat:write
            </code>{" "}
            and{" "}
            <code style={{ fontFamily: "monospace", fontSize: "12px" }}>
              channels:read
            </code>{" "}
            scopes.
          </p>
          <button
            type="button"
            onClick={handleInstall}
            disabled={installing}
            style={{
              background: "#4a9eff",
              color: "#fff",
              border: "none",
              borderRadius: "6px",
              padding: "8px 18px",
              fontSize: "13px",
              cursor: installing ? "not-allowed" : "pointer",
              opacity: installing ? 0.7 : 1,
              fontFamily: "inherit",
            }}
          >
            {installing ? "Redirecting to Slack…" : "Install ConfigTrace Slack App"}
          </button>
        </div>
      ) : (
        /* ── Installed ── */
        <div>
          {/* Installation info */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              marginBottom: "14px",
            }}
          >
            <span
              style={{
                width: "8px",
                height: "8px",
                borderRadius: "50%",
                background: hasChannel && isEnabled ? "#4ade80" : "#f59e0b",
                display: "inline-block",
                flexShrink: 0,
              }}
            />
            <span style={{ fontSize: "13px", color: "#c4c8d4" }}>
              Connected to{" "}
              <strong style={{ color: "#e2e5ef" }}>
                {settings?.slack_team_name ?? "Slack workspace"}
              </strong>
              {settings?.slack_channel_name && (
                <>
                  {" "}
                  · delivering to{" "}
                  <strong style={{ color: "#4ade80" }}>
                    #{settings.slack_channel_name}
                  </strong>
                </>
              )}
            </span>
          </div>

          {/* Last error */}
          {settings?.slack_app_last_error && (
            <div
              style={{
                background: "#2a1a1a",
                border: "1px solid #5a2a2a",
                borderRadius: "5px",
                padding: "8px 12px",
                fontSize: "12px",
                color: "#f87171",
                marginBottom: "14px",
              }}
            >
              Last error: {settings.slack_app_last_error}
            </div>
          )}

          {/* Channel selection */}
          <div style={{ marginBottom: "14px" }}>
            {channels.length === 0 ? (
              <button
                type="button"
                onClick={handleLoadChannels}
                disabled={loadingChannels}
                style={{
                  background: "none",
                  color: "#4a9eff",
                  border: "1px solid #2a4a7a",
                  borderRadius: "5px",
                  padding: "6px 12px",
                  fontSize: "12px",
                  cursor: loadingChannels ? "not-allowed" : "pointer",
                  fontFamily: "inherit",
                }}
              >
                {loadingChannels ? "Loading channels…" : "Select channel"}
              </button>
            ) : (
              <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                <select
                  value={selectedChannel}
                  onChange={(e) => setSelectedChannel(e.target.value)}
                  aria-label="Select Slack channel"
                  style={{
                    background: "#1a1d28",
                    border: "1px solid #3a3d4a",
                    borderRadius: "5px",
                    padding: "6px 10px",
                    fontSize: "13px",
                    color: "#e2e5ef",
                    fontFamily: "inherit",
                    flex: 1,
                    maxWidth: "280px",
                    cursor: "pointer",
                  }}
                >
                  {channels.map((ch) => (
                    <option key={ch.id} value={ch.id}>
                      #{ch.name}
                      {ch.is_private ? " 🔒" : ""}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={handleSaveChannel}
                  disabled={savingChannel || !selectedChannel}
                  style={{
                    background: "#8b5cf6",
                    color: "#fff",
                    border: "none",
                    borderRadius: "5px",
                    padding: "6px 14px",
                    fontSize: "12px",
                    cursor: savingChannel ? "not-allowed" : "pointer",
                    opacity: savingChannel ? 0.7 : 1,
                    fontFamily: "inherit",
                  }}
                >
                  {savingChannel ? "Saving…" : "Save channel"}
                </button>
              </div>
            )}
          </div>

          {/* Actions */}
          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
            {hasChannel && (
              <button
                type="button"
                onClick={handleTest}
                disabled={testing}
                style={{
                  background: "none",
                  color: "#8b90a0",
                  border: "1px solid #2a2d38",
                  borderRadius: "5px",
                  padding: "6px 12px",
                  fontSize: "12px",
                  cursor: testing ? "not-allowed" : "pointer",
                  opacity: testing ? 0.7 : 1,
                  fontFamily: "inherit",
                }}
              >
                {testing ? "Sending test…" : "Send test message"}
              </button>
            )}
            <button
              type="button"
              onClick={handleDisconnect}
              disabled={disconnecting}
              style={{
                background: "none",
                color: "#f87171",
                border: "none",
                padding: "6px 0",
                fontSize: "12px",
                cursor: disconnecting ? "not-allowed" : "pointer",
                fontFamily: "inherit",
              }}
            >
              {disconnecting ? "Disconnecting…" : "Disconnect"}
            </button>
          </div>
        </div>
      )}
    </>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Convert a URL-safe base64 string (VAPID public key) to a Uint8Array that
 * the Web Push API expects for applicationServerKey.
 */
function urlBase64ToUint8Array(base64String: string): Uint8Array<ArrayBuffer> {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding)
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const rawData = window.atob(base64);
  const buffer = new ArrayBuffer(rawData.length);
  const outputArray = new Uint8Array(buffer);
  for (let i = 0; i < rawData.length; i++) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

/** Detect the current browser name from the user-agent string. */
function detectBrowserName(): string {
  const ua = navigator.userAgent;
  if (ua.includes("Firefox")) return "Firefox";
  if (ua.includes("Edg/")) return "Edge";
  if (ua.includes("OPR/") || ua.includes("Opera")) return "Opera";
  if (ua.includes("Chrome")) return "Chrome";
  if (ua.includes("Safari")) return "Safari";
  return "Browser";
}

// ── Browser Push Card ──────────────────────────────────────────────────────────

type PushPermission = "unsupported" | "default" | "denied" | "granted";

function BrowserPushCard({
  workspaceId,
  isAdmin,
}: {
  workspaceId: string;
  isAdmin?: boolean;
}) {
  const { getToken } = useAuth();

  // Browser push support state.
  const [permState, setPermState] = useState<PushPermission>("default");
  const [pushSupported, setPushSupported] = useState(true);

  // Backend subscription list.
  const [subscriptions, setSubscriptions] = useState<PushSubscriptionResponse[]>([]);
  const [loadingSubs, setLoadingSubs] = useState(false);

  // Current device's subscription (matched by checking the SW pushManager).
  const [currentSubId, setCurrentSubId] = useState<string | null>(null);

  // UI state.
  const [subscribing, setSubscribing] = useState(false);
  const [unsubscribing, setUnsubscribing] = useState(false);
  const [testing, setTesting] = useState(false);
  const [minRiskLevel, setMinRiskLevel] = useState<PushMinRiskLevel>("high");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Prevent double-init in strict mode.
  const initialized = useRef(false);

  // ── Check browser support + permission on mount ──────────────────────────
  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;

    // Check for required browser APIs.
    if (
      typeof window === "undefined" ||
      !("serviceWorker" in navigator) ||
      !("PushManager" in window) ||
      !("Notification" in window)
    ) {
      setPushSupported(false);
      setPermState("unsupported");
      return;
    }

    setPermState(Notification.permission as PushPermission);
    if (Notification.permission === "granted") {
      void loadSubscriptions();
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Load workspace subscriptions ─────────────────────────────────────────
  async function loadSubscriptions() {
    setLoadingSubs(true);
    try {
      const token = await getToken();
      const { subscriptions: subs } = await listPushSubscriptions(workspaceId, token);
      setSubscriptions(subs);

      // Check if this device has an existing SW subscription and match it.
      if ("serviceWorker" in navigator) {
        try {
          const reg = await navigator.serviceWorker.ready;
          const existing = await reg.pushManager.getSubscription();
          if (existing) {
            // Find a matching enabled subscription in the backend list.
            // We can't match by endpoint directly (it's encrypted server-side),
            // so we identify this device's subscription by it being the most
            // recently created enabled one (best-effort heuristic).
            const enabled = subs.filter((s) => s.enabled);
            if (enabled.length > 0) {
              setCurrentSubId(enabled[enabled.length - 1].id);
            }
          }
        } catch {
          // SW not ready yet — that's fine, user can still subscribe.
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load subscriptions.");
    } finally {
      setLoadingSubs(false);
    }
  }

  // ── Subscribe this device ─────────────────────────────────────────────────
  async function handleSubscribe() {
    setSubscribing(true);
    setError(null);
    setSuccess(null);
    try {
      // 1. Request notification permission.
      const permission = await Notification.requestPermission();
      setPermState(permission as PushPermission);
      if (permission !== "granted") {
        setError(
          permission === "denied"
            ? "Notifications blocked. Enable them in your browser settings, then try again."
            : "Notification permission not granted.",
        );
        return;
      }

      // 2. Get VAPID public key from backend.
      const token = await getToken();
      const { vapid_public_key, configured } = await getPushPublicKey(workspaceId, token);
      if (!configured || !vapid_public_key) {
        setError("Push notifications are not configured on this server. Contact your administrator.");
        return;
      }

      // 3. Wait for service worker registration.
      const reg = await navigator.serviceWorker.ready;

      // 4. Subscribe via the Push API.
      const sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(vapid_public_key),
      });

      // 5. Extract keys.
      const rawP256dh = sub.getKey("p256dh");
      const rawAuth = sub.getKey("auth");
      if (!rawP256dh || !rawAuth) {
        throw new Error("Browser returned incomplete push subscription keys.");
      }
      const p256dh = btoa(String.fromCharCode(...new Uint8Array(rawP256dh)));
      const auth = btoa(String.fromCharCode(...new Uint8Array(rawAuth)));

      // 6. Register with backend (nested subscription object per API schema).
      const browserName = detectBrowserName();
      const newSub = await subscribePush(
        workspaceId,
        {
          subscription: {
            endpoint: sub.endpoint,
            keys: { p256dh, auth },
          },
          device_label: `${browserName} on ${navigator.platform || "device"}`,
          min_risk_level: minRiskLevel,
        },
        token,
      );

      setCurrentSubId(newSub.id);
      setSubscriptions((prev) => [...prev, newSub]);
      setSuccess("Browser notifications enabled for this device.");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to enable push notifications.",
      );
    } finally {
      setSubscribing(false);
    }
  }

  // ── Unsubscribe this device ───────────────────────────────────────────────
  async function handleUnsubscribe() {
    if (!currentSubId) return;
    setUnsubscribing(true);
    setError(null);
    setSuccess(null);
    try {
      // Remove browser subscription.
      if ("serviceWorker" in navigator) {
        const reg = await navigator.serviceWorker.ready;
        const existing = await reg.pushManager.getSubscription();
        if (existing) {
          await existing.unsubscribe();
        }
      }
      // Remove from backend.
      const token = await getToken();
      await deletePushSubscription(workspaceId, currentSubId, token);
      setSubscriptions((prev) => prev.filter((s) => s.id !== currentSubId));
      setCurrentSubId(null);
      setPermState("default");
      setSuccess("Browser notifications disabled for this device.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to disable push notifications.");
    } finally {
      setUnsubscribing(false);
    }
  }

  // ── Remove another device's subscription ─────────────────────────────────
  async function handleRemoveSub(subId: string) {
    try {
      const token = await getToken();
      await deletePushSubscription(workspaceId, subId, token);
      setSubscriptions((prev) => prev.filter((s) => s.id !== subId));
      if (currentSubId === subId) {
        setCurrentSubId(null);
        setPermState("default");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove subscription.");
    }
  }

  // ── Send test push ────────────────────────────────────────────────────────
  async function handleTest() {
    setTesting(true);
    setError(null);
    setSuccess(null);
    try {
      const token = await getToken();
      const result = await testPushNotifications(workspaceId, token);
      if (result.error) {
        setError(`Test failed: ${result.error}`);
      } else {
        setSuccess(
          `Test push sent to ${result.sent} of ${result.total_subscriptions} device(s).`,
        );
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to send test push.");
    } finally {
      setTesting(false);
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

  const rowStyle: React.CSSProperties = {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "8px",
    marginBottom: "10px",
  };

  const smallBtnStyle: React.CSSProperties = {
    background: "none",
    color: "#f87171",
    border: "none",
    padding: "2px 0",
    fontSize: "11px",
    cursor: "pointer",
    fontFamily: "inherit",
  };

  return (
    <>
      {error && <ErrorBanner message={error} />}
      {success && (
        <div
          role="status"
          aria-live="polite"
          style={{
            background: "#1a2a1a",
            border: "1px solid #2a5a2a",
            borderRadius: "6px",
            padding: "8px 12px",
            color: "#4ade80",
            fontSize: "12px",
            marginBottom: "12px",
          }}
        >
          {success}
        </div>
      )}

      {/* ── Unsupported ───────────────────────────────────────────────── */}
      {!pushSupported && (
        <p style={{ fontSize: "13px", color: "#565b6e", margin: 0 }}>
          Your browser does not support Web Push notifications. Try Chrome,
          Edge, or Firefox on a desktop device.
        </p>
      )}

      {/* ── Denied ────────────────────────────────────────────────────── */}
      {pushSupported && permState === "denied" && (
        <div>
          <p style={{ fontSize: "13px", color: "#f87171", margin: "0 0 8px" }}>
            Notifications are blocked in your browser.
          </p>
          <p style={{ fontSize: "12px", color: "#8b90a0", margin: 0, lineHeight: 1.6 }}>
            To enable them, click the lock icon in your browser&apos;s address
            bar → <strong>Notifications</strong> → <strong>Allow</strong>, then
            reload this page.
          </p>
        </div>
      )}

      {/* ── Not yet subscribed ────────────────────────────────────────── */}
      {pushSupported && permState !== "denied" && !currentSubId && (
        <div>
          <p style={{ fontSize: "13px", color: "#8b90a0", margin: "0 0 14px", lineHeight: 1.6 }}>
            Receive real-time alerts in this browser when high or critical
            configuration changes are detected. No extra app needed.
          </p>

          {/* Risk level selector */}
          <div style={{ marginBottom: "14px" }}>
            <label
              htmlFor="push-min-risk"
              style={{ display: "block", fontSize: "12px", color: "#565b6e", marginBottom: "5px" }}
            >
              Minimum risk level for this device
            </label>
            <select
              id="push-min-risk"
              value={minRiskLevel}
              onChange={(e) => setMinRiskLevel(e.target.value as PushMinRiskLevel)}
              style={{
                background: "#1a1d28",
                border: "1px solid #3a3d4a",
                borderRadius: "5px",
                padding: "6px 10px",
                fontSize: "13px",
                color: "#e2e5ef",
                fontFamily: "inherit",
                cursor: "pointer",
              }}
            >
              <option value="high">High + Critical (recommended)</option>
              <option value="critical_only">Critical only</option>
            </select>
          </div>

          <button
            type="button"
            onClick={handleSubscribe}
            disabled={subscribing}
            style={{
              background: "#8b5cf6",
              color: "#fff",
              border: "none",
              borderRadius: "6px",
              padding: "8px 18px",
              fontSize: "13px",
              cursor: subscribing ? "not-allowed" : "pointer",
              opacity: subscribing ? 0.7 : 1,
              fontFamily: "inherit",
            }}
          >
            {subscribing ? "Enabling…" : "Enable browser notifications"}
          </button>
        </div>
      )}

      {/* ── Subscribed ────────────────────────────────────────────────── */}
      {pushSupported && currentSubId && (
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px" }}>
            <span
              style={{
                width: "8px",
                height: "8px",
                borderRadius: "50%",
                background: "#4ade80",
                display: "inline-block",
                flexShrink: 0,
              }}
            />
            <span style={{ fontSize: "13px", color: "#c4c8d4" }}>
              Browser notifications enabled for this device.
            </span>
          </div>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            {isAdmin && (
              <button
                type="button"
                onClick={handleTest}
                disabled={testing}
                style={{
                  background: "none",
                  color: "#8b90a0",
                  border: "1px solid #2a2d38",
                  borderRadius: "5px",
                  padding: "6px 12px",
                  fontSize: "12px",
                  cursor: testing ? "not-allowed" : "pointer",
                  opacity: testing ? 0.7 : 1,
                  fontFamily: "inherit",
                }}
              >
                {testing ? "Sending test…" : "Send test push"}
              </button>
            )}
            <button
              type="button"
              onClick={handleUnsubscribe}
              disabled={unsubscribing}
              style={{
                background: "none",
                color: "#f87171",
                border: "none",
                padding: "6px 0",
                fontSize: "12px",
                cursor: unsubscribing ? "not-allowed" : "pointer",
                fontFamily: "inherit",
              }}
            >
              {unsubscribing ? "Disabling…" : "Disable for this device"}
            </button>
          </div>
        </div>
      )}

      {/* ── Other devices list ────────────────────────────────────────── */}
      {pushSupported && subscriptions.length > 0 && (
        <div style={{ marginTop: "18px" }}>
          <p
            style={{
              fontSize: "11px",
              fontWeight: 600,
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.04em",
              marginBottom: "8px",
            }}
          >
            Subscribed devices ({subscriptions.length})
          </p>
          {loadingSubs ? (
            <p style={{ fontSize: "12px", color: "#565b6e" }}>Loading…</p>
          ) : (
            <div>
              {subscriptions.map((sub) => (
                <div key={sub.id} style={rowStyle}>
                  <div style={{ display: "flex", alignItems: "center", gap: "7px", minWidth: 0 }}>
                    <span
                      style={{
                        width: "6px",
                        height: "6px",
                        borderRadius: "50%",
                        background: sub.enabled ? "#4ade80" : "#565b6e",
                        flexShrink: 0,
                        display: "inline-block",
                      }}
                    />
                    <span
                      style={{
                        fontSize: "12px",
                        color: sub.id === currentSubId ? "#c4c8d4" : "#8b90a0",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {sub.device_label ?? sub.browser_name ?? "Unknown device"}
                      {sub.id === currentSubId && (
                        <span style={{ color: "#4ade80", marginLeft: "5px" }}>(this device)</span>
                      )}
                      {!sub.enabled && (
                        <span style={{ color: "#565b6e", marginLeft: "5px" }}>(expired)</span>
                      )}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleRemoveSub(sub.id)}
                    style={smallBtnStyle}
                    title="Remove this subscription"
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </>
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

  // ── Test (legacy channels) ─────────────────────────────────────────────────
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

  // ── Slack App update callback ──────────────────────────────────────────────
  async function handleSlackAppUpdate(msg: string) {
    setSuccess(msg);
    // Reload settings to pick up the new Slack App status.
    await loadSettings();
  }

  // ── Derive admin status from workspace role ────────────────────────────────
  // The notifications page is accessible to all members, but the push test
  // button is admin-only.  We pass a best-effort flag here; the backend
  // enforces authorization on the test endpoint regardless.
  const isAdmin = true; // Backend enforces role; frontend shows/hides test btn only.

  // ── Render ─────────────────────────────────────────────────────────────────
  if (!selectedWorkspace) {
    return (
      <>
        <PageHeader
          title="Notifications"
          description="Email alerts are sent automatically for high and critical changes. Configure Slack and webhook channels here as additional delivery options."
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
          description="Email alerts are sent automatically for high and critical changes. Configure Slack and webhook channels here as additional delivery options."
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
        description="Email alerts are sent automatically for high and critical changes. Configure Slack and webhook channels here as additional delivery options."
      />

      <div className="px-6 pb-8" style={{ maxWidth: "680px" }}>
        {error && <ErrorBanner message={error} />}
        {success && <SuccessBanner message={success} />}

        {/* ── Email (always-on) ──────────────────────────────────────── */}
        <SectionCard title="Email" accentColor="#f59e0b">
          <p
            style={{
              fontSize: "13px",
              color: "#8b90a0",
              margin: 0,
              lineHeight: 1.6,
            }}
          >
            Email alerts are sent automatically to all workspace members for
            high and critical changes. No configuration needed.
          </p>
        </SectionCard>

        {/* ── Slack App (recommended) ───────────────────────────────── */}
        <SectionCard title="Slack App" accentColor="#4a9eff" badge="Recommended">
          <SlackAppCard
            settings={settings}
            workspaceId={selectedWorkspace.id}
            onUpdate={handleSlackAppUpdate}
          />
        </SectionCard>

        {/* ── Browser / Desktop Push (M58.7) ───────────────────────── */}
        <SectionCard title="Browser / Desktop Notifications" accentColor="#a78bfa">
          <BrowserPushCard
            workspaceId={selectedWorkspace.id}
            isAdmin={isAdmin}
          />
        </SectionCard>

        <form onSubmit={handleSave}>
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
              Choose which risk levels trigger a notification. Applies to both
              Slack and webhook channels.
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

          {/* ── Slack incoming webhook (fallback) ─────────────────────── */}
          <SectionCard title="Slack — Incoming Webhook" accentColor="#6b7280">
            <p
              style={{
                fontSize: "12px",
                color: "#565b6e",
                margin: "0 0 14px",
                lineHeight: 1.5,
              }}
            >
              Fallback option. Use this only if the Slack App above is not
              suitable. The Slack App is recommended for better reliability.
            </p>
            <div style={{ marginBottom: "14px" }}>
              <Toggle
                checked={slackEnabled}
                onChange={setSlackEnabled}
                label="Send Slack notifications via incoming webhook"
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
                    timestamp: "2026-05-26T12:00:00Z",
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
            Email alerts are always sent to workspace members for high and critical
            changes — regardless of Slack or webhook settings. Slack and webhook
            channels use the risk-level filter above. ConfigTrace monitors
            configuration metadata only — no customer data is included in any
            notification.
          </p>
        </form>
      </div>
    </>
  );
}
