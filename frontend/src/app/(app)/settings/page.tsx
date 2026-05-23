"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import type {
  AlertRiskThreshold,
  ProviderFilter,
  TimelineRange,
  UserSettings,
  UserSettingsUpdateRequest,
} from "@/types";
import { getSettings, patchSettings } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";

// ── Design tokens ─────────────────────────────────────────────────────────────

const CARD: React.CSSProperties = {
  background: "#13151a",
  border: "1px solid #2a2d38",
  borderRadius: "6px",
  padding: "22px 24px",
  marginBottom: "16px",
};

const SECTION_TITLE: React.CSSProperties = {
  fontSize: "13px",
  fontWeight: 600,
  color: "#e8eaf0",
  marginBottom: "4px",
};

const SECTION_DESC: React.CSSProperties = {
  fontSize: "12px",
  color: "#565b6e",
  marginBottom: "20px",
  lineHeight: 1.6,
};

const ROW: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: "24px",
  paddingTop: "12px",
  paddingBottom: "12px",
  borderTop: "1px solid #1e2030",
};

const FIELD_LABEL: React.CSSProperties = {
  fontSize: "13px",
  color: "#c4c8d4",
  fontWeight: 500,
  marginBottom: "2px",
};

const FIELD_HINT: React.CSSProperties = {
  fontSize: "11px",
  color: "#565b6e",
  lineHeight: 1.6,
};

// ── Helper components ─────────────────────────────────────────────────────────

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <p
      style={{
        fontSize: "10px",
        color: "#565b6e",
        textTransform: "uppercase" as const,
        letterSpacing: "0.08em",
        fontWeight: 600,
        margin: "0 0 10px",
      }}
    >
      {children}
    </p>
  );
}

function FieldLeft({
  label,
  hint,
}: {
  label: string;
  hint?: string;
}) {
  return (
    <div style={{ flex: 1, minWidth: 0 }}>
      <p style={FIELD_LABEL}>{label}</p>
      {hint && <p style={FIELD_HINT}>{hint}</p>}
    </div>
  );
}

function Select<T extends string | number>({
  value,
  onChange,
  options,
  disabled,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: string }[];
  disabled?: boolean;
}) {
  return (
    <select
      value={String(value)}
      onChange={(e) => {
        const raw = e.target.value;
        // Infer int vs string by original value type
        const cast = (typeof value === "number" ? Number(raw) : raw) as T;
        onChange(cast);
      }}
      disabled={disabled}
      style={{
        background: "#1a1d26",
        border: "1px solid #2a2d38",
        borderRadius: "5px",
        color: disabled ? "#565b6e" : "#e8eaf0",
        fontSize: "12px",
        padding: "5px 10px",
        cursor: disabled ? "not-allowed" : "pointer",
        fontFamily: "inherit",
        flexShrink: 0,
        minWidth: "180px",
      }}
    >
      {options.map((o) => (
        <option key={String(o.value)} value={String(o.value)}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

function Toggle({
  checked,
  onChange,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      onClick={() => !disabled && onChange(!checked)}
      disabled={disabled}
      style={{
        position: "relative",
        width: "36px",
        height: "20px",
        background: checked ? "#4f80f7" : "#2a2d38",
        border: "none",
        borderRadius: "10px",
        cursor: disabled ? "not-allowed" : "pointer",
        padding: 0,
        transition: "background 0.2s",
        flexShrink: 0,
      }}
    >
      <span
        style={{
          position: "absolute",
          top: "3px",
          left: checked ? "19px" : "3px",
          width: "14px",
          height: "14px",
          borderRadius: "50%",
          background: "#ffffff",
          transition: "left 0.2s",
        }}
      />
    </button>
  );
}

function ReadOnlyRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ ...ROW, alignItems: "flex-start", gap: "16px" }}>
      <FieldLeft label={label} />
      <span
        style={{
          fontSize: "12px",
          color: "#8b90a0",
          textAlign: "right",
          flexShrink: 0,
          maxWidth: "260px",
          lineHeight: 1.6,
        }}
      >
        {value}
      </span>
    </div>
  );
}

function SaveBar({
  dirty,
  saving,
  savedAt,
  onSave,
  onDiscard,
}: {
  dirty: boolean;
  saving: boolean;
  savedAt: Date | null;
  onSave: () => void;
  onDiscard: () => void;
}) {
  if (!dirty && !saving && !savedAt) return null;

  return (
    <div
      style={{
        position: "sticky",
        bottom: "16px",
        zIndex: 10,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "12px",
        background: "#1a1d26",
        border: "1px solid #2a2d38",
        borderRadius: "8px",
        padding: "10px 18px",
        boxShadow: "0 4px 24px rgba(0,0,0,0.4)",
      }}
    >
      <span style={{ fontSize: "12px", color: "#8b90a0" }}>
        {saving
          ? "Saving…"
          : savedAt && !dirty
          ? `Saved ${savedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
          : "You have unsaved changes"}
      </span>
      <div style={{ display: "flex", gap: "8px" }}>
        {dirty && (
          <button
            onClick={onDiscard}
            disabled={saving}
            style={{
              background: "transparent",
              border: "1px solid #2a2d38",
              color: "#8b90a0",
              borderRadius: "5px",
              padding: "5px 14px",
              fontSize: "12px",
              cursor: "pointer",
              fontFamily: "inherit",
            }}
          >
            Discard
          </button>
        )}
        {dirty && (
          <button
            onClick={onSave}
            disabled={saving}
            style={{
              background: "#4f80f7",
              border: "none",
              color: "#ffffff",
              borderRadius: "5px",
              padding: "5px 18px",
              fontSize: "12px",
              fontWeight: 500,
              cursor: saving ? "not-allowed" : "pointer",
              fontFamily: "inherit",
              opacity: saving ? 0.7 : 1,
            }}
          >
            {saving ? "Saving…" : "Save changes"}
          </button>
        )}
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const { getToken, isLoaded } = useAuth();
  const [settings, setSettings] = useState<UserSettings | null>(null);
  const [pending, setPending] = useState<UserSettingsUpdateRequest>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [savedAt, setSavedAt] = useState<Date | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Track the "base" settings separately so discard works correctly
  const baseSettings = useRef<UserSettings | null>(null);

  const fetchSettings = useCallback(async () => {
    if (!isLoaded) return;
    try {
      const token = await getToken();
      const data = await getSettings(token);
      setSettings(data);
      baseSettings.current = data;
      setPending({});
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load settings.");
    } finally {
      setLoading(false);
    }
  }, [isLoaded, getToken]);

  useEffect(() => {
    if (isLoaded) void fetchSettings();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLoaded]);

  // Merged view: base settings overlaid with pending changes
  const current: UserSettings | null = settings
    ? { ...settings, ...pending }
    : null;

  const dirty = Object.keys(pending).length > 0;

  function setPendingField<K extends keyof UserSettingsUpdateRequest>(
    key: K,
    value: UserSettingsUpdateRequest[K],
  ) {
    setPending((prev) => ({ ...prev, [key]: value }));
    setSaveError(null);
  }

  function discard() {
    setPending({});
    setSaveError(null);
  }

  async function save() {
    if (!dirty) return;
    setSaving(true);
    setSaveError(null);
    try {
      const token = await getToken();
      const updated = await patchSettings(pending, token);
      setSettings(updated);
      baseSettings.current = updated;
      setPending({});
      setSavedAt(new Date());
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : "Failed to save settings.");
    } finally {
      setSaving(false);
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <>
      <PageHeader
        title="Settings"
        description="Alert preferences, sync defaults, and account configuration."
      />

      <div className="px-6 py-6" style={{ maxWidth: "720px" }}>
        {loading && <LoadingState />}
        {!loading && error && <ErrorState message={error} />}

        {!loading && !error && current && (
          <>
            {/* ── Alert Policy ─────────────────────────────────────────── */}
            <SectionHeading>Alert Policy</SectionHeading>
            <div style={CARD}>
              <p style={SECTION_TITLE}>Change alerts</p>
              <p style={SECTION_DESC}>
                Control which risk levels trigger email notifications. Applies to all
                integrations. Emails go to your Clerk account address.
              </p>

              {/* Risk threshold */}
              <div style={{ ...ROW, borderTop: "none", paddingTop: 0 }}>
                <FieldLeft
                  label="Alert threshold"
                  hint="Send email alerts for changes at or above this risk level."
                />
                <Select<AlertRiskThreshold>
                  value={current.alert_risk_threshold}
                  onChange={(v) => setPendingField("alert_risk_threshold", v)}
                  options={[
                    { value: "critical_only",      label: "Critical only" },
                    { value: "high_and_critical",  label: "High and critical (default)" },
                    { value: "medium_and_above",   label: "Medium, high, and critical" },
                  ]}
                />
              </div>
            </div>

            {/* Sync failure alerts */}
            <div style={CARD}>
              <p style={SECTION_TITLE}>Sync failure alerts</p>
              <p style={SECTION_DESC}>
                Email you when an integration has repeated scheduled sync failures.
                Manual sync failures are never counted.
              </p>

              {/* Enable toggle */}
              <div style={{ ...ROW, borderTop: "none", paddingTop: 0 }}>
                <FieldLeft
                  label="Enable sync failure alerts"
                  hint="When disabled, no failure emails are sent regardless of other settings."
                />
                <Toggle
                  checked={current.sync_failure_alerts_enabled}
                  onChange={(v) => setPendingField("sync_failure_alerts_enabled", v)}
                />
              </div>

              {/* Threshold */}
              <div style={ROW}>
                <FieldLeft
                  label="Failure threshold"
                  hint="Alert after this many consecutive scheduled failures."
                />
                <Select<2 | 3 | 5>
                  value={current.sync_failure_threshold}
                  onChange={(v) => setPendingField("sync_failure_threshold", v as 2 | 3 | 5)}
                  disabled={!current.sync_failure_alerts_enabled}
                  options={[
                    { value: 2, label: "2 consecutive failures" },
                    { value: 3, label: "3 consecutive failures (default)" },
                    { value: 5, label: "5 consecutive failures" },
                  ]}
                />
              </div>

              {/* Cooldown */}
              <div style={ROW}>
                <FieldLeft
                  label="Alert cooldown"
                  hint="Minimum time between failure alert emails for the same integration."
                />
                <Select<6 | 12 | 24>
                  value={current.sync_failure_cooldown_hours}
                  onChange={(v) =>
                    setPendingField("sync_failure_cooldown_hours", v as 6 | 12 | 24)
                  }
                  disabled={!current.sync_failure_alerts_enabled}
                  options={[
                    { value: 6,  label: "6 hours" },
                    { value: 12, label: "12 hours" },
                    { value: 24, label: "24 hours (default)" },
                  ]}
                />
              </div>
            </div>

            {/* ── Sync Defaults ─────────────────────────────────────────── */}
            <SectionHeading>Sync Defaults</SectionHeading>
            <div style={CARD}>
              <p style={SECTION_TITLE}>New integration defaults</p>
              <p style={SECTION_DESC}>
                These settings apply to newly created integrations. They do not retroactively
                change existing integrations.
              </p>

              {/* Scheduled sync enabled */}
              <div style={{ ...ROW, borderTop: "none", paddingTop: 0 }}>
                <FieldLeft
                  label="Scheduled sync on by default"
                  hint="New integrations will have scheduled syncs enabled automatically."
                />
                <Toggle
                  checked={current.default_sync_enabled}
                  onChange={(v) => setPendingField("default_sync_enabled", v)}
                />
              </div>

              {/* Sync interval */}
              <div style={ROW}>
                <FieldLeft
                  label="Default sync interval"
                  hint="Polling frequency for new integrations."
                />
                <Select<5 | 10 | 15 | 30 | 60>
                  value={current.default_sync_interval_minutes}
                  onChange={(v) =>
                    setPendingField(
                      "default_sync_interval_minutes",
                      v as 5 | 10 | 15 | 30 | 60,
                    )
                  }
                  disabled={!current.default_sync_enabled}
                  options={[
                    { value: 5,  label: "Every 5 minutes" },
                    { value: 10, label: "Every 10 minutes" },
                    { value: 15, label: "Every 15 minutes" },
                    { value: 30, label: "Every 30 minutes" },
                    { value: 60, label: "Every 60 minutes (default)" },
                  ]}
                />
              </div>

              {/* Change alerts */}
              <div style={ROW}>
                <FieldLeft
                  label="Change alerts on by default"
                  hint="Saved for when per-integration alert controls are added. Change emails are currently always sent for changes at or above your alert threshold."
                />
                <Toggle
                  checked={current.default_change_alerts_enabled}
                  onChange={(v) => setPendingField("default_change_alerts_enabled", v)}
                />
              </div>
            </div>

            {/* ── UI Preferences ─────────────────────────────────────────── */}
            <SectionHeading>UI Preferences</SectionHeading>
            <div style={CARD}>
              <p style={SECTION_TITLE}>Timeline defaults</p>
              <p style={SECTION_DESC}>
                Default filter state on the Timeline page. You can always change filters per
                session without saving.
              </p>

              {/* Default timeline range */}
              <div style={{ ...ROW, borderTop: "none", paddingTop: 0 }}>
                <FieldLeft
                  label="Default time range"
                  hint="Applied when you open the Timeline with no active URL filters. URL parameters always take precedence."
                />
                <Select<TimelineRange>
                  value={current.default_timeline_range}
                  onChange={(v) => setPendingField("default_timeline_range", v)}
                  options={[
                    { value: "24h", label: "Last 24 hours" },
                    { value: "7d",  label: "Last 7 days (default)" },
                    { value: "30d", label: "Last 30 days" },
                    { value: "all", label: "All time" },
                  ]}
                />
              </div>

              {/* Default provider filter */}
              <div style={ROW}>
                <FieldLeft
                  label="Default provider filter"
                  hint="Applied when you open the Timeline with no active URL filters. URL parameters always take precedence."
                />
                <Select<ProviderFilter>
                  value={current.default_provider_filter}
                  onChange={(v) => setPendingField("default_provider_filter", v)}
                  options={[
                    { value: "all",        label: "All providers (default)" },
                    { value: "cloudflare", label: "Cloudflare" },
                    { value: "github",     label: "GitHub" },
                    { value: "vercel",     label: "Vercel" },
                    { value: "stripe",     label: "Stripe" },
                  ]}
                />
              </div>
            </div>

            {/* ── Risk Policy Overview ───────────────────────────────────── */}
            <SectionHeading>Risk Policy Overview</SectionHeading>
            <div style={CARD}>
              <p style={SECTION_TITLE}>How risk levels are assigned</p>
              <p style={SECTION_DESC}>
                Risk classification is automatic and rule-based. It cannot be configured
                here — the rules are maintained by ConfigTrace.
              </p>

              {[
                {
                  level: "Critical",
                  color: "#e84040",
                  desc: "Changes that expose infrastructure or break production — e.g. deleting A/AAAA records, removing WAF rules, removing production env vars.",
                },
                {
                  level: "High",
                  color: "#f5632a",
                  desc: "Changes with significant blast radius — e.g. disabling proxied mode, changing MX routing, modifying security headers, altering git_branch.",
                },
                {
                  level: "Medium",
                  color: "#f5a623",
                  desc: "Operationally significant but recoverable — e.g. TTL changes, removing preview env vars, removing domains, adding unproxied records.",
                },
                {
                  level: "Low",
                  color: "#6b9cf8",
                  desc: "Informational drift — e.g. adding preview env vars, comment-only changes, minor metadata updates.",
                },
              ].map(({ level, color, desc }) => (
                <div key={level} style={{ ...ROW, alignItems: "flex-start" }}>
                  <div
                    style={{
                      flexShrink: 0,
                      width: "64px",
                      fontSize: "12px",
                      fontWeight: 600,
                      color,
                      paddingTop: "1px",
                    }}
                  >
                    {level}
                  </div>
                  <p style={{ flex: 1, margin: 0, fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
                    {desc}
                  </p>
                </div>
              ))}
            </div>

            {/* ── Data Safety ────────────────────────────────────────────── */}
            <SectionHeading>Data Safety</SectionHeading>
            <div style={CARD}>
              <p style={SECTION_TITLE}>How ConfigTrace handles credentials</p>
              <p style={SECTION_DESC}>
                ConfigTrace stores only what it needs to monitor your configuration.
                No sensitive values are stored or returned in any response.
              </p>

              <ReadOnlyRow
                label="API tokens"
                value="Encrypted at rest using AES-256. Never returned by the API. Rotatable from the integration detail page."
              />
              <ReadOnlyRow
                label="Environment variable values"
                value="Never captured. Only key names are recorded in snapshots; values are excluded entirely."
              />
              <ReadOnlyRow
                label="GitHub tokens"
                value="Fine-grained PATs and GitHub App installation tokens are encrypted at rest and never logged or exposed."
              />
              <ReadOnlyRow
                label="Snapshot data"
                value="Contains only configuration metadata (record types, field names, counts). No secrets, passwords, or env var values."
              />
            </div>

            {/* ── Developer Diagnostics ──────────────────────────────────── */}
            <SectionHeading>Developer Diagnostics</SectionHeading>
            <div style={CARD}>
              <p style={SECTION_TITLE}>API access</p>
              <p style={SECTION_DESC}>
                ConfigTrace has a REST API. All endpoints require a Clerk JWT passed as{" "}
                <code
                  style={{
                    fontFamily: "monospace",
                    fontSize: "11px",
                    background: "#1e2030",
                    padding: "1px 5px",
                    borderRadius: "3px",
                    color: "#8b90a0",
                  }}
                >
                  Authorization: Bearer &lt;token&gt;
                </code>
                .
              </p>

              <ReadOnlyRow
                label="Base URL"
                value={
                  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") ??
                  "http://localhost:8000"
                }
              />
              <ReadOnlyRow
                label="Auth scheme"
                value="Clerk JWT — short-lived, rotated every ~60 s. Obtain via getToken() in the Clerk SDK."
              />
              <ReadOnlyRow
                label="Pagination"
                value="All list endpoints accept ?page=N&page_size=N. Default page size is 20; maximum is 100."
              />
              <ReadOnlyRow
                label="Rate limits"
                value="No hard rate limits are enforced in this release."
              />
            </div>

            {/* ── Save error ─────────────────────────────────────────────── */}
            {saveError && (
              <div
                style={{
                  background: "rgba(232,64,64,0.08)",
                  border: "1px solid rgba(232,64,64,0.25)",
                  borderRadius: "6px",
                  padding: "10px 16px",
                  marginBottom: "16px",
                }}
              >
                <p style={{ margin: 0, fontSize: "12px", color: "#e84040" }}>
                  {saveError}
                </p>
              </div>
            )}

            {/* ── Sticky save bar ─────────────────────────────────────────── */}
            <SaveBar
              dirty={dirty}
              saving={saving}
              savedAt={savedAt}
              onSave={save}
              onDiscard={discard}
            />
          </>
        )}
      </div>
    </>
  );
}
