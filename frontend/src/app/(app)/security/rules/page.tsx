"use client";

/**
 * Security Rules (M60.9 catalog + M61.7 enable/disable).
 *
 * A catalog of the Security Exposure rules ConfigTrace evaluates, mirroring the
 * backend rules in security_rules/* (see lib/securityRuleCatalog). M61.7 adds
 * per-workspace enable/disable controls: disabling a rule stops FUTURE findings
 * from it — it does not resolve or remove existing findings.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth } from "@clerk/nextjs";

import { getProviderMeta } from "@/lib/providers";
import type { SecurityRulePack, SecurityRulePackRule } from "@/types";
import { getSecurityRuleSettings, updateSecurityRuleSetting, getSecurityRulePack } from "@/lib/api";
import { trackSecurityBetaEvent } from "@/lib/securityBetaEvents";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { canManageSecurityRules } from "@/lib/workspacePermissions";
import { formatAbsoluteTime } from "@/lib/utils";
import {
  DEFERRED_RULES,
  PROVIDER_COVERAGE,
  SECURITY_RULES,
  SecurityRuleMeta,
} from "@/lib/securityRuleCatalog";

import PageHeader from "@/components/common/PageHeader";
import { SectionLabel } from "@/components/security/previews";
import { SeverityBadge } from "@/components/security/findingDisplay";

type StatusFilter = "all" | "active" | "planned";
type StateFilter = "all" | "enabled" | "disabled";

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];

export default function SecurityRulesPage() {
  const { getToken } = useAuth();
  const { role, roleLoaded } = useWorkspace();
  const canManage = canManageSecurityRules(role);
  const [search, setSearch] = useState("");
  const [providerFilter, setProviderFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [stateFilter, setStateFilter] = useState<StateFilter>("all");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // M61.7: per-workspace enable/disable state. Missing key → enabled (default).
  const [enabledByKey, setEnabledByKey] = useState<Record<string, boolean>>({});
  const [updatedByKey, setUpdatedByKey] = useState<Record<string, string | null>>({});
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  // M63.3: active rule pack + per-rule version metadata.
  const [pack, setPack] = useState<SecurityRulePack | null>(null);
  const packByKey = useMemo(() => {
    const m: Record<string, SecurityRulePackRule> = {};
    for (const r of pack?.rules ?? []) m[r.rule_key] = r;
    return m;
  }, [pack]);

  const loadPack = useCallback(async () => {
    try {
      const token = await getToken();
      setPack(await getSecurityRulePack(token));
    } catch {
      // Non-fatal: rules remain visible without version metadata.
    }
  }, [getToken]);

  useEffect(() => {
    void loadPack();
  }, [loadPack]);

  const loadSettings = useCallback(async () => {
    try {
      const token = await getToken();
      const res = await getSecurityRuleSettings(token);
      const en: Record<string, boolean> = {};
      const up: Record<string, string | null> = {};
      for (const s of res.items) {
        en[s.rule_key] = s.enabled;
        up[s.rule_key] = s.updated_at;
      }
      setEnabledByKey(en);
      setUpdatedByKey(up);
    } catch {
      // Non-fatal: rules remain visible; toggles default to enabled.
    }
  }, [getToken]);

  useEffect(() => {
    void loadSettings();
  }, [loadSettings]);

  const isEnabled = useCallback(
    (key: string) => enabledByKey[key] !== false, // default true
    [enabledByKey],
  );

  const handleToggleEnabled = useCallback(
    async (key: string, next: boolean) => {
      setSavingKey(key);
      setActionError(null);
      const prev = enabledByKey[key];
      setEnabledByKey((m) => ({ ...m, [key]: next })); // optimistic
      try {
        const token = await getToken();
        const updated = await updateSecurityRuleSetting(key, next, token);
        setEnabledByKey((m) => ({ ...m, [key]: updated.enabled }));
        setUpdatedByKey((m) => ({ ...m, [key]: updated.updated_at }));
        trackSecurityBetaEvent(
          "security_rule_toggled",
          { rule_key: key, action: updated.enabled ? "enabled" : "disabled" },
          { getToken, pagePath: "/security/rules" },
        );
      } catch (e) {
        // Roll back on failure.
        setEnabledByKey((m) => ({ ...m, [key]: prev ?? true }));
        setActionError(e instanceof Error ? e.message : "Failed to update rule.");
      } finally {
        setSavingKey(null);
      }
    },
    [enabledByKey, getToken],
  );

  const toggle = (key: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });

  // Distinct option lists derived from the catalog.
  const providerOptions = useMemo(
    () => [...new Set(SECURITY_RULES.map((r) => r.provider))].sort(),
    [],
  );
  const categoryOptions = useMemo(
    () => [...new Set(SECURITY_RULES.map((r) => r.category))].sort(),
    [],
  );

  // Metrics from the implemented catalog.
  const metrics = useMemo(() => {
    const critical = SECURITY_RULES.filter((r) => r.severity === "critical").length;
    const high = SECURITY_RULES.filter((r) => r.severity === "high").length;
    const providers = new Set(SECURITY_RULES.map((r) => r.provider)).size;
    return { total: SECURITY_RULES.length, critical, high, providers };
  }, []);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return SECURITY_RULES.filter((r) => {
      if (providerFilter !== "all" && r.provider !== providerFilter) return false;
      if (severityFilter !== "all" && r.severity !== severityFilter) return false;
      if (categoryFilter !== "all" && r.category !== categoryFilter) return false;
      if (stateFilter !== "all") {
        const on = enabledByKey[r.key] !== false;
        if (stateFilter === "enabled" && !on) return false;
        if (stateFilter === "disabled" && on) return false;
      }
      if (q) {
        const hay = `${r.title} ${r.key} ${r.provider} ${r.category}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [search, providerFilter, severityFilter, categoryFilter, stateFilter, enabledByKey]);

  const showActive = statusFilter !== "planned";
  const showPlanned = statusFilter !== "active";

  return (
    <div>
      <PageHeader
        title="Security Rules"
        description="See the configuration exposure rules ConfigTrace evaluates across connected providers."
      />

      <p
        style={{
          margin: "-12px 0 24px",
          fontSize: "13px",
          color: "#8b90a0",
          lineHeight: 1.6,
          maxWidth: "780px",
        }}
      >
        Security Rules shows the current checks used by the Security Exposure engine.
        These rules evaluate provider configuration snapshots for risky current
        states. They do not claim breach detection or inspect payloads or secrets.
      </p>

      {/* M63.3 — active rule pack badge */}
      {pack ? (
        <div
          className="bg-surface1 border border-border"
          style={{
            display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap",
            borderRadius: "10px", padding: "10px 14px", marginBottom: "20px",
          }}
        >
          <span
            style={{
              fontSize: "11px", fontWeight: 700, letterSpacing: "0.03em", textTransform: "uppercase",
              color: "#6b9cf8", background: "rgba(107,156,248,0.12)", border: "1px solid rgba(107,156,248,0.4)",
              borderRadius: "6px", padding: "2px 8px", whiteSpace: "nowrap",
            }}
          >
            Rule pack
          </span>
          <span style={{ fontSize: "12.5px", color: "#c4c8d4" }}>
            ConfigTrace Security Exposure · version {pack.version}
            <span style={{ color: "#565b6e" }}>
              {" "}· {pack.rule_count} rules{pack.released_at ? ` · released ${pack.released_at}` : ""}
            </span>
          </span>
        </div>
      ) : null}

      {/* M63.5 — non-admin notice (only once role is known and is not admin). */}
      {roleLoaded && !canManage ? (
        <div
          className="bg-surface1 border border-border"
          style={{ borderRadius: "10px", padding: "10px 14px", marginBottom: "20px", fontSize: "12.5px", color: "#8b90a0" }}
        >
          Only workspace admins can change rule settings. Members can still view rule coverage.
        </div>
      ) : null}

      {/* Metrics */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
          gap: "14px",
          marginBottom: "24px",
        }}
      >
        <Metric label="Active rules" value={metrics.total} accent="#4f80f7" />
        <Metric label="Critical rules" value={metrics.critical} accent="#e84040" />
        <Metric label="High rules" value={metrics.high} accent="#f5632a" />
        <Metric label="Providers covered" value={metrics.providers} accent="#6b9cf8" />
        <Metric label="Metadata-only checks" value={metrics.total} accent="#3ccf7e" />
      </div>

      {/* Filters / search */}
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: "12px",
          alignItems: "center",
          marginBottom: "18px",
        }}
      >
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search rules by title, key, or provider…"
          style={{
            flex: "1 1 240px",
            minWidth: "200px",
            fontSize: "13px",
            color: "#e8eaf0",
            background: "#13151a",
            border: "1px solid #2a2d38",
            borderRadius: "8px",
            padding: "8px 12px",
          }}
        />
        <FilterSelect
          label="Status"
          value={statusFilter}
          onChange={(v) => setStatusFilter(v as StatusFilter)}
          options={[
            { value: "all", label: "All" },
            { value: "active", label: "Active" },
            { value: "planned", label: "Planned" },
          ]}
        />
        <FilterSelect
          label="Provider"
          value={providerFilter}
          onChange={setProviderFilter}
          options={[
            { value: "all", label: "All providers" },
            ...providerOptions.map((p) => ({ value: p, label: getProviderMeta(p).shortLabel })),
          ]}
        />
        <FilterSelect
          label="Severity"
          value={severityFilter}
          onChange={setSeverityFilter}
          options={[
            { value: "all", label: "All severities" },
            ...SEVERITY_OPTIONS.map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) })),
          ]}
        />
        <FilterSelect
          label="Category"
          value={categoryFilter}
          onChange={setCategoryFilter}
          options={[
            { value: "all", label: "All categories" },
            ...categoryOptions.map((c) => ({ value: c, label: c })),
          ]}
        />
        <FilterSelect
          label="State"
          value={stateFilter}
          onChange={(v) => setStateFilter(v as StateFilter)}
          options={[
            { value: "all", label: "All states" },
            { value: "enabled", label: "Enabled" },
            { value: "disabled", label: "Disabled" },
          ]}
        />
      </div>

      {/* M61.7: enable/disable note */}
      <p style={{ fontSize: "12px", color: "#8b90a0", margin: "0 0 18px", lineHeight: 1.6, maxWidth: "780px" }}>
        Disabling a rule prevents future findings from that rule. It does not mark
        existing findings fixed or resolved, and it does not remove the underlying
        risk. Re-enabling resumes normal evaluation.
      </p>
      {actionError ? (
        <p style={{ fontSize: "12px", color: "#e07a5f", margin: "0 0 14px" }}>{actionError}</p>
      ) : null}

      {/* Active rule catalog */}
      {showActive ? (
        <div style={{ marginBottom: "32px" }}>
          <SectionLabel>
            Active rules ({filtered.length}
            {filtered.length !== SECURITY_RULES.length ? ` of ${SECURITY_RULES.length}` : ""})
          </SectionLabel>
          {filtered.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "12px" }}>
              {filtered.map((r) => (
                <RuleCard
                  key={r.key}
                  rule={r}
                  packRule={packByKey[r.key] ?? null}
                  expanded={expanded.has(r.key)}
                  onToggle={() => toggle(r.key)}
                  enabled={isEnabled(r.key)}
                  saving={savingKey === r.key}
                  updatedAt={updatedByKey[r.key] ?? null}
                  onToggleEnabled={(next) => handleToggleEnabled(r.key, next)}
                  canManage={canManage}
                />
              ))}
            </div>
          ) : (
            <div
              className="bg-surface1 border border-border"
              style={{ borderRadius: "12px", padding: "28px", textAlign: "center", marginTop: "12px" }}
            >
              <div style={{ fontSize: "14px", color: "#e8eaf0", fontWeight: 600 }}>
                No rules match these filters.
              </div>
              <div style={{ fontSize: "12.5px", color: "#8b90a0", marginTop: "6px" }}>
                Try adjusting search, provider, severity, or category.
              </div>
            </div>
          )}
        </div>
      ) : null}

      {/* Provider coverage */}
      {showActive ? (
        <div style={{ marginBottom: "32px" }}>
          <SectionLabel>Provider coverage</SectionLabel>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
              gap: "14px",
              marginTop: "12px",
            }}
          >
            {PROVIDER_COVERAGE.map((c) => {
              const meta = getProviderMeta(c.provider);
              return (
                <div
                  key={c.provider}
                  className="bg-surface1 border border-border"
                  style={{ borderRadius: "12px", padding: "16px 18px" }}
                >
                  <div style={{ fontSize: "14px", fontWeight: 700, color: meta.color }}>
                    {meta.shortLabel}
                  </div>
                  <div
                    style={{
                      display: "flex",
                      flexWrap: "wrap",
                      gap: "6px",
                      marginTop: "10px",
                    }}
                  >
                    {c.surfaces.map((s) => (
                      <span
                        key={s}
                        style={{
                          fontSize: "11.5px",
                          color: "#8b90a0",
                          background: "rgba(148,163,184,0.08)",
                          border: "1px solid #2a2d38",
                          borderRadius: "7px",
                          padding: "3px 9px",
                        }}
                      >
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : null}

      {/* Deferred / planned coverage */}
      {showPlanned ? (
        <div>
          <SectionLabel>Planned / deferred coverage (not active yet)</SectionLabel>
          <p style={{ fontSize: "12.5px", color: "#565b6e", margin: "8px 0 12px", lineHeight: 1.6 }}>
            These checks are intentionally not active — they need data or context the
            current connectors don&apos;t reliably provide, and enabling them would
            create noise.
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {DEFERRED_RULES.map((d, i) => {
              const meta = getProviderMeta(d.provider);
              return (
                <div
                  key={i}
                  className="bg-surface1 border border-border"
                  style={{ borderRadius: "10px", padding: "13px 16px", opacity: 0.9 }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <span style={{ fontSize: "12px", fontWeight: 600, color: meta.color }}>
                      {meta.shortLabel}
                    </span>
                    <span style={{ fontSize: "13.5px", color: "#c4c8d4", fontWeight: 500 }}>
                      {d.title}
                    </span>
                    <span
                      style={{
                        marginLeft: "auto",
                        fontSize: "10px",
                        color: "#565b6e",
                        border: "1px solid #2a2d38",
                        borderRadius: "6px",
                        padding: "2px 8px",
                        whiteSpace: "nowrap",
                      }}
                    >
                      Planned
                    </span>
                  </div>
                  <div style={{ fontSize: "12px", color: "#8b90a0", marginTop: "6px", lineHeight: 1.55 }}>
                    {d.reason}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : null}
    </div>
  );
}

// ── Rule card ──────────────────────────────────────────────────────────────

function RuleCard({
  rule,
  packRule,
  expanded,
  onToggle,
  enabled,
  saving,
  updatedAt,
  onToggleEnabled,
  canManage,
}: {
  rule: SecurityRuleMeta;
  packRule: SecurityRulePackRule | null;
  expanded: boolean;
  onToggle: () => void;
  enabled: boolean;
  saving: boolean;
  updatedAt: string | null;
  onToggleEnabled: (next: boolean) => void;
  canManage: boolean;
}) {
  const meta = getProviderMeta(rule.provider);

  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", overflow: "hidden", opacity: enabled ? 1 : 0.72 }}
    >
      {/* Header: expand button on the left, enable toggle as a sibling (never
          a nested interactive element). */}
      <div style={{ display: "flex", alignItems: "flex-start", gap: "10px", padding: "14px 16px" }}>
        <button
          onClick={onToggle}
          aria-expanded={expanded}
          style={{
            flex: 1,
            minWidth: 0,
            textAlign: "left",
            background: "transparent",
            border: "none",
            cursor: "pointer",
            display: "flex",
            flexDirection: "column",
            gap: "8px",
            padding: 0,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0, flexWrap: "wrap" }}>
            <SeverityBadge severity={rule.severity} />
            <span style={{ fontSize: "12px", color: meta.color, fontWeight: 600 }}>{meta.shortLabel}</span>
            <span style={{ fontSize: "14px", fontWeight: 600, color: "#e8eaf0" }}>{rule.title}</span>
            {rule.metadataOnly ? <MetadataBadge /> : null}
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "8px",
              fontSize: "12px",
              color: "#8b90a0",
            }}
          >
            <span style={{ fontFamily: "monospace", fontSize: "11px", color: "#565b6e" }}>{rule.key}</span>
            <span style={{ color: "#3a3d4a" }}>·</span>
            <span>{rule.category}</span>
            <span style={{ color: "#3a3d4a" }}>·</span>
            <span>confidence: {rule.confidence}</span>
            {packRule ? (
              <>
                <span style={{ color: "#3a3d4a" }}>·</span>
                <span>v{packRule.rule_version}</span>
                <span style={{ color: "#3a3d4a" }}>·</span>
                <span>introduced {packRule.introduced_in}</span>
                <span style={{ color: "#3a3d4a" }}>·</span>
                <span style={{ color: packRule.status === "active" ? "#3ccf7e" : "#8b90a0" }}>
                  {packRule.status}
                </span>
              </>
            ) : null}
            {!enabled && updatedAt ? (
              <>
                <span style={{ color: "#3a3d4a" }}>·</span>
                <span>disabled {formatAbsoluteTime(updatedAt)}</span>
              </>
            ) : null}
          </div>

          <div style={{ fontSize: "12.5px", color: "#8b90a0", lineHeight: 1.5 }}>{rule.description}</div>
        </button>

        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
          <EnableToggle enabled={enabled} saving={saving} onToggleEnabled={onToggleEnabled} canManage={canManage} />
          <button
            type="button"
            onClick={onToggle}
            aria-label={expanded ? "Collapse" : "Expand"}
            style={{ background: "transparent", border: "none", cursor: "pointer", fontSize: "16px", color: "#565b6e", padding: 0 }}
          >
            {expanded ? "▾" : "▸"}
          </button>
        </div>
      </div>

      {expanded ? (
        <div
          style={{
            borderTop: "1px solid #2a2d38",
            padding: "16px",
            display: "flex",
            flexDirection: "column",
            gap: "14px",
          }}
        >
          <DetailRow label="What it checks" value={rule.whatItChecks} />
          <DetailRow label="Why it matters" value={rule.whyItMatters} />
          <DetailRow label="Evidence used" value={rule.evidence} />
          <DetailRow label="Suggested remediation" value={rule.remediation} />
          <DetailRow label="Why it's conservative" value={rule.falsePositiveGuard} />
          {rule.severityNote ? <DetailRow label="Severity note" value={rule.severityNote} /> : null}
        </div>
      ) : null}
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div
        style={{
          fontSize: "11px",
          fontWeight: 600,
          letterSpacing: "0.04em",
          textTransform: "uppercase",
          color: "#565b6e",
          marginBottom: "4px",
        }}
      >
        {label}
      </div>
      <div style={{ fontSize: "13px", color: "#c4c8d4", lineHeight: 1.55 }}>{value}</div>
    </div>
  );
}

function EnableToggle({
  enabled,
  saving,
  onToggleEnabled,
  canManage,
}: {
  enabled: boolean;
  saving: boolean;
  onToggleEnabled: (next: boolean) => void;
  canManage: boolean;
}) {
  const color = enabled ? "#3ccf7e" : "#8b90a0";
  const bg = enabled ? "rgba(60,207,126,0.14)" : "rgba(148,163,184,0.10)";
  const border = enabled ? "rgba(60,207,126,0.4)" : "#2a2d38";
  const disabled = saving || !canManage;
  return (
    <button
      type="button"
      disabled={disabled}
      aria-pressed={enabled}
      onClick={() => onToggleEnabled(!enabled)}
      title={
        !canManage
          ? "Only workspace admins can change rule settings."
          : enabled
            ? "Disable this rule — stops future findings; does not resolve existing ones."
            : "Enable this rule — resumes normal evaluation."
      }
      style={{
        fontSize: "11px",
        fontWeight: 700,
        letterSpacing: "0.03em",
        textTransform: "uppercase",
        color,
        background: bg,
        border: `1px solid ${border}`,
        borderRadius: "7px",
        padding: "4px 10px",
        cursor: disabled ? (saving ? "wait" : "not-allowed") : "pointer",
        opacity: disabled ? 0.6 : 1,
        whiteSpace: "nowrap",
        fontFamily: "inherit",
      }}
    >
      {saving ? "Saving…" : enabled ? "Enabled" : "Disabled"}
    </button>
  );
}

function MetadataBadge() {
  return (
    <span
      title="Evaluates configuration metadata only — never secrets, payloads, or customer data."
      style={{
        fontSize: "10px",
        fontWeight: 600,
        color: "#6b9cf8",
        background: "rgba(107,156,248,0.12)",
        border: "1px solid rgba(107,156,248,0.35)",
        borderRadius: "6px",
        padding: "2px 8px",
        whiteSpace: "nowrap",
      }}
    >
      Metadata-only
    </span>
  );
}

function Metric({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px" }}>
      <div style={{ fontSize: "12px", color: "#8b90a0", fontWeight: 500 }}>{label}</div>
      <div style={{ fontSize: "26px", fontWeight: 700, color: accent, marginTop: "8px", letterSpacing: "-0.02em" }}>
        {value}
      </div>
    </div>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
      <span style={{ fontSize: "12px", color: "#565b6e" }}>{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{
          fontSize: "13px",
          color: "#e8eaf0",
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "8px",
          padding: "7px 10px",
          cursor: "pointer",
        }}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}
